import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import re
import time
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Optional, Set
import asyncio
import aiohttp
from aiohttp import ClientTimeout, ClientConnectorError, ClientResponseError
from lxml import html
from config import ProxyConfig, ChannelConfig
from config_validator import ConfigValidator
from parse_fallback import FallbackParser
from pathlib import Path
from dateutil import parser as date_parser
import base64
from functools import lru_cache

from retry_utils import retry_with_backoff, is_retryable
from session_pool import SessionPool
from user_settings import (
    CHANNEL_RETRY_ATTEMPTS,
    CHANNEL_RETRY_BASE_DELAY,
    CHANNEL_RETRY_MAX_DELAY,
    CHANNEL_RETRY_DEADLINE,
    TELEGRAM_CALLS_PER_SECOND,
    MAX_RESPONSE_SIZE_BYTES
)

logger = logging.getLogger(__name__)

# Предварительная компиляция паттернов для быстрого поиска
_PROTOCOL_PATTERNS = {
    'vmess': re.compile(r'vmess://[A-Za-z0-9+/=_-]+', re.IGNORECASE),
    'vless': re.compile(r'vless://[A-Za-z0-9+/=_-]+', re.IGNORECASE),
    'trojan': re.compile(r'trojan://[^/\s]+', re.IGNORECASE),
    'ss': re.compile(r'ss://[A-Za-z0-9+/=_-]+', re.IGNORECASE),
    'hysteria2': re.compile(r'(?:hysteria2|hy2)://[^\s]+', re.IGNORECASE),
    'tuic': re.compile(r'tuic://[^\s]+', re.IGNORECASE),
    'wireguard': re.compile(r'wireguard://[^\s]+', re.IGNORECASE),
}


class AdaptiveRateLimiter:
    """Адаптивный Token Bucket с обратной связью по ошибкам."""
    def __init__(self, rate: float = 1.5, max_burst: int = 10):
        self.rate = rate
        self.max_tokens = max_burst
        self.tokens = max_burst
        self.last_refill = time.time()
        self._lock = asyncio.Lock()
        self.backoff_factor = 1.0

    async def acquire(self):
        async with self._lock:
            now = time.time()
            elapsed = now - self.last_refill
            self.tokens = min(self.max_tokens,
                              self.tokens + elapsed * self.rate * self.backoff_factor)
            self.last_refill = now

            if self.tokens < 1:
                wait = (1 - self.tokens) / (self.rate * self.backoff_factor)
                await asyncio.sleep(wait)
                self.tokens = 0
            else:
                self.tokens -= 1

    def report_success(self):
        self.backoff_factor = min(2.0, self.backoff_factor * 1.02)

    def report_error(self, is_429: bool = False):
        if is_429:
            self.backoff_factor = max(0.1, self.backoff_factor * 0.7)
        else:
            self.backoff_factor = max(0.3, self.backoff_factor * 0.9)

    def set_retry_after(self, seconds: int):
        self.last_refill = time.time() + seconds


class AsyncConfigFetcher:
    """Полностью асинхронный сборщик конфигураций с адаптивным лимитером."""

    def __init__(self, config: ProxyConfig, max_concurrent: int = 50):
        self.config = config
        self.validator = ConfigValidator()
        self.max_concurrent = max_concurrent
        self._session = None
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self.protocol_counts: Dict[str, int] = {p: 0 for p in config.SUPPORTED_PROTOCOLS}
        self.seen_configs: Set[str] = set()
        self.channel_protocol_counts: Dict[str, Dict[str, int]] = {}
        self._message_cache: Dict[str, List[str]] = {}
        self._cache_ttl = 3600

        num_channels = len(config.SOURCE_URLS) if config.SOURCE_URLS else 1
        self._connector_limit = min(200, num_channels * 10)
        self._connector_per_host = min(50, num_channels * 5)

        self._rate_limiter = AdaptiveRateLimiter(rate=TELEGRAM_CALLS_PER_SECOND)
        self._enabled_protocols_set = {p for p, enabled in config.SUPPORTED_PROTOCOLS.items() if enabled}

    @lru_cache(maxsize=128)
    def _get_protocol(self, config: str) -> Optional[str]:
        for protocol in self._enabled_protocols_set:
            if config.startswith(protocol):
                return protocol
        return None

    async def _ensure_session(self) -> aiohttp.ClientSession:
        pool = SessionPool()
        self._session = await pool.get_session(
            connector_limit=self._connector_limit,
            per_host_limit=self._connector_per_host,
            timeout_total=self.config.REQUEST_TIMEOUT,
            headers=self.config.HEADERS
        )
        return self._session

    @retry_with_backoff(attempts=3, base_delay=0.2, max_delay=5.0, deadline=30.0)
    async def _fetch_with_retry(self, url: str) -> Optional[str]:
        await self._rate_limiter.acquire()
        session = await self._ensure_session()
        try:
            async with session.get(url) as response:
                if response.status == 429:
                    retry_after = response.headers.get('Retry-After', '5')
                    try:
                        wait_time = int(retry_after)
                    except ValueError:
                        wait_time = 5
                    self._rate_limiter.set_retry_after(wait_time)
                    self._rate_limiter.report_error(is_429=True)
                    await asyncio.sleep(wait_time)
                    raise aiohttp.ClientResponseError(
                        response.request_info,
                        response.history,
                        status=response.status,
                        message=f"Rate limited, retry after {wait_time}s"
                    )
                if response.status >= 500:
                    self._rate_limiter.report_error(is_429=False)
                    raise aiohttp.ClientResponseError(
                        response.request_info,
                        response.history,
                        status=response.status,
                        message=response.reason
                    )
                text = await response.text()
                if len(text) > MAX_RESPONSE_SIZE_BYTES:
                    logger.warning(f"Response from {url} too large ({len(text)} bytes), truncating")
                    text = text[:MAX_RESPONSE_SIZE_BYTES]
                self._rate_limiter.report_success()
                return text
        except asyncio.TimeoutError:
            self._rate_limiter.report_error(is_429=False)
            logger.warning(f"Timeout fetching {url}")
            raise

    async def fetch_ssconf_configs(self, url: str) -> List[str]:
        https_url = self.validator.convert_ssconf_to_https(url)
        text = await self._fetch_with_retry(https_url)
        if not text:
            return []
        text = text.strip()
        if self.validator.is_base64(text):
            decoded = self.validator.decode_base64_text(text)
            if decoded:
                text = decoded
        if text.startswith('ss://'):
            return [text]
        return self.validator.split_configs(text)

    def _extract_configs_from_text_fast(self, text: str) -> List[str]:
        """Быстрое извлечение конфигов с использованием предварительно скомпилированных паттернов."""
        configs = []
        for proto, pattern in _PROTOCOL_PATTERNS.items():
            for match in pattern.finditer(text):
                configs.append(match.group(0))
        return list(set(configs))

    def _extract_message_texts_from_lxml(self, tree) -> List[str]:
        """Извлекает тексты сообщений из lxml-дерева."""
        messages = []
        # Поиск через XPath для Telegram
        elements = tree.xpath('//div[@class="tgme_widget_message_text"]')
        if not elements:
            # Fallback: ищем любые div с текстом
            elements = tree.xpath('//div[contains(@class, "tgme_widget_message")]//div[contains(@class, "text")]')
        for elem in elements:
            text = elem.text_content()
            if text and text.strip():
                messages.append(text.strip())
        return messages

    async def fetch_channel(self, channel: ChannelConfig) -> List[str]:
        async with self._semaphore:
            return await self._fetch_channel_internal(channel)

    async def _fetch_channel_internal(self, channel: ChannelConfig) -> List[str]:
        configs = []
        channel.metrics.total_configs = 0
        channel.metrics.valid_configs = 0
        channel.metrics.unique_configs = 0
        channel.metrics.protocol_counts = {p: 0 for p in self.config.SUPPORTED_PROTOCOLS}
        start_time = time.time()

        cache_key = channel.url
        if cache_key in self._message_cache:
            cached = self._message_cache[cache_key]
            logger.debug(f"Using cached messages for {channel.url} ({len(cached)} messages)")
            for msg in cached:
                configs.extend(self._extract_configs_from_text_fast(msg))
        else:
            if channel.url.startswith('ssconf://'):
                configs.extend(await self.fetch_ssconf_configs(channel.url))
                if configs:
                    response_time = time.time() - start_time
                    self.config.update_channel_stats(channel, True, response_time)
                return configs

            text = await self._fetch_with_retry(channel.url)
            if text is None:
                self.config.update_channel_stats(channel, False)
                return configs

            response_time = time.time() - start_time

            if channel.is_telegram:
                # Используем lxml вместо BeautifulSoup для скорости
                tree = html.fromstring(text)
                messages = self._extract_message_texts_from_lxml(tree)
                # Сортировка по дате (если доступна)
                # Сохраняем в кеш
                cached_messages = []
                for msg_text in messages:
                    if msg_text:
                        cached_messages.append(msg_text)
                        configs.extend(self._extract_configs_from_text_fast(msg_text))
                self._message_cache[cache_key] = cached_messages
                if len(self._message_cache) > 100:
                    keys = list(self._message_cache.keys())[:50]
                    for k in keys:
                        del self._message_cache[k]
            else:
                configs.extend(self._extract_configs_from_text_fast(text))

        configs = list(set(configs))
        processed = []
        for cfg in configs:
            proc = self.process_config(cfg, channel)
            if proc:
                processed.extend(proc)

        if len(processed) >= self.config.MIN_CONFIGS_PER_CHANNEL:
            self.config.update_channel_stats(channel, True, time.time() - start_time)
            self.config.adjust_protocol_limits(channel)
        else:
            self.config.update_channel_stats(channel, False)
            logger.warning(f"Not enough configs from {channel.url}: {len(processed)}")

        return processed

    def process_config(self, config: str, channel: ChannelConfig) -> List[str]:
        processed = []
        if config.startswith('hy2://'):
            config = self.validator.normalize_hysteria2_protocol(config)

        protocol = self._get_protocol(config)
        if not protocol:
            return processed

        if not self.config.is_protocol_enabled(protocol):
            return processed

        if protocol == "vmess://":
            config = self.validator.clean_vmess_config(config)

        clean = self.validator.clean_config(config)
        if self.validator.validate_protocol_config(clean, protocol):
            channel.metrics.valid_configs += 1
            channel.metrics.protocol_counts[protocol] = channel.metrics.protocol_counts.get(protocol, 0) + 1
            if clean not in self.seen_configs:
                channel.metrics.unique_configs += 1
                self.seen_configs.add(clean)
                processed.append(clean)
                self.protocol_counts[protocol] = self.protocol_counts.get(protocol, 0) + 1
        return processed

    def check_and_decode_base64(self, text: str) -> str:
        if self.validator.is_base64(text):
            try:
                decoded = base64.b64decode(text + '==', validate=True)
                if decoded:
                    return decoded.decode('utf-8', errors='ignore')
            except Exception:
                pass
        return text

    def extract_date_from_message(self, message) -> Optional[datetime]:
        # Для lxml
        time_elem = message.find('.//time')
        if time_elem is not None and 'datetime' in time_elem.attrib:
            try:
                dt_str = time_elem.attrib['datetime']
                return date_parser.parse(dt_str)
            except Exception as e:
                logger.debug(f"Date parsing failed: {e}")
        return None

    def is_config_valid(self, config_text: str, date: Optional[datetime]) -> bool:
        if not date:
            return True
        cutoff = datetime.now(timezone.utc) - timedelta(days=self.config.MAX_CONFIG_AGE_DAYS)
        return date >= cutoff

    def balance_protocols(self, configs: List[str]) -> List[str]:
        protocol_configs = {p: [] for p in self.config.SUPPORTED_PROTOCOLS}
        for cfg in configs:
            if cfg.startswith('hy2://'):
                cfg = self.validator.normalize_hysteria2_protocol(cfg)
            for p in self.config.SUPPORTED_PROTOCOLS:
                if cfg.startswith(p):
                    protocol_configs[p].append(cfg)
                    break
        total = sum(len(c) for c in protocol_configs.values())
        if total == 0:
            return []
        balanced = []
        sorted_protocols = sorted(
            protocol_configs.items(),
            key=lambda x: (self.config.SUPPORTED_PROTOCOLS[x[0]]["priority"], len(x[1])),
            reverse=True
        )
        for protocol, plist in sorted_protocols:
            info = self.config.SUPPORTED_PROTOCOLS[protocol]
            if len(plist) >= info["min_configs"]:
                max_c = min(info["max_configs"], len(plist))
                balanced.extend(plist[:max_c])
            elif info["flexible_max"] and len(plist) > 0:
                balanced.extend(plist)
        return balanced

    async def fetch_all(self) -> List[str]:
        enabled = self.config.get_enabled_channels()
        if not enabled:
            logger.warning("No enabled channels found.")
            return []

        tasks = [self.fetch_channel(ch) for ch in enabled]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_configs = []
        for idx, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Channel {enabled[idx].url} failed after retries: {result}")
            else:
                all_configs.extend(result)

        if all_configs:
            all_configs = self.balance_protocols(sorted(set(all_configs)))
        return all_configs

    async def close(self):
        pass


# Для обратной совместимости
class ConfigFetcher:
    def __init__(self, config):
        self.config = config
        self.validator = ConfigValidator()
        self.protocol_counts = {}
        self.seen_configs = set()
        self.channel_protocol_counts = {}

    def fetch_all_configs(self):
        import asyncio
        fetcher = AsyncConfigFetcher(self.config)
        try:
            return asyncio.run(fetcher.fetch_all())
        finally:
            asyncio.run(fetcher.close())
