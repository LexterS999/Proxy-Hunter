"""
Модуль для активной проверки работоспособности прокси-конфигураций.
Выполняет ICMP ping (опционально), TCP SYN и HTTP-пробинг с кешированием.
Использует настройки из user_settings.
"""

import asyncio
import logging
import time
import socket
import os
import re
from typing import Dict, List, Optional, Tuple
from collections import OrderedDict
from urllib.parse import urlparse, parse_qs

import aiohttp
from aiohttp import ClientTimeout

from concurrency import ConcurrencyLimiter
from session_pool import SessionPool
from retry_utils import retry_with_backoff
from user_settings import (
    ENABLE_ICMP_PING,
    ICMP_TIMEOUT,
    TCP_TIMEOUT,
    HTTP_TIMEOUT,
    MAX_LATENCY_MS,
    ACTIVE_CHECKER_WORKERS,
    PER_HOST_LIMIT
)

logger = logging.getLogger(__name__)

# Попытка импорта icmplib для ICMP (если не установлен, ICMP будет пропущен)
try:
    from icmplib import ping as icmp_ping
    HAS_ICMP = True
except ImportError:
    HAS_ICMP = False
    logger.warning("icmplib not installed, ICMP ping disabled. Install with: pip install icmplib")


class ActiveChecker:
    """
    Активная проверка с ICMP, TCP, HTTP, кешированием и пулом соединений.
    """

    def __init__(self,
                 timeout: float = None,
                 max_workers: int = None,
                 test_url: str = "https://www.google.com/generate_204",
                 max_latency: float = None,
                 history: Dict = None):
        self.timeout = timeout or TCP_TIMEOUT
        self.max_workers = max_workers or ACTIVE_CHECKER_WORKERS
        self.test_url = test_url
        self.max_latency = max_latency or MAX_LATENCY_MS
        self.history = history or {}
        self._session = None
        self._connector = None

        self._limiter = ConcurrencyLimiter(
            global_limit=self.max_workers,
            per_host_limit=PER_HOST_LIMIT
        )

        self._tcp_cache = OrderedDict()
        self._cache_max_size = 5000

        self._enable_icmp = ENABLE_ICMP_PING and HAS_ICMP

    def _should_skip(self, config: str) -> bool:
        """Фильтрация по истории."""
        if not self.history:
            return False
        from profile_scorer import ProfileScorer
        scorer = ProfileScorer()
        try:
            parsed = self._extract_parsed(config)
            if not parsed:
                return False
            key = scorer.get_profile_key(config, parsed)
            profile = self.history.get('profiles', {}).get(key, {})
            if profile.get('is_active') is False:
                return True
            if profile.get('overall_score', 100) < 30:
                return True
        except Exception:
            pass
        return False

    def _extract_parsed(self, config: str) -> Optional[Dict]:
        import config_parser as parser
        if config.startswith('vless://'):
            return parser.parse_vless(config)
        elif config.startswith('vmess://'):
            return parser.decode_vmess(config)
        elif config.startswith('trojan://'):
            return parser.parse_trojan(config)
        elif config.startswith('ss://'):
            return parser.parse_shadowsocks(config)
        return None

    async def _get_session(self) -> aiohttp.ClientSession:
        pool = SessionPool()
        self._session = await pool.get_session(
            connector_limit=200,
            per_host_limit=50,
            timeout_total=HTTP_TIMEOUT * 2
        )
        return self._session

    async def _icmp_ping(self, host: str) -> float:
        """Выполняет ICMP ping и возвращает RTT в миллисекундах или -1 при ошибке."""
        if not self._enable_icmp:
            return -1.0
        try:
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(
                None,
                lambda: icmp_ping(host, count=1, timeout=ICMP_TIMEOUT, privileged=False)
            )
            if result.is_alive:
                return result.avg_rtt * 1000  # в мс
            return -1.0
        except Exception as e:
            logger.debug(f"ICMP ping error for {host}: {e}")
            return -1.0

    @retry_with_backoff(attempts=3, base_delay=0.2, max_delay=1.0, deadline=5.0,
                        retryable_exceptions=(asyncio.TimeoutError, ConnectionError, OSError, ConnectionResetError))
    async def _tcp_latency_with_retry(self, host: str, port: int) -> float:
        return await self._tcp_latency_raw(host, port)

    async def _tcp_latency_raw(self, host: str, port: int) -> float:
        start = time.time()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=False),
                timeout=self.timeout
            )
            writer.close()
            await writer.wait_closed()
            return (time.time() - start) * 1000
        except Exception:
            return -1.0

    async def _tcp_latency(self, host: str, port: int) -> float:
        key = (host, port)
        if key in self._tcp_cache:
            self._tcp_cache.move_to_end(key)
            return self._tcp_cache[key]

        # Если ICMP включён, сначала пинг
        if self._enable_icmp:
            icmp_rtt = await self._icmp_ping(host)
            if icmp_rtt < 0 or icmp_rtt > self.max_latency:
                # Хост не отвечает на ICMP или слишком высокая задержка — пропускаем
                latency = -1.0
                if len(self._tcp_cache) >= self._cache_max_size:
                    self._tcp_cache.popitem(last=False)
                self._tcp_cache[key] = latency
                return latency

        latency = await self._tcp_latency_with_retry(host, port)

        if len(self._tcp_cache) >= self._cache_max_size:
            self._tcp_cache.popitem(last=False)
        self._tcp_cache[key] = latency
        return latency

    async def _http_probe(self, host: str, port: int, use_tls: bool) -> float:
        try:
            session = await self._get_session()
            proto = 'https' if use_tls else 'http'
            url = f"{proto}://{host}:{port}"
            headers = {'Range': 'bytes=0-0'}
            start = time.time()
            async with session.get(url, headers=headers, allow_redirects=True, timeout=HTTP_TIMEOUT) as resp:
                if resp.status in (200, 204, 206, 301, 302, 307, 308):
                    return (time.time() - start) * 1000
            return -1.0
        except Exception:
            return -1.0

    async def check_config(self, config: str) -> Dict:
        result = {'config': config, 'valid': False, 'latency': -1.0, 'success': False, 'error': None}

        if self._should_skip(config):
            result['error'] = 'skipped_by_history'
            return result

        server_info = self._extract_server_info(config)
        if not server_info:
            result['error'] = 'no_server_info'
            return result

        host, port, use_tls = server_info

        tcp_latency = await self._limiter.run(host, self._tcp_latency(host, port))
        if tcp_latency < 0:
            result['error'] = 'tcp_failed'
            return result

        if tcp_latency > 0 and tcp_latency < self.max_latency:
            http_latency = await self._limiter.run(host, self._http_probe(host, port, use_tls))
            if http_latency > 0:
                result['latency'] = http_latency
                result['valid'] = True
                result['success'] = True
                return result

        if tcp_latency <= self.max_latency:
            result['latency'] = tcp_latency
            result['valid'] = True
            result['success'] = True
            return result

        result['error'] = 'latency_too_high'
        return result

    async def check_batch(self, configs: List[str]) -> List[Dict]:
        if not configs:
            return []

        filtered_configs = [c for c in configs if not self._should_skip(c)]

        # Прогрев кеша TCP
        server_groups = {}
        for cfg in filtered_configs:
            info = self._extract_server_info(cfg)
            if info:
                server_groups[(info[0], info[1])] = True

        warm_tasks = []
        for (host, port) in server_groups.keys():
            warm_tasks.append(self._limiter.run(host, self._tcp_latency(host, port)))
        if warm_tasks:
            await asyncio.gather(*warm_tasks, return_exceptions=True)

        sem = asyncio.Semaphore(self.max_workers * 2)

        async def check_one(cfg: str):
            async with sem:
                return await self.check_config(cfg)

        tasks = [check_one(cfg) for cfg in filtered_configs]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        final = []
        for idx, res in enumerate(results):
            if isinstance(res, Exception):
                final.append({
                    'config': filtered_configs[idx],
                    'valid': False,
                    'latency': -1.0,
                    'success': False,
                    'error': str(res)
                })
            else:
                final.append(res)

        return final

    async def close(self):
        pass

    def _extract_server_info(self, config: str) -> Optional[Tuple[str, int, bool]]:
        try:
            import config_parser as parser
            if config.startswith('vmess://'):
                data = parser.decode_vmess(config)
                if data and data.get('add') and data.get('port'):
                    host = data.get('add')
                    port = int(data.get('port'))
                    tls = data.get('tls', '').lower() in ('tls', 'xtls', 'reality')
                    return (host, port, tls)
            elif config.startswith('vless://'):
                data = parser.parse_vless(config)
                if data and data.get('address') and data.get('port'):
                    host = data.get('address')
                    port = int(data.get('port'))
                    tls = data.get('security', '').lower() in ('tls', 'reality')
                    return (host, port, tls)
            elif config.startswith('trojan://'):
                data = parser.parse_trojan(config)
                if data and data.get('address') and data.get('port'):
                    host = data.get('address')
                    port = int(data.get('port'))
                    tls = data.get('security', 'tls').lower() in ('tls', 'reality')
                    return (host, port, tls)
            elif config.startswith('ss://'):
                data = parser.parse_shadowsocks(config)
                if data and data.get('address') and data.get('port'):
                    host = data.get('address')
                    port = int(data.get('port'))
                    return (host, port, False)
        except Exception as e:
            logger.debug(f"Parser extraction failed: {e}")

        # fallback через urlparse
        try:
            base = config.split('#')[0]
            parsed = urlparse(base)
            if parsed.hostname:
                host = parsed.hostname
                port = parsed.port or 443
                params = parse_qs(parsed.query)
                security = params.get('security', [''])[0].lower()
                tls = security in ('tls', 'reality', 'xtls') or parsed.scheme in ('https', 'trojan')
                return (host, port, tls)
        except Exception:
            pass

        # regex fallback
        match = re.search(r'@([^:]+):(\d+)', config)
        if match:
            host = match.group(1)
            port = int(match.group(2))
            tls = 'security=tls' in config or 'security=reality' in config or 'sni=' in config
            return (host, port, tls)

        return None

    def filter_by_latency(self, results: List[Dict], max_latency: float = None) -> List[str]:
        if max_latency is None:
            max_latency = self.max_latency
        return [
            r['config'] for r in results
            if r.get('valid', False) and 0 <= r.get('latency', -1) <= max_latency
        ]
