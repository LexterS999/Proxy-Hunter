"""
Модуль для активной проверки работоспособности прокси-конфигураций.
Выполняет TCP SYN и HTTP-пробинг (HEAD/GET) с кешированием и инвалидацией.
Добавлены: DeadHostTracker, BoundedConcurrencyLimiter.
"""

import asyncio
import logging
import time
import socket
import ssl
from typing import Dict, List, Optional, Tuple
from collections import OrderedDict

import aiohttp

from concurrency import ConcurrencyLimiter
from session_pool import SessionPool
from retry_utils import retry_with_backoff
from user_settings import (
    TCP_TIMEOUT,
    HTTP_TIMEOUT,
    MAX_LATENCY_MS,
    ACTIVE_CHECKER_WORKERS,
    PER_HOST_LIMIT
)

logger = logging.getLogger(__name__)

# ============================
# DeadHostTracker
# ============================

class DeadHostTracker:
    """Отслеживает мёртвые хосты и временно их банит."""
    def __init__(self, threshold=3, ban_time=300):
        self.failures = {}
        self.banned = {}
        self.threshold = threshold
        self.ban_time = ban_time

    def record_failure(self, host):
        self.failures[host] = self.failures.get(host, 0) + 1
        if self.failures[host] >= self.threshold:
            self.banned[host] = time.time() + self.ban_time
            logger.debug(f"Host {host} banned for {self.ban_time}s")

    def record_success(self, host):
        self.failures[host] = 0

    def is_banned(self, host):
        if host in self.banned:
            if time.time() < self.banned[host]:
                return True
            del self.banned[host]
        return False

# ============================
# BoundedConcurrencyLimiter
# ============================

class BoundedConcurrencyLimiter(ConcurrencyLimiter):
    def __init__(self, global_limit: int = 20, per_host_limit: int = 4, queue_size: int = 1000):
        super().__init__(global_limit, per_host_limit)
        self.queue = asyncio.Queue(maxsize=queue_size)

# ============================
# Основной класс
# ============================

class CachedActiveChecker:
    """
    Активная проверка с кешированием результатов на основе TTL.
    Использует lru_cache для TCP-кеша, но с инвалидацией при ошибках.
    """

    def __init__(self,
                 timeout: float = None,
                 max_workers: int = None,
                 test_url: str = "https://www.google.com/generate_204",
                 max_latency: float = None,
                 history: Dict = None,
                 cache_ttl: int = 3600):
        self.timeout = timeout or TCP_TIMEOUT
        self.max_workers = max_workers or ACTIVE_CHECKER_WORKERS
        self.test_url = test_url
        self.max_latency = max_latency or MAX_LATENCY_MS
        self.history = history or {}
        self.cache_ttl = cache_ttl
        self._cache = {}
        self._session = None
        self._connector = None
        self._limiter = BoundedConcurrencyLimiter(
            global_limit=self.max_workers,
            per_host_limit=PER_HOST_LIMIT,
            queue_size=2000
        )
        self._dead_host_tracker = DeadHostTracker(threshold=3, ban_time=300)
        self._tcp_cache = {}
        self._tcp_cache_alpha = 0.3

    def _should_skip(self, config: str) -> bool:
        # ... (без изменений)
        pass

    def _extract_parsed(self, config: str) -> Optional[Dict]:
        # ... (без изменений)
        pass

    async def _get_session(self) -> aiohttp.ClientSession:
        # ... (без изменений)
        pass

    @retry_with_backoff(attempts=3, base_delay=0.2, max_delay=1.0, deadline=5.0,
                        retryable_exceptions=(asyncio.TimeoutError, ConnectionError, OSError, ConnectionResetError))
    async def _tcp_latency_with_retry(self, host: str, port: int, use_tls: bool = False) -> float:
        return await self._tcp_latency_raw(host, port, use_tls)

    async def _tcp_latency_raw(self, host: str, port: int, use_tls: bool = False) -> float:
        key = (host, port, use_tls)
        # Проверяем кеш с инвалидацией
        if key in self._tcp_cache:
            cached = self._tcp_cache[key]
            if time.time() - cached['ts'] > self.cache_ttl:
                del self._tcp_cache[key]
            elif cached.get('error'):
                # Попробовать снова через N секунд
                if time.time() - cached.get('error_ts', 0) < 60:
                    return -1.0
                else:
                    # Удаляем запись об ошибке, чтобы попробовать снова
                    del self._tcp_cache[key]
            else:
                return cached['latency']

        # Проверяем, не забанен ли хост
        if self._dead_host_tracker.is_banned(host):
            return -1.0

        start = time.time()
        try:
            if use_tls:
                context = ssl.create_default_context()
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=context),
                    timeout=self.timeout
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=False),
                    timeout=self.timeout
                )
            writer.close()
            await writer.wait_closed()
            latency = (time.time() - start) * 1000
            self._tcp_cache[key] = {'latency': latency, 'ts': time.time(), 'error': None}
            self._dead_host_tracker.record_success(host)
            return latency
        except Exception as e:
            self._dead_host_tracker.record_failure(host)
            self._tcp_cache[key] = {'latency': -1.0, 'ts': time.time(), 'error': str(e), 'error_ts': time.time()}
            return -1.0

    async def _http_probe(self, host: str, port: int, use_tls: bool) -> float:
        """HTTP-пробинг с fallback на GET."""
        session = await self._get_session()
        proto = 'https' if use_tls else 'http'
        url = f"{proto}://{host}:{port}/generate_204"
        methods = ['HEAD', 'GET']
        for method in methods:
            try:
                start = time.time()
                async with session.request(method, url, allow_redirects=False, timeout=HTTP_TIMEOUT) as resp:
                    if resp.status < 400:
                        return (time.time() - start) * 1000
            except Exception:
                continue
        return -1.0

    async def check_config(self, config: str) -> Dict:
        now = time.time()
        if config in self._cache:
            ts, result = self._cache[config]
            if now - ts < self.cache_ttl:
                return result
            else:
                del self._cache[config]

        result = {'config': config, 'valid': False, 'latency': -1.0, 'success': False, 'error': None}

        if self._should_skip(config):
            result['error'] = 'skipped_by_history'
            self._cache[config] = (now, result)
            return result

        server_info = self._extract_server_info(config)
        if not server_info:
            result['error'] = 'no_server_info'
            self._cache[config] = (now, result)
            return result

        host, port, use_tls = server_info
        tcp_latency = await self._limiter.run(host, self._tcp_latency_with_retry(host, port, use_tls))
        if tcp_latency < 0:
            result['error'] = 'tcp_failed'
            self._cache[config] = (now, result)
            return result

        if tcp_latency > 0 and tcp_latency < self.max_latency:
            http_latency = await self._limiter.run(host, self._http_probe(host, port, use_tls))
            if http_latency > 0:
                result['latency'] = http_latency
                result['valid'] = True
                result['success'] = True
                self._cache[config] = (now, result)
                return result

        if tcp_latency <= self.max_latency:
            result['latency'] = tcp_latency
            result['valid'] = True
            result['success'] = True
            self._cache[config] = (now, result)
            return result

        result['error'] = 'latency_too_high'
        self._cache[config] = (now, result)
        return result

    async def check_batch(self, configs: List[str]) -> List[Dict]:
        # ... (без изменений)
        pass

    async def close(self):
        pass

    def _extract_server_info(self, config: str) -> Optional[Tuple[str, int, bool]]:
        # ... (без изменений)
        pass

    def filter_by_latency(self, results: List[Dict], max_latency: float = None) -> List[str]:
        # ... (без изменений)
        pass

    def clear_cache(self):
        self._cache.clear()
        self._tcp_cache.clear()
        logger.info("Cleared check cache")


ActiveChecker = CachedActiveChecker
