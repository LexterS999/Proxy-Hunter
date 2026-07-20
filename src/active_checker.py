"""
Модуль для активной проверки работоспособности прокси-конфигураций.
Выполняет TCP SYN и HTTP-пробинг (HEAD) с кешированием результатов.
ICMP полностью удалён.
"""

import asyncio
import logging
import time
import socket
import re
from typing import Dict, List, Optional, Tuple
from collections import OrderedDict, deque
from urllib.parse import urlparse, parse_qs

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


class CachedActiveChecker:
    """
    Активная проверка с кешированием результатов на основе TTL.
    """

    def __init__(self,
                 timeout: float = None,
                 max_workers: int = None,
                 test_url: str = "https://www.google.com/generate_204",
                 max_latency: float = None,
                 history: Dict = None,
                 cache_ttl: int = 3600):  # 1 час
        self.timeout = timeout or TCP_TIMEOUT
        self.max_workers = max_workers or ACTIVE_CHECKER_WORKERS
        self.test_url = test_url
        self.max_latency = max_latency or MAX_LATENCY_MS
        self.history = history or {}
        self.cache_ttl = cache_ttl
        self._cache = {}  # config -> (timestamp, result)
        self._session = None
        self._connector = None
        self._limiter = ConcurrencyLimiter(
            global_limit=self.max_workers,
            per_host_limit=PER_HOST_LIMIT
        )
        self._tcp_cache = OrderedDict()
        self._cache_max_size = 5000

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

        latency = await self._tcp_latency_with_retry(host, port)
        if len(self._tcp_cache) >= self._cache_max_size:
            self._tcp_cache.popitem(last=False)
        self._tcp_cache[key] = latency
        return latency

    async def _http_probe(self, host: str, port: int, use_tls: bool) -> float:
        """Использует HEAD-запрос вместо Range."""
        try:
            session = await self._get_session()
            proto = 'https' if use_tls else 'http'
            url = f"{proto}://{host}:{port}"
            start = time.time()
            # HEAD-запрос
            async with session.head(url, allow_redirects=True, timeout=HTTP_TIMEOUT) as resp:
                if resp.status < 400:  # 2xx или 3xx
                    return (time.time() - start) * 1000
            return -1.0
        except Exception:
            return -1.0

    async def check_config(self, config: str) -> Dict:
        # Проверяем кеш
        now = time.time()
        if config in self._cache:
            ts, result = self._cache[config]
            if now - ts < self.cache_ttl:
                logger.debug(f"Using cached result for {config[:50]}")
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

        tcp_latency = await self._limiter.run(host, self._tcp_latency(host, port))
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
        if not configs:
            return []

        # Прогрев кеша TCP
        server_groups = {}
        for cfg in configs:
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

        tasks = [check_one(cfg) for cfg in configs]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        final = []
        for idx, res in enumerate(results):
            if isinstance(res, Exception):
                final.append({
                    'config': configs[idx],
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

        # fallback
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

    def clear_cache(self):
        """Очищает кеш результатов."""
        self._cache.clear()
        logger.info("Cleared check cache")


# Для обратной совместимости переименуем
ActiveChecker = CachedActiveChecker
