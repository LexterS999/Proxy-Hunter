"""
Модуль для активной проверки работоспособности прокси-конфигураций.
Выполняет TCP SYN (без TLS) с кешированием по хосту:порту,
HTTP-пробинг через keep-alive сессию, фильтрацию по истории.
Добавлены: per-host семафоры, LRU-кеш, расширенный пробинг, SNI-проверка, speed-тест.
"""

import asyncio
import logging
import time
import socket
import os
import re
from typing import Dict, List, Optional, Tuple
from collections import defaultdict, OrderedDict
from urllib.parse import urlparse, parse_qs

import aiohttp
from aiohttp import ClientTimeout

from concurrency import ConcurrencyLimiter
from session_pool import SessionPool
from retry_utils import retry_with_backoff

logger = logging.getLogger(__name__)

SPEED_TAGS = {
    'fast': (0, 200),
    'medium': (200, 800),
    'slow': (800, 2000),
    'dead': (2000, None)
}


class ActiveChecker:
    """
    Активная проверка с кешированием, пулом соединений и фильтрацией.
    """

    def __init__(self,
                 timeout: float = 1.0,
                 max_workers: int = None,
                 test_url: str = "https://www.google.com/generate_204",
                 max_latency: float = 6000.0,
                 history: Dict = None):
        self.timeout = timeout
        self.max_workers = max_workers or min(100, (os.cpu_count() or 4) * 4)
        self.test_url = test_url
        self.max_latency = max_latency
        self.history = history or {}
        self._session = None
        self._connector = None

        self._limiter = ConcurrencyLimiter(
            global_limit=self.max_workers,
            per_host_limit=max(2, self.max_workers // 10)
        )

        # Используем OrderedDict как LRU-кеш с ограничением размера
        self._tcp_cache = OrderedDict()
        self._cache_max_size = 5000  # уменьшено с 10000 для эффективности

    def _should_skip(self, config: str) -> bool:
        """Фильтрация по историческим данным: пропускаем заведомо мёртвые."""
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
            timeout_total=self.timeout * 2
        )
        return self._session

    @retry_with_backoff(attempts=3, base_delay=0.2, max_delay=1.0, deadline=5.0,
                        retryable_exceptions=(asyncio.TimeoutError, ConnectionError, OSError, ConnectionResetError))
    async def _tcp_latency_with_retry(self, host: str, port: int) -> float:
        return await self._tcp_latency_raw(host, port)

    async def _tcp_latency_raw(self, host: str, port: int) -> float:
        """Реализация TCP-проверки без кеша."""
        start = time.time()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=False),
                timeout=self.timeout
            )
            writer.close()
            await writer.wait_closed()
            latency = (time.time() - start) * 1000
            return latency
        except asyncio.TimeoutError:
            logger.debug(f"TCP timeout {host}:{port}")
            return -1.0
        except ConnectionRefusedError:
            logger.debug(f"TCP connection refused {host}:{port}")
            return -1.0
        except OSError as e:
            logger.debug(f"TCP OS error {host}:{port}: {e}")
            return -1.0
        except socket.gaierror as e:
            logger.debug(f"TCP DNS error {host}:{port}: {e}")
            return -1.0
        except Exception as e:
            logger.debug(f"TCP check error {host}:{port}: {e}")
            return -1.0

    async def _tcp_latency(self, host: str, port: int) -> float:
        """Возвращает задержку из кеша или выполняет проверку."""
        key = (host, port)
        if key in self._tcp_cache:
            # Перемещаем в конец (LRU)
            self._tcp_cache.move_to_end(key)
            return self._tcp_cache[key]

        latency = await self._tcp_latency_with_retry(host, port)

        # LRU-обновление с ограничением размера
        if len(self._tcp_cache) >= self._cache_max_size:
            # Удаляем самый старый элемент (первый в OrderedDict)
            self._tcp_cache.popitem(last=False)
        self._tcp_cache[key] = latency
        return latency

    async def _http_probe(self, host: str, port: int, use_tls: bool) -> float:
        """
        HTTP-пробинг с использованием GET и Range: bytes=0-0 для минимизации трафика.
        """
        try:
            session = await self._get_session()
            proto = 'https' if use_tls else 'http'
            url = f"{proto}://{host}:{port}"
            headers = {'Range': 'bytes=0-0'}
            start = time.time()
            async with session.get(url, headers=headers, allow_redirects=True, timeout=self.timeout) as resp:
                if resp.status in (200, 204, 206, 301, 302, 307, 308):
                    return (time.time() - start) * 1000
            return -1.0
        except Exception as e:
            logger.debug(f"HTTP probe error {host}:{port}: {e}")
            return -1.0

    async def _sni_probe(self, host: str, port: int, sni: Optional[str] = None) -> float:
        if not sni:
            sni = host
        try:
            import ssl
            context = ssl.create_default_context()
            start = time.time()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=context, server_hostname=sni),
                timeout=self.timeout
            )
            writer.close()
            await writer.wait_closed()
            return (time.time() - start) * 1000
        except Exception as e:
            logger.debug(f"SNI probe failed {host}:{port} SNI={sni}: {e}")
            return -1.0

    async def _speed_test(self, host: str, port: int, use_tls: bool, test_file_size: int = 10*1024) -> float:
        try:
            session = await self._get_session()
            proto = 'https' if use_tls else 'http'
            url = f"{proto}://{host}:{port}/speedtest?size={test_file_size}"
            start = time.time()
            async with session.get(url, timeout=self.timeout) as resp:
                if resp.status != 200:
                    return -1.0
                content = await resp.read()
                elapsed = time.time() - start
                if elapsed < 0.001:
                    return -1.0
                size_kb = len(content) / 1024
                speed = size_kb / elapsed
                return speed
        except Exception:
            return -1.0

    def _classify_speed(self, latency_ms: float) -> str:
        for tag, (low, high) in SPEED_TAGS.items():
            if high is None:
                if latency_ms >= low:
                    return tag
            else:
                if low <= latency_ms < high:
                    return tag
        return 'unknown'

    async def check_config(self, config: str) -> Dict:
        result = {'config': config, 'valid': False, 'latency': -1.0, 'success': False, 'error': None, 'speed_tag': 'unknown'}

        if self._should_skip(config):
            result['error'] = 'skipped_by_history'
            logger.debug(f"Config skipped by history: {config[:80]}")
            return result

        server_info = self._extract_server_info(config)
        if not server_info:
            result['error'] = 'no_server_info'
            logger.debug(f"Could not extract server info from: {config[:100]}")
            return result

        host, port, use_tls = server_info

        try:
            tcp_latency = await self._limiter.run(host, self._tcp_latency(host, port))
        except Exception as e:
            result['error'] = f'tcp_limiter_exception: {e}'
            logger.debug(f"TCP limiter error for {host}:{port}: {e}")
            return result

        if tcp_latency < 0:
            result['error'] = 'tcp_failed'
            logger.debug(f"TCP failed for {host}:{port}")
            return result

        if tcp_latency > 0 and tcp_latency < self.max_latency:
            http_latency = await self._limiter.run(host, self._http_probe(host, port, use_tls))
            if http_latency > 0:
                result['latency'] = http_latency
                result['valid'] = True
                result['success'] = True
                result['speed_tag'] = self._classify_speed(http_latency)
                sni = self._extract_sni(config)
                if sni:
                    await self._limiter.run(host, self._sni_probe(host, port, sni))
                return result

        if tcp_latency <= self.max_latency:
            result['latency'] = tcp_latency
            result['valid'] = True
            result['success'] = True
            result['speed_tag'] = self._classify_speed(tcp_latency)
            return result

        result['error'] = 'latency_too_high'
        logger.debug(f"Latency too high for {host}:{port}: {tcp_latency:.2f}ms")
        return result

    def _extract_sni(self, config: str) -> Optional[str]:
        try:
            import config_parser as parser
            if config.startswith('vless://'):
                data = parser.parse_vless(config)
                if data:
                    return data.get('sni')
            elif config.startswith('vmess://'):
                data = parser.decode_vmess(config)
                if data:
                    return data.get('sni')
            elif config.startswith('trojan://'):
                data = parser.parse_trojan(config)
                if data:
                    return data.get('sni')
        except Exception:
            pass
        return None

    async def check_batch(self, configs: List[str]) -> List[Dict]:
        if not configs:
            return []

        filtered_configs = [c for c in configs if not self._should_skip(c)]

        server_groups = defaultdict(list)
        for cfg in filtered_configs:
            info = self._extract_server_info(cfg)
            if info:
                server_groups[(info[0], info[1])].append(cfg)

        warm_tasks = []
        for (host, port), cfgs in server_groups.items():
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
                    'error': str(res),
                    'speed_tag': 'unknown'
                })
            else:
                final.append(res)

        return final

    async def close(self):
        pass

    def _extract_server_info(self, config: str) -> Optional[Tuple[str, int, bool]]:
        """
        Извлекает хост, порт и флаг TLS из конфигурации.
        Возвращает (host, port, use_tls) или None.
        Улучшенная версия с регулярными выражениями.
        """
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

        try:
            base = config.split('#')[0]
            parsed = urlparse(base)
            if parsed.hostname:
                host = parsed.hostname
                port = parsed.port
                if port is None:
                    if parsed.scheme in ('https', 'vless', 'trojan'):
                        port = 443
                    elif parsed.scheme == 'ss':
                        port = 8388
                    elif parsed.scheme == 'vmess':
                        port = 80
                    else:
                        port = 443
                params = parse_qs(parsed.query)
                security = params.get('security', [''])[0].lower()
                tls = security in ('tls', 'reality', 'xtls') or parsed.scheme in ('https', 'trojan')
                return (host, port, tls)
        except Exception as e:
            logger.debug(f"urlparse extraction failed: {e}")

        match = re.search(r'@([^:]+):(\d+)', config)
        if match:
            host = match.group(1)
            port = int(match.group(2))
            tls = 'security=tls' in config or 'security=reality' in config or 'sni=' in config
            return (host, port, tls)

        match = re.search(r'([0-9a-zA-Z.-]+):(\d+)', config)
        if match:
            host = match.group(1)
            port = int(match.group(2))
            tls = 'security=tls' in config or 'security=reality' in config or 'sni=' in config
            return (host, port, tls)

        logger.debug(f"Could not extract server info from config: {config[:100]}")
        return None

    def filter_by_latency(self, results: List[Dict], max_latency: float = None) -> List[str]:
        if max_latency is None:
            max_latency = self.max_latency
        return [
            r['config'] for r in results
            if r.get('valid', False) and 0 <= r.get('latency', -1) <= max_latency
        ]
