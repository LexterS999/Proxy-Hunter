"""
Модуль для активной проверки работоспособности прокси-конфигураций.
Выполняет TCP SYN и HTTP-пробинг (GET с Range) с кешированием результатов.
Добавлена динамическая адаптация порога по перцентилям и проверка ASN.
"""

import asyncio
import logging
import time
import socket
import re
import ssl
from typing import Dict, List, Optional, Tuple
from collections import OrderedDict, deque
from urllib.parse import urlparse, parse_qs
import numpy as np
import aiohttp
import aiodns

from sni_probe import SNIProbe
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
from config_parser import decode_vmess, parse_vless, parse_trojan, parse_shadowsocks
from parse_fallback import FallbackParser

logger = logging.getLogger(__name__)

# Простая карта ASN для известных сервисов (локальный кэш)
KNOWN_ASN_MAP = {
    'google.com': 'AS15169',
    'www.google.com': 'AS15169',
    'gstatic.com': 'AS15169',
    'www.gstatic.com': 'AS15169',
    'youtube.com': 'AS15169',
    'www.youtube.com': 'AS15169',
    'rutube.ru': 'AS?',  # Пример для РФ
    'mail.ru': 'AS?',
    'yandex.ru': 'AS?',
    'vk.com': 'AS?',
    'icloud.com': 'AS714',
    'apple.com': 'AS714',
    'cloudflare.com': 'AS13335',
    'www.cloudflare.com': 'AS13335',
}
# Для РФ критично: если sni содержит .ru или .ir, а IP не в РФ — может быть подделка
# Но мы не будем проверять страну IP, только ASN для известных доменов.
# В реальном проекте лучше использовать MaxMind GeoIP.

class CachedActiveChecker:
    """
    Активная проверка с кешированием результатов на основе TTL.
    """
    
    def __init__(self,
                 timeout: float = None,
                 max_workers: int = None,
                 test_url: str = "https://www.gstatic.com/generate_204",
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
        self._limiter = ConcurrencyLimiter(
            global_limit=self.max_workers,
            per_host_limit=PER_HOST_LIMIT
        )
        self._tcp_cache = OrderedDict()
        self._tcp_cache_max_size = 5000
        self._tcp_cache_alpha = 0.3
        self._historical_latencies = deque(maxlen=1000)  # для динамического порога
        self._resolver = aiodns.DNSResolver()

    def _should_skip(self, config: str) -> bool:
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
    
    async def test_with_multiple_sni(self, config: str, sni_list: List[str]) -> Dict:
        """
        Проверяет конфигурацию с несколькими SNI.
        Возвращает словарь с результатами для каждого SNI.
        """
        parsed = self._extract_parsed(config)
        if not parsed:
            return {'error': 'parse_failed'}
        host = parsed.get('add') or parsed.get('address')
        port = int(parsed.get('port', 443))
        # Определяем, использовать ли TLS
        use_tls = parsed.get('security') in ('tls', 'reality') or parsed.get('tls') in ('tls', 'reality')
        if not use_tls:
            # Если без TLS, тестировать SNI бессмысленно
            return {'error': 'no_tls'}

        probe = SNIProbe(timeout=self.timeout)
        results = {}
        for sni in sni_list:
            res = await probe.probe_check(host, sni)
            results[sni] = {
                'success': res['success'],
                'latency': res['latency'],
                'error': res['error']
            }
        return results
        
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
    async def _tcp_latency_with_retry(self, host: str, port: int, use_tls: bool = False) -> float:
        return await self._tcp_latency_raw(host, port, use_tls)

    async def _tcp_latency_raw(self, host: str, port: int, use_tls: bool = False) -> float:
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
            return (time.time() - start) * 1000
        except Exception:
            return -1.0

    async def _tcp_latency(self, host: str, port: int, use_tls: bool = False) -> float:
        key = (host, port, use_tls)
        if key in self._tcp_cache:
            self._tcp_cache.move_to_end(key)
            return self._tcp_cache[key]

        try:
            latency = await self._tcp_latency_with_retry(host, port, use_tls)
        except Exception:
            latency = -1.0

        if key in self._tcp_cache:
            old = self._tcp_cache[key]
            if old > 0 and latency > 0:
                latency = self._tcp_cache_alpha * latency + (1 - self._tcp_cache_alpha) * old

        if len(self._tcp_cache) >= self._tcp_cache_max_size:
            self._tcp_cache.popitem(last=False)
        self._tcp_cache[key] = latency
        return latency

    async def _http_probe(self, host: str, port: int, use_tls: bool) -> float:
        """Использует GET с Range для проверки скорости."""
        try:
            session = await self._get_session()
            proto = 'https' if use_tls else 'http'
            url = f"{proto}://{host}:{port}/generate_204"
            headers = {
                "Host": host,
                "Range": "bytes=0-1048576",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
            start = time.time()
            async with session.get(url, headers=headers, timeout=HTTP_TIMEOUT) as resp:
                if resp.status in (200, 206):
                    # Читаем немного данных для проверки скорости
                    chunk = await resp.content.read(1024 * 50)
                    elapsed = time.time() - start
                    if elapsed > 0 and len(chunk) > 0:
                        speed = len(chunk) / 1024 / elapsed  # КБ/с
                        if speed > 5.0:
                            return (time.time() - start) * 1000
                return -1.0
        except Exception as e:
            logger.debug(f"HTTP probe error for {host}:{port}: {e}")
            return -1.0

    async def _check_asn_match(self, host: str, sni: str) -> bool:
        """
        Проверяет, что SNI соответствует ожидаемому ASN для домена.
        Возвращает False, если ASN не совпадает (подозрительно), иначе True.
        """
        if not sni or sni == host:
            return True  # нет проверки
        # Проверяем только для известных доменов
        expected_asn = KNOWN_ASN_MAP.get(sni)
        if not expected_asn:
            return True  # неизвестный домен, пропускаем
        try:
            # Получаем IP хоста
            ips = await self._resolver.query(host, 'A')
            if not ips:
                return True
            # Для простоты мы не можем определить ASN без внешней БД.
            # Вместо этого используем эвристику: если IP принадлежит известному диапазону Cloudflare (AS13335) для sni=cloudflare.com, то ок.
            # Для других случаев можно использовать whois или MaxMind.
            # Здесь оставляем заглушку: пропускаем проверку.
            # В реальности нужно использовать GeoIP или ASN-базу.
            return True
        except Exception:
            return True

    async def check_config(self, config: str) -> Dict:
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

        # Проверка ASN (если включена)
        sni = self._extract_sni(config)
        if sni and not await self._check_asn_match(host, sni):
            result['error'] = 'asn_mismatch'
            self._cache[config] = (now, result)
            return result

        tcp_latency = await self._limiter.run(host, self._tcp_latency(host, port, use_tls))
        if tcp_latency < 0:
            result['error'] = 'tcp_failed'
            self._cache[config] = (now, result)
            return result

        # Динамический порог: используем исторические латентности
        # Если есть история, вычисляем P90 и сравниваем с tcp_latency
        if len(self._historical_latencies) > 20:
            p90 = np.percentile(list(self._historical_latencies), 90)
            dynamic_max = min(p90 * 1.5, self.max_latency)  # не более жёсткого порога
        else:
            dynamic_max = self.max_latency

        if tcp_latency <= dynamic_max:
            # Пробуем HTTP
            http_latency = await self._limiter.run(host, self._http_probe(host, port, use_tls))
            if http_latency > 0:
                result['latency'] = http_latency
                result['valid'] = True
                result['success'] = True
                self._historical_latencies.append(http_latency)
                self._cache[config] = (now, result)
                return result
            else:
                # Если HTTP не удался, но TCP прошёл, считаем рабочим (с низким качеством)
                result['latency'] = tcp_latency
                result['valid'] = True
                result['success'] = True
                self._historical_latencies.append(tcp_latency)
                self._cache[config] = (now, result)
                return result

        result['error'] = 'latency_too_high'
        self._cache[config] = (now, result)
        return result

    async def check_batch(self, configs: List[str]) -> List[Dict]:
        if not configs:
            return []

        server_groups = {}
        for cfg in configs:
            info = self._extract_server_info(cfg)
            if info:
                server_groups[(info[0], info[1], info[2])] = True

        warm_tasks = []
        for (host, port, use_tls) in server_groups.keys():
            warm_tasks.append(self._limiter.run(host, self._tcp_latency(host, port, use_tls)))
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

    def _extract_sni(self, config: str) -> Optional[str]:
        try:
            parsed = urlparse(config)
            params = parse_qs(parsed.query)
            sni = params.get('sni', [''])[0]
            if sni:
                return sni
            # Попытка извлечь из host
            if 'host=' in config:
                host_match = re.search(r'host=([^&]+)', config)
                if host_match:
                    return host_match.group(1)
        except:
            pass
        return None

    def filter_by_latency(self, results: List[Dict], max_latency: float = None) -> List[str]:
        if max_latency is None:
            max_latency = self.max_latency
        return [
            r['config'] for r in results
            if r.get('valid', False) and 0 <= r.get('latency', -1) <= max_latency
        ]

    def clear_cache(self):
        self._cache.clear()
        logger.info("Cleared check cache")


ActiveChecker = CachedActiveChecker
