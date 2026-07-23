"""
Активная проверка прокси-конфигураций с улучшенной обработкой ошибок и параллелизацией.

Исправления и оптимизации:
- Контекстные менеджеры (async with) для всех ClientSession
- Параллельная проверка TCP для групп конфигов с одинаковым host:port
- Улучшенная обработка ошибок (конкретные исключения)
- Кеширование результатов проверок
"""

import asyncio
import logging
import re
import ssl
import time
from collections import OrderedDict, deque, defaultdict
from typing import Dict, List, Optional, Tuple, Set
from urllib.parse import parse_qs, urlparse

import aiohttp
import numpy as np

from concurrency import ConcurrencyLimiter
from session_pool import SessionPool
from retry_utils import retry_with_backoff
from user_settings import TCP_TIMEOUT, HTTP_TIMEOUT, MAX_LATENCY_MS, ACTIVE_CHECKER_WORKERS, PER_HOST_LIMIT, get_settings
from parse_fallback import FallbackParser
from sni_probe import SNIProbe

logger = logging.getLogger(__name__)
settings = get_settings()


class CachedActiveChecker:
    """Проверяет работоспособность прокси с кешированием и параллелизацией."""
    def __init__(
        self,
        timeout: float = None,
        max_workers: int = None,
        test_url: str = "https://www.gstatic.com/generate_204",
        max_latency: float = None,
        history: Dict = None,
        cache_ttl: int = 1800,
    ):
        self.timeout = timeout or TCP_TIMEOUT
        self.max_workers = max_workers or ACTIVE_CHECKER_WORKERS
        self.test_url = test_url
        self.max_latency = max_latency or MAX_LATENCY_MS
        self.history = history or {}
        self.cache_ttl = cache_ttl
        self.negative_cache_ttl = min(300, cache_ttl)
        self._cache: Dict[str, Tuple[float, Dict]] = {}
        self._limiter = ConcurrencyLimiter(global_limit=self.max_workers, per_host_limit=PER_HOST_LIMIT)
        self._tcp_cache: OrderedDict[Tuple[str, int, bool], float] = OrderedDict()
        self._tcp_cache_max_size = 5000
        self._tcp_cache_alpha = 0.3
        self._historical_latencies = deque(maxlen=1000)
        self._parsed_cache: Dict[str, Optional[Dict]] = {}
        self._sni_probe = SNIProbe(timeout=self.timeout)
        self._session_pool = SessionPool()

    def _cache_get(self, config: str) -> Optional[Dict]:
        """Получает результат из кеша."""
        item = self._cache.get(config)
        if not item:
            return None
        ts, result = item
        ttl = self.cache_ttl if result.get('success') else self.negative_cache_ttl
        if time.time() - ts < ttl:
            return result
        self._cache.pop(config, None)
        return None

    def _cache_put(self, config: str, result: Dict) -> Dict:
        """Сохраняет результат в кеш."""
        self._cache[config] = (time.time(), result)
        return result

    def _should_skip(self, config: str) -> bool:
        """Проверяет, нужно ли пропустить конфиг на основе истории."""
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
            if profile.get('overall_score', 100) < 15:
                return True
        except Exception:
            pass
        return False

    def _extract_parsed(self, config: str) -> Optional[Dict]:
        """Извлекает распарсенные данные из кеша или парсит заново."""
        if config in self._parsed_cache:
            return self._parsed_cache[config]
        parsed, _ = FallbackParser.parse_with_stats(config)
        self._parsed_cache[config] = parsed
        return parsed

    async def _get_session(self) -> aiohttp.ClientSession:
        """Получает сессию из пула."""
        return await self._session_pool.get_session(
            connector_limit=max(200, self.max_workers * 4),
            per_host_limit=max(20, PER_HOST_LIMIT * 2),
            timeout_total=HTTP_TIMEOUT * 2,
        )

    @retry_with_backoff(
        attempts=3,
        base_delay=0.2,
        max_delay=1.0,
        deadline=5.0,
        retryable_exceptions=(asyncio.TimeoutError, ConnectionError, OSError, ConnectionResetError),
    )
    async def _tcp_latency_with_retry(self, host: str, port: int, use_tls: bool = False, server_hostname: Optional[str] = None) -> float:
        """Выполняет TCP-проверку с ретраями."""
        return await self._tcp_latency_raw(host, port, use_tls, server_hostname)

    async def _tcp_latency_raw(self, host: str, port: int, use_tls: bool = False, server_hostname: Optional[str] = None) -> float:
        """Выполняет TCP-проверку."""
        start = time.time()
        try:
            if use_tls:
                context = ssl.create_default_context()
                context.check_hostname = False
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=context, server_hostname=server_hostname or host),
                    timeout=self.timeout,
                )
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=False),
                    timeout=self.timeout,
                )
            writer.close()
            await writer.wait_closed()
            return (time.time() - start) * 1000.0
        except asyncio.TimeoutError:
            return -1.0
        except ConnectionRefusedError:
            return -1.0
        except OSError:
            return -1.0
        except Exception:
            return -1.0

    async def _tcp_latency(self, host: str, port: int, use_tls: bool = False, server_hostname: Optional[str] = None) -> float:
        """Возвращает закешированную TCP-задержку."""
        key = (host.lower(), int(port), bool(use_tls))
        if key in self._tcp_cache:
            self._tcp_cache.move_to_end(key)
            return self._tcp_cache[key]

        try:
            latency = await self._tcp_latency_with_retry(host, port, use_tls, server_hostname)
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

    def _extract_server_info(self, config: str, parsed: Optional[Dict] = None) -> Optional[Tuple[str, int, bool]]:
        """Извлекает информацию о сервере из конфига."""
        parsed = parsed or self._extract_parsed(config)
        if parsed:
            host = parsed.get('address') or parsed.get('add') or parsed.get('host')
            port = int(parsed.get('port', 0) or 0)
            use_tls = (parsed.get('security') in ('tls', 'reality') or parsed.get('tls') in ('tls', 'reality'))
            if host and port:
                return host, port, use_tls

        try:
            base = config.split('#')[0]
            parsed_url = urlparse(base)
            if parsed_url.hostname:
                params = parse_qs(parsed_url.query)
                security = params.get('security', [''])[0].lower()
                tls = security in ('tls', 'reality', 'xtls') or parsed_url.scheme in ('https', 'trojan')
                return parsed_url.hostname, parsed_url.port or 443, tls
        except Exception:
            pass

        match = re.search(r'@([^:]+):(\d+)', config)
        if match:
            host = match.group(1)
            port = int(match.group(2))
            tls = 'security=tls' in config or 'security=reality' in config or 'sni=' in config
            return host, port, tls
        return None

    def _extract_probe_request(self, parsed: Optional[Dict], host: str) -> Tuple[str, str]:
        """Извлекает параметры для HTTP-пробы."""
        if not parsed:
            return '/', host
        path = parsed.get('path') or '/'
        if not str(path).startswith('/'):
            path = '/' + str(path)
        host_header = parsed.get('host') or parsed.get('authority') or parsed.get('sni') or host
        return path, host_header

    async def _http_probe(self, config: str, parsed: Optional[Dict], host: str, port: int, use_tls: bool) -> float:
        """Выполняет HTTP-пробу."""
        try:
            async with await self._get_session() as session:
                scheme = 'https' if use_tls else 'http'
                path, host_header = self._extract_probe_request(parsed, host)
                url = f"{scheme}://{host}:{port}{path}"
                headers = {
                    'Host': host_header,
                    'User-Agent': 'Proxy-Hunter/2.1',
                    'Range': 'bytes=0-0',
                    'Accept': '*/*',
                    'Connection': 'keep-alive',
                }
                start = time.time()
                async with session.get(url, headers=headers, timeout=HTTP_TIMEOUT, allow_redirects=False) as resp:
                    if resp.status < 500:
                        await resp.content.readany()
                        return (time.time() - start) * 1000.0
                    return -1.0
        except asyncio.TimeoutError:
            return -1.0
        except aiohttp.ClientError as e:
            logger.debug("HTTP probe error for %s:%s: %s", host, port, e)
            return -1.0
        except Exception as e:
            logger.debug("HTTP probe error for %s:%s: %s", host, port, e)
            return -1.0

    async def check_config(self, config: str) -> Dict:
        """Проверяет один конфиг."""
        cached = self._cache_get(config)
        if cached is not None:
            return cached

        result = {'config': config, 'valid': False, 'latency': -1.0, 'success': False, 'error': None}
        if self._should_skip(config):
            result['error'] = 'skipped_by_history'
            return self._cache_put(config, result)

        parsed = self._extract_parsed(config)
        server_info = self._extract_server_info(config, parsed)
        if not server_info:
            result['error'] = 'no_server_info'
            return self._cache_put(config, result)

        host, port, use_tls = server_info
        sni = parsed.get('sni') if parsed else None
        
        # Используем лимитер для параллельных TCP-проверок
        tcp_latency = await self._limiter.run(host, self._tcp_latency(host, port, use_tls, sni))
        if tcp_latency < 0:
            result['error'] = 'tcp_failed'
            return self._cache_put(config, result)

        if len(self._historical_latencies) > 20:
            p90 = float(np.percentile(list(self._historical_latencies), 90))
            dynamic_max = min(p90 * 1.5, self.max_latency)
        else:
            dynamic_max = self.max_latency

        if tcp_latency > dynamic_max:
            result['error'] = 'latency_too_high'
            result['latency'] = tcp_latency
            return self._cache_put(config, result)

        http_latency = await self._limiter.run(host, self._http_probe(config, parsed, host, port, use_tls))
        final_latency = http_latency if http_latency > 0 else tcp_latency
        result['latency'] = final_latency
        result['valid'] = True
        result['success'] = final_latency > 0
        if result['success']:
            self._historical_latencies.append(final_latency)
        else:
            result['error'] = 'http_probe_failed'
        return self._cache_put(config, result)

    async def check_with_alternative_sni(self, config: str, alt_sni_list: List[str] = None) -> Dict:
        """Проверяет конфиг с альтернативными SNI."""
        if alt_sni_list is None:
            alt_sni_list = ['cloudflare.com', 'www.cloudflare.com', 'google.com', 'dl.google.com', 'speedtest.net']

        result = await self.check_config(config)
        if result.get('success'):
            return result

        parsed = self._extract_parsed(config)
        if not parsed:
            return result
        host = parsed.get('address') or parsed.get('add')
        port = int(parsed.get('port', 443) or 443)
        use_tls = parsed.get('security') in ('tls', 'reality') or parsed.get('tls') in ('tls', 'reality')
        if not host or not use_tls:
            return result

        for sni in alt_sni_list:
            try:
                res = await self._sni_probe.probe_check(host, sni)
            except Exception:
                continue
            if res.get('success'):
                new_result = result.copy()
                new_result['sni_override'] = sni
                new_result['success'] = True
                new_result['valid'] = True
                new_result['latency'] = res.get('latency', result.get('latency', 0))
                new_result['error'] = None
                return self._cache_put(config, new_result)
        return result

    async def check_batch(self, configs: List[str]) -> List[Dict]:
        """Проверяет пачку конфигов с параллелизацией по host:port."""
        if not configs:
            return []

        unique_configs = list(dict.fromkeys(configs))
        
        # Группируем конфиги по host:port:use_tls для параллельной проверки
        endpoint_map: Dict[Tuple[str, int, bool], List[str]] = {}
        parsed_map: Dict[str, Optional[Dict]] = {}
        for cfg in unique_configs:
            parsed = self._extract_parsed(cfg)
            parsed_map[cfg] = parsed
            info = self._extract_server_info(cfg, parsed)
            if info:
                endpoint_map.setdefault(info, []).append(cfg)

        # Предварительно прогреваем TCP-кеш для всех эндпоинтов
        warm_tasks = []
        for host, port, use_tls in endpoint_map.keys():
            warm_tasks.append(self._limiter.run(host, self._tcp_latency(host, port, use_tls)))
        if warm_tasks:
            await asyncio.gather(*warm_tasks, return_exceptions=True)

        sem = asyncio.Semaphore(self.max_workers * 2)

        async def check_one(cfg: str):
            async with sem:
                return await self.check_with_alternative_sni(cfg)

        gathered = await asyncio.gather(*(check_one(cfg) for cfg in unique_configs), return_exceptions=True)
        unique_results: Dict[str, Dict] = {}
        for idx, res in enumerate(gathered):
            cfg = unique_configs[idx]
            if isinstance(res, Exception):
                unique_results[cfg] = {
                    'config': cfg,
                    'valid': False,
                    'latency': -1.0,
                    'success': False,
                    'error': str(res),
                }
            else:
                unique_results[cfg] = res
        return [unique_results[cfg] for cfg in configs]

    async def close(self) -> None:
        """Закрывает все ресурсы."""
        self._cache.clear()
        self._parsed_cache.clear()
        self._tcp_cache.clear()
        try:
            await self._session_pool.close_all()
        except Exception:
            pass

    def filter_by_latency(self, results: List[Dict], max_latency: float = None) -> List[str]:
        """Фильтрует конфиги по задержке."""
        if max_latency is None:
            max_latency = self.max_latency
        return [
            r['config'] for r in results
            if r.get('valid', False) and 0 <= r.get('latency', -1) <= max_latency
        ]

    def clear_cache(self) -> None:
        """Очищает кеш."""
        self._cache.clear()
        logger.info("Cleared check cache")

    async def test_with_multiple_sni(self, config: str, sni_list: List[str]) -> Dict:
        """Тестирует конфиг с несколькими SNI."""
        parsed = self._extract_parsed(config)
        if not parsed:
            return {'error': 'parse_failed'}
        host = parsed.get('add') or parsed.get('address')
        use_tls = parsed.get('security') in ('tls', 'reality') or parsed.get('tls') in ('tls', 'reality')
        if not host or not use_tls:
            return {'error': 'no_tls'}

        results = {}
        for sni in sni_list:
            res = await self._sni_probe.probe_check(host, sni)
            results[sni] = {
                'success': res.get('success', False),
                'latency': res.get('latency', -1.0),
                'error': res.get('error'),
            }
        return results


ActiveChecker = CachedActiveChecker
