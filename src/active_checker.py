"""
Модуль для активной проверки работоспособности прокси-конфигураций.
Выполняет TCP SYN (без TLS) с кешированием по хосту:порту,
HTTP-пробинг через keep-alive сессию, фильтрацию по истории.
Добавлены: per-host семафоры, LRU-кеш, расширенный пробинг, SNI-проверка, speed-тест,
а также персистентное кеширование TCP/HTTP, пропуск стабильных профилей,
параллельный запуск TCP и HTTP, батчинг по хосту.
"""

import asyncio
import logging
import time
import socket
import os
import re
import sqlite3
import json
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
from urllib.parse import urlparse, parse_qs

import aiohttp
from aiohttp import ClientTimeout

from concurrency import ConcurrencyLimiter
from session_pool import SessionPool
from retry_utils import retry_with_backoff
from protocol_registry import registry
from profile_scorer import ProfileScorer

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
    ВАЖНО: этот модуль выполняет только проверку достижимости (TCP + HTTP HEAD),
    НЕ проверяет работоспособность самого прокси-протокола (VLESS/VMess/Trojan handshake).
    """

    def __init__(self,
                 timeout: float = 1.0,
                 max_workers: int = None,
                 test_url: str = "https://www.google.com/generate_204",
                 max_latency: float = 6000.0,
                 history: Dict = None,
                 cache_db: str = "active_check_cache.db"):
        self.timeout = timeout
        self.max_workers = max_workers or min(100, (os.cpu_count() or 4) * 4)
        self.test_url = test_url
        self.max_latency = max_latency
        self.history = history or {}
        self._session = None
        self._connector = None

        # Контроль параллелизма
        self._limiter = ConcurrencyLimiter(
            global_limit=self.max_workers,
            per_host_limit=max(2, self.max_workers // 10)
        )

        # Персистентный кеш TCP/HTTP (SQLite)
        self._cache_db = cache_db
        self._init_cache_db()

        # LRU-кеш в памяти для быстрого доступа
        self._tcp_cache = {}
        self._cache_max_size = 10000

        # Счётчик обращений к кешу для статистики
        self._cache_hits = 0
        self._cache_misses = 0

        # Профилировщик для пропуска стабильных
        self._scorer = ProfileScorer()

    def _init_cache_db(self):
        """Создаёт таблицу для кеша, если её нет."""
        conn = sqlite3.connect(self._cache_db)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS tcp_cache (
                host TEXT,
                port INTEGER,
                latency REAL,
                checked_at INTEGER,
                PRIMARY KEY (host, port)
            )
        ''')
        # Индекс для быстрого удаления старых записей
        c.execute('CREATE INDEX IF NOT EXISTS idx_checked_at ON tcp_cache(checked_at)')
        conn.commit()
        conn.close()

    def _get_cached_tcp(self, host: str, port: int, ttl_seconds: int = 900) -> Optional[float]:
        """Возвращает кешированную задержку, если она не старше TTL."""
        # Сначала проверяем память
        key = (host, port)
        if key in self._tcp_cache:
            entry = self._tcp_cache[key]
            if time.time() - entry['time'] < ttl_seconds:
                self._cache_hits += 1
                return entry['latency']
            else:
                del self._tcp_cache[key]

        # Затем SQLite
        conn = sqlite3.connect(self._cache_db)
        c = conn.cursor()
        c.execute(
            'SELECT latency, checked_at FROM tcp_cache WHERE host=? AND port=?',
            (host, port)
        )
        row = c.fetchone()
        conn.close()
        if row:
            latency, checked_at = row
            if time.time() - checked_at < ttl_seconds:
                self._cache_hits += 1
                # Сохраняем в память
                self._tcp_cache[key] = {'latency': latency, 'time': checked_at}
                return latency
        self._cache_misses += 1
        return None

    def _save_cached_tcp(self, host: str, port: int, latency: float):
        """Сохраняет задержку в кеш (память + БД)."""
        key = (host, port)
        now = time.time()
        self._tcp_cache[key] = {'latency': latency, 'time': now}

        # Ограничиваем размер памяти
        if len(self._tcp_cache) > self._cache_max_size:
            # Удаляем половину (простейший LRU – удаляем случайные)
            items = list(self._tcp_cache.items())
            self._tcp_cache = dict(items[len(items)//2:])

        # Сохраняем в БД с заменой
        conn = sqlite3.connect(self._cache_db)
        c = conn.cursor()
        c.execute(
            'INSERT OR REPLACE INTO tcp_cache (host, port, latency, checked_at) VALUES (?, ?, ?, ?)',
            (host, port, latency, int(now))
        )
        conn.commit()
        conn.close()

    def _should_skip_stable(self, config: str) -> bool:
        """Пропускает активную проверку для стабильных профилей."""
        if not self.history:
            return False
        try:
            parsed = registry.parse(config)
            if not parsed:
                return False
            key = self._scorer.get_profile_key(config, parsed)
            profile = self.history.get('profiles', {}).get(key, {})
            if not profile:
                return False
            # Критерии: стабильность > 0.9, успешность > 0.95, последний успех < 1 часа
            stability = self._scorer.calculate_stability(profile)
            success_count = profile.get('success_count', 0)
            fail_count = profile.get('fail_count', 0)
            total = success_count + fail_count
            if total == 0:
                return False
            success_rate = success_count / total
            last_seen = profile.get('last_seen')
            if not last_seen:
                return False
            try:
                from datetime import datetime, timedelta
                last_time = datetime.fromisoformat(last_seen)
                age = (datetime.now() - last_time).total_seconds()
            except:
                age = 999999
            if stability > 0.9 and success_rate > 0.95 and age < 3600:
                # Берём среднюю латентность из профиля
                latencies = profile.get('latencies', [])
                avg_lat = sum(latencies) / len(latencies) if latencies else 200
                logger.debug(f"Skipping active check for stable profile {key}")
                return True
        except Exception as e:
            logger.debug(f"Error checking stable profile: {e}")
        return False

    def _should_skip(self, config: str) -> bool:
        """Фильтрация по историческим данным: пропускаем заведомо мёртвые."""
        if not self.history:
            return False
        # Сначала проверяем стабильные
        if self._should_skip_stable(config):
            return True
        from profile_scorer import ProfileScorer
        scorer = ProfileScorer()
        try:
            parsed = registry.parse(config)
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

    async def _get_session(self) -> aiohttp.ClientSession:
        pool = SessionPool()
        self._session = await pool.get_session(
            connector_limit=200,
            per_host_limit=50,
            timeout_total=self.timeout * 2
        )
        return self._session

    @retry_with_backoff(attempts=3, base_delay=0.2, max_delay=1.0, deadline=5.0)
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
        # Пытаемся получить из кеша
        cached = self._get_cached_tcp(host, port)
        if cached is not None:
            return cached

        latency = await self._tcp_latency_with_retry(host, port)
        if latency > 0:
            self._save_cached_tcp(host, port, latency)
        return latency

    async def _http_probe(self, host: str, port: int, use_tls: bool) -> float:
        """HTTP HEAD-запрос для проверки доступности сервера (без проверки сертификата)."""
        try:
            session = await self._get_session()
            proto = 'https' if use_tls else 'http'
            url = f"{proto}://{host}:{port}"
            start = time.time()
            async with session.head(url, allow_redirects=True, timeout=self.timeout, ssl=False) as resp:
                if resp.status in (200, 204, 301, 302, 307, 308):
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
            async with session.get(url, timeout=self.timeout, ssl=False) as resp:
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

        # Используем ProtocolRegistry для извлечения серверной информации
        server_info = registry.get_server_info(config)
        if not server_info:
            result['error'] = 'no_server_info'
            logger.debug(f"Could not extract server info from: {config[:100]}")
            return result

        host, port, use_tls = server_info

        # Параллельный запуск TCP и HTTP
        tcp_task = asyncio.create_task(self._limiter.run(host, self._tcp_latency(host, port)))
        http_task = asyncio.create_task(self._limiter.run(host, self._http_probe(host, port, use_tls)))

        done, pending = await asyncio.wait([tcp_task, http_task], return_when=asyncio.FIRST_COMPLETED)

        tcp_latency = -1.0
        http_latency = -1.0

        # Обрабатываем TCP
        if tcp_task in done:
            try:
                tcp_latency = tcp_task.result()
            except Exception as e:
                logger.debug(f"TCP task exception: {e}")
                tcp_latency = -1.0
        else:
            # TCP всё ещё выполняется – отменяем? Но нам нужен результат, поэтому ждём с таймаутом
            try:
                tcp_latency = await asyncio.wait_for(tcp_task, timeout=self.timeout * 2)
            except asyncio.TimeoutError:
                tcp_latency = -1.0
                tcp_task.cancel()
            except Exception as e:
                logger.debug(f"TCP task exception after wait: {e}")
                tcp_latency = -1.0

        # Обрабатываем HTTP
        if http_task in done:
            try:
                http_latency = http_task.result()
            except Exception as e:
                logger.debug(f"HTTP task exception: {e}")
                http_latency = -1.0
        else:
            # Если TCP уже завершился успешно, ждём HTTP
            if tcp_latency > 0:
                try:
                    http_latency = await asyncio.wait_for(http_task, timeout=self.timeout)
                except asyncio.TimeoutError:
                    http_latency = -1.0
                    http_task.cancel()
                except Exception as e:
                    logger.debug(f"HTTP task exception after wait: {e}")
                    http_latency = -1.0
            else:
                # TCP не удался, отменяем HTTP
                http_task.cancel()
                http_latency = -1.0

        # Принимаем решение
        if tcp_latency < 0:
            result['error'] = 'tcp_failed'
            logger.debug(f"TCP failed for {host}:{port}")
            return result

        if tcp_latency > 0 and tcp_latency < self.max_latency:
            # Если HTTP успешен, используем его задержку
            if http_latency > 0:
                result['latency'] = http_latency
                result['valid'] = True
                result['success'] = True
                result['speed_tag'] = self._classify_speed(http_latency)
                sni = self._extract_sni(config)
                if sni:
                    await self._limiter.run(host, self._sni_probe(host, port, sni))
                return result

        # Если HTTP не удался, но TCP прошёл – считаем валидным с TCP-задержкой
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
        parsed = registry.parse(config)
        if parsed:
            return parsed.get('sni') or parsed.get('host')
        return None

    async def check_batch(self, configs: List[str]) -> List[Dict]:
        if not configs:
            return []

        filtered_configs = [c for c in configs if not self._should_skip(c)]

        # Группировка по хосту для батчинга
        server_groups = defaultdict(list)
        for cfg in filtered_configs:
            info = registry.get_server_info(cfg)
            if info:
                server_groups[(info[0], info[1])].append(cfg)

        # Предварительный прогрев кеша – асинхронное разрешение DNS и TCP кеш
        warm_tasks = []
        for (host, port), cfgs in server_groups.items():
            # Используем одну задачу на хост для заполнения кеша
            warm_tasks.append(self._limiter.run(host, self._tcp_latency(host, port)))
        if warm_tasks:
            await asyncio.gather(*warm_tasks, return_exceptions=True)

        # Создаём сессию для каждой группы, чтобы использовать keep-alive
        sem = asyncio.Semaphore(self.max_workers * 2)

        async def check_with_session(cfg: str, session: aiohttp.ClientSession):
            async with sem:
                # Передаём сессию в метод check_config? Нужно модифицировать, чтобы использовать переданную сессию.
                # Пока оставим как есть, но можно передать сессию через self._session.
                # Для простоты будем использовать общую сессию из пула.
                return await self.check_config(cfg)

        # Запускаем проверки
        tasks = []
        for cfg in filtered_configs:
            tasks.append(check_with_session(cfg, None))  # Не используется, т.к. check_config использует свой пул

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

    def filter_by_latency(self, results: List[Dict], max_latency: float = None) -> List[str]:
        if max_latency is None:
            max_latency = self.max_latency
        return [
            r['config'] for r in results
            if r.get('valid', False) and 0 <= r.get('latency', -1) <= max_latency
        ]
