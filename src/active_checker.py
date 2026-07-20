"""
active_checker.py - Активная проверка прокси (TCP/HTTP)
"""

import asyncio
import time
import logging
from typing import Dict, Any, Optional, Tuple

import aiohttp

from config_identity import ConfigIdentity
from session_pool import SessionPool

logger = logging.getLogger(__name__)


class AsyncConfigFetcher:
    """Обёртка над HTTP-сессией для проверок"""

    def __init__(self):
        self._closed = False

    async def close(self):
        """
        [CHANGE] реальное закрытие сессии (ранее было `pass` → утечка соединений).
        """
        if self._closed:
            return
        try:
            pool = SessionPool()
            await pool.close()
        except Exception as e:
            logger.debug(f"⚠️ close: {e}")
        finally:
            self._closed = True


class ActiveChecker:
    """Активная проверка прокси-конфигов"""

    def __init__(self, max_latency: int = 5000, timeout: int = 10,
                 connector_limit: int = 500, per_host: int = 100):
        self.max_latency = max_latency
        self.timeout = timeout
        self.connector_limit = connector_limit
        self.per_host = per_host
        self.fetcher = AsyncConfigFetcher()

    def _extract_server_info(self, config: str) -> Tuple[str, int, str]:
        """
        [CHANGE] извлечение через единый ConfigIdentity
        (ранее — собственная независимая реализация).
        """
        ep = ConfigIdentity.get_endpoint(config)
        if ep.is_valid:
            return ep.host, ep.port, ep.proto
        return '', 0, ''

    async def check_config(self, config: str) -> Dict[str, Any]:
        """Проверяет конфиг: TCP latency + HTTP probe"""
        result = {
            'config': config,
            'valid': False,
            'tcp_latency': -1,
            'http_ok': False,
            'error': None,
        }

        host, port, proto = self._extract_server_info(config)
        if not host or not port:
            result['error'] = 'cannot extract server info'
            return result

        # TCP latency
        tcp_latency = await self._tcp_ping(host, port)
        result['tcp_latency'] = tcp_latency

        if tcp_latency < 0 or tcp_latency > self.max_latency:
            result['error'] = 'tcp timeout'
            return result

        # HTTP probe (дополнительная проверка)
        http_ok = await self._http_probe(host, port)
        result['http_ok'] = http_ok

        # Валидно, если TCP в пределах нормы
        if tcp_latency <= self.max_latency:
            result['valid'] = True

        return result

    async def _tcp_ping(self, host: str, port: int) -> float:
        """Измеряет TCP latency (мс). Возвращает -1 при ошибке."""
        try:
            start = time.perf_counter()
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )
            latency = (time.perf_counter() - start) * 1000.0
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return round(latency, 2)
        except Exception:
            return -1.0

    async def _http_probe(self, host: str, port: int) -> bool:
        """HEAD-запрос для проверки HTTP-доступности порта."""
        try:
            session = await SessionPool().get_session(
                connector_limit=self.connector_limit,
                per_host=self.per_host
            )
            url = f"https://{host}:{port}"
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with session.head(url, timeout=timeout, ssl=False,
                                    allow_redirects=False) as resp:
                return resp.status < 500
        except Exception:
            return False

    async def check_batch(self, configs: list) -> list:
        """Пакетная проверка"""
        tasks = [self.check_config(c) for c in configs]
        return await asyncio.gather(*tasks, return_exceptions=False)

    async def close(self):
        await self.fetcher.close()
