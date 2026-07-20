"""
Единый пул aiohttp ClientSession для всего приложения.
Предотвращает создание множества соединений и улучшает переиспользование keep-alive.
Добавлена блокировка и корректное закрытие старых соединений.
"""

import aiohttp
import asyncio
import logging
from typing import Optional

logger = logging.getLogger(__name__)

class SessionPool:
    """
    Синглтон для переиспользования одной aiohttp ClientSession.
    Используется в fetch_configs.py и active_checker.py.
    """

    _instance = None
    _session: Optional[aiohttp.ClientSession] = None
    _connector: Optional[aiohttp.TCPConnector] = None
    _lock = asyncio.Lock()

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    async def get_session(
        self,
        connector_limit: int = 200,
        per_host_limit: int = 50,
        timeout_total: float = 60.0,
        headers: Optional[dict] = None
    ) -> aiohttp.ClientSession:
        """
        Возвращает общую ClientSession. Параметры применяются только при первом создании.
        Блокировка гарантирует, что сессия создаётся только один раз.
        """
        async with self._lock:
            if self._session is None or self._session.closed:
                # Закрываем старые объекты перед созданием новых
                await self._cleanup_old()

                self._connector = aiohttp.TCPConnector(
                    limit=connector_limit,
                    limit_per_host=per_host_limit,
                    ttl_dns_cache=300,
                    enable_cleanup_closed=True,
                    force_close=True  # Явно закрывать соединения
                )
                timeout = aiohttp.ClientTimeout(total=timeout_total)
                default_headers = {
                    'User-Agent': 'Proxy-Hunter/2.0',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive'
                }
                if headers:
                    default_headers.update(headers)
                self._session = aiohttp.ClientSession(
                    connector=self._connector,
                    timeout=timeout,
                    headers=default_headers
                )
                logger.info(
                    f"Created shared ClientSession with limit={connector_limit}, "
                    f"per_host_limit={per_host_limit}"
                )
            return self._session

    async def _cleanup_old(self):
        """Закрывает старый коннектор и сессию, если они существуют."""
        if self._connector and not self._connector.closed:
            await self._connector.close()
            logger.debug("Closed old TCPConnector")
        if self._session and not self._session.closed:
            await self._session.close()
            logger.debug("Closed old ClientSession")
        self._connector = None
        self._session = None

    async def close(self):
        """Закрывает сессию и коннектор."""
        async with self._lock:
            await self._cleanup_old()
            logger.info("Closed shared ClientSession and TCPConnector")

    def reset(self):
        """Сброс состояния (для тестов)."""
        self._session = None
        self._connector = None
