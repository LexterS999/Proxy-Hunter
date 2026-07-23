"""
Единый пул aiohttp ClientSession для всего приложения.
Переиспользует keep-alive соединения и умеет:
- Автоматически очищать старые сессии при создании новых
- Мягко расширять лимиты
- Закрывать ресурсы при ошибках
"""

import aiohttp
import asyncio
import logging
from typing import Optional, Dict, Any, List

logger = logging.getLogger(__name__)


class SessionPool:
    """Пул сессий aiohttp с автоматической очисткой и управлением ресурсами."""
    
    _instance: Optional["SessionPool"] = None
    _session: Optional[aiohttp.ClientSession] = None
    _connector: Optional[aiohttp.TCPConnector] = None
    _lock: Optional[asyncio.Lock] = None
    _config: Optional[Dict[str, Any]] = None
    _active_sessions: List[aiohttp.ClientSession] = []  # Отслеживаем все активные сессии

    def __new__(cls) -> "SessionPool":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def _get_lock(self) -> asyncio.Lock:
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    def _needs_recreate(
        self,
        connector_limit: int,
        per_host_limit: int,
        timeout_total: float,
        headers: Optional[dict],
    ) -> bool:
        """Проверяет, нужно ли пересоздать сессию."""
        if self._session is None or self._session.closed or self._config is None:
            return True

        requested = {
            'connector_limit': connector_limit,
            'per_host_limit': per_host_limit,
            'timeout_total': timeout_total,
            'headers': headers or {},
        }
        current = self._config

        if requested['connector_limit'] > current['connector_limit']:
            return True
        if requested['per_host_limit'] > current['per_host_limit']:
            return True
        if requested['timeout_total'] > current['timeout_total']:
            return True

        for key, value in requested['headers'].items():
            if current['headers'].get(key) != value:
                return True
        return False

    async def _cleanup_old(self) -> None:
        """Закрывает старые сессии и коннекторы."""
        lock = self._get_lock()
        async with lock:
            # Закрываем все активные сессии
            for session in self._active_sessions:
                if not session.closed:
                    await session.close()
                    logger.debug("Closed old ClientSession")
            self._active_sessions.clear()
            
            # Закрываем текущий коннектор
            if self._connector and not self._connector.closed:
                await self._connector.close()
                logger.debug("Closed old TCPConnector")
            
            self._session = None
            self._connector = None
            self._config = None

    async def get_session(
        self,
        connector_limit: int = 500,
        per_host_limit: int = 100,
        timeout_total: float = 60.0,
        headers: Optional[dict] = None,
    ) -> aiohttp.ClientSession:
        """
        Возвращает сессию из пула или создаёт новую.
        Автоматически очищает старые сессии при необходимости.
        """
        lock = self._get_lock()
        async with lock:
            if self._needs_recreate(connector_limit, per_host_limit, timeout_total, headers):
                await self._cleanup_old()

                default_headers = {
                    'User-Agent': 'Proxy-Hunter/2.1',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection': 'keep-alive',
                }
                if headers:
                    default_headers.update(headers)

                self._connector = aiohttp.TCPConnector(
                    limit=connector_limit,
                    limit_per_host=per_host_limit,
                    ttl_dns_cache=300,
                    enable_cleanup_closed=True,
                    force_close=False,
                    keepalive_timeout=30,
                )
                timeout = aiohttp.ClientTimeout(total=timeout_total)
                self._session = aiohttp.ClientSession(
                    connector=self._connector,
                    timeout=timeout,
                    headers=default_headers,
                )
                self._active_sessions.append(self._session)
                self._config = {
                    'connector_limit': connector_limit,
                    'per_host_limit': per_host_limit,
                    'timeout_total': timeout_total,
                    'headers': default_headers,
                }
                logger.info(
                    "Created shared ClientSession with limit=%s, per_host_limit=%s",
                    connector_limit,
                    per_host_limit,
                )
            return self._session

    async def close_all(self) -> None:
        """Закрывает все активные сессии и коннекторы."""
        lock = self._get_lock()
        async with lock:
            await self._cleanup_old()
            logger.info("Closed all ClientSession and TCPConnector instances")

    async def close(self) -> None:
        """Закрывает текущую сессию и коннектор."""
        lock = self._get_lock()
        async with lock:
            if self._session and not self._session.closed:
                await self._session.close()
                self._session = None
                logger.debug("Closed current ClientSession")
            if self._connector and not self._connector.closed:
                await self._connector.close()
                self._connector = None
                logger.debug("Closed current TCPConnector")

    def reset(self) -> None:
        """Сбрасывает состояние пула (используется для тестов)."""
        self._session = None
        self._connector = None
        self._lock = None
        self._config = None
        self._active_sessions.clear()
