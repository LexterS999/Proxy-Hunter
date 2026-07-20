"""
session_pool.py - Пул aiohttp-сессий (синглтон)
"""

import asyncio
import logging
from typing import Optional

import aiohttp

logger = logging.getLogger(__name__)


class SessionPool:
    """
    Синглтон-пул aiohttp-сессий.

    [CHANGE] asyncio.Lock создаётся лениво при первом использовании (внутри
    event loop), а не на уровне класса при импорте — это избегает проблем в
    Python 3.10+, когда Lock, созданный вне loop, привязывается не к тому loop.

    [CHANGE] параметры connector_limit / per_host теперь учитываются: если
    запрошены большие лимиты, чем у текущей сессии, сессия пересоздаётся
    (ранее параметры молча игнорировались после первого создания).
    """

    _instance: Optional['SessionPool'] = None
    _session: Optional[aiohttp.ClientSession] = None
    _connector: Optional[aiohttp.TCPConnector] = None
    _lock: Optional[asyncio.Lock] = None
    _current_limit: int = 0
    _current_per_host: int = 0

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    @classmethod
    def _get_lock(cls) -> asyncio.Lock:
        """Ленивое создание Lock внутри текущего event loop."""
        if cls._lock is None:
            cls._lock = asyncio.Lock()
        return cls._lock

    @classmethod
    async def get_session(cls, connector_limit: int = 1000,
                          per_host: int = 200,
                          force_new: bool = False) -> aiohttp.ClientSession:
        """
        Возвращает (при необходимости создаёт) общую сессию.
        Если запрошены большие лимиты — пересоздаёт сессию.
        """
        lock = cls._get_lock()
        async with lock:
            need_recreate = (
                force_new
                or cls._session is None
                or cls._session.closed
                or connector_limit > cls._current_limit
                or per_host > cls._current_per_host
            )

            if need_recreate:
                # Закрываем старую сессию, если есть
                if cls._session is not None and not cls._session.closed:
                    try:
                        await cls._session.close()
                    except Exception:
                        pass

                cls._connector = aiohttp.TCPConnector(
                    limit=connector_limit,
                    limit_per_host=per_host,
                    ttl_dns_cache=300,
                    ssl=False,
                )
                cls._session = aiohttp.ClientSession(connector=cls._connector)
                cls._current_limit = connector_limit
                cls._current_per_host = per_host
                logger.debug(
                    f"🔌 Создана сессия: limit={connector_limit}, per_host={per_host}"
                )

            return cls._session

    @classmethod
    async def close(cls):
        """Закрывает сессию и коннектор."""
        lock = cls._get_lock()
        async with lock:
            if cls._session is not None and not cls._session.closed:
                try:
                    await cls._session.close()
                except Exception as e:
                    logger.debug(f"⚠️ close session: {e}")
            cls._session = None
            cls._connector = None
            cls._current_limit = 0
            cls._current_per_host = 0
