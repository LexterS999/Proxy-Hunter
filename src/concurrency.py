"""
Управление параллелизмом с глобальным и по-хостовым ограничением.
Используется в active_checker.py для контроля числа одновременных проверок на один хост.
"""

import asyncio
from typing import Dict, Callable, Coroutine, Any, Optional
import logging

logger = logging.getLogger(__name__)


class ConcurrencyLimiter:
    """
    Ограничивает параллелизм глобально (общее число задач) и на каждый хост (число задач на IP/домен).
    """

    def __init__(self, global_limit: int = 20, per_host_limit: int = 4, max_hosts: int = 1000):
        self.global_sem = asyncio.Semaphore(global_limit)
        self.per_host_limit = per_host_limit
        self._host_sems: Dict[str, asyncio.Semaphore] = {}
        self._lock = asyncio.Lock()
        self._max_hosts = max_hosts

    async def _get_host_sem(self, host: str) -> asyncio.Semaphore:
        async with self._lock:
            if host not in self._host_sems:
                # Ограничиваем количество записей, чтобы избежать утечки памяти
                if len(self._host_sems) >= self._max_hosts:
                    # Удаляем случайный (LRU можно было бы, но для простоты удаляем первый)
                    oldest = next(iter(self._host_sems))
                    del self._host_sems[oldest]
                    logger.debug(f"Removed old semaphore for {oldest}")
                self._host_sems[host] = asyncio.Semaphore(self.per_host_limit)
                logger.debug(f"Created per-host semaphore for {host}")
            return self._host_sems[host]

    async def run(self, host: str, coro: Coroutine) -> Any:
        async with self.global_sem:
            host_sem = await self._get_host_sem(host)
            async with host_sem:
                return await coro

    def reset(self):
        """Сброс всех семафоров."""
        self._host_sems.clear()
        logger.debug("Per-host semaphores cleared")
