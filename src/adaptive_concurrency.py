"""
Адаптивный контроль параллелизма для асинхронных запросов.
Регулирует количество одновременных задач на основе времени ответа и успешности.
"""

import asyncio
import logging
import time
from typing import Optional

logger = logging.getLogger(__name__)


class AdaptiveConcurrency:
    """
    Динамически изменяет параллелизм в пределах [min_concurrent, max_concurrent].
    Увеличивает при высокой успешности и низкой задержке, уменьшает при ошибках или таймаутах.
    """

    def __init__(self, min_concurrent: int = 20, max_concurrent: int = 100, initial: int = 50):
        self.min_concurrent = min_concurrent
        self.max_concurrent = max_concurrent
        self.current = min(max(initial, min_concurrent), max_concurrent)
        self._semaphore = asyncio.Semaphore(self.current)
        self._lock = asyncio.Lock()
        self._stats = {
            'success': 0,
            'fail': 0,
            'total_time': 0.0,
            'count': 0,
            'last_adjust': time.time()
        }
        self._adjust_interval = 5.0  # секунд

    async def acquire(self):
        """Захватывает слот, обновляя семафор с текущим лимитом."""
        # Периодически пересоздаём семафор при изменении лимита
        async with self._lock:
            if self._semaphore._value != self.current:
                # Создаём новый семафор с новым лимитом
                self._semaphore = asyncio.Semaphore(self.current)
        await self._semaphore.acquire()

    def release(self):
        self._semaphore.release()

    def record(self, success: bool, response_time: float):
        """Записывает результат запроса для статистики."""
        self._stats['success'] += 1 if success else 0
        self._stats['fail'] += 0 if success else 1
        self._stats['total_time'] += response_time
        self._stats['count'] += 1

        # Периодическая корректировка
        now = time.time()
        if now - self._stats['last_adjust'] >= self._adjust_interval:
            self._adjust()
            self._stats['last_adjust'] = now

    def _adjust(self):
        """Вычисляет новый лимит на основе статистики."""
        total = self._stats['success'] + self._stats['fail']
        if total == 0:
            return

        success_rate = self._stats['success'] / total
        avg_time = self._stats['total_time'] / self._stats['count'] if self._stats['count'] > 0 else 0

        # Увеличиваем, если успешность > 90% и среднее время < 2с
        if success_rate > 0.9 and avg_time < 2.0:
            new_limit = min(self.max_concurrent, int(self.current * 1.05) + 1)
        # Уменьшаем, если успешность < 70% или время > 5с
        elif success_rate < 0.7 or avg_time > 5.0:
            new_limit = max(self.min_concurrent, int(self.current * 0.9) - 1)
        else:
            new_limit = self.current

        if new_limit != self.current:
            logger.debug(f"Adaptive concurrency adjusted: {self.current} -> {new_limit} "
                         f"(success_rate={success_rate:.2f}, avg_time={avg_time:.2f}s)")
            self.current = new_limit

        # Сбрасываем статистику для следующего интервала
        self._stats['success'] = 0
        self._stats['fail'] = 0
        self._stats['total_time'] = 0.0
        self._stats['count'] = 0

    async def __aenter__(self):
        await self.acquire()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.release()
