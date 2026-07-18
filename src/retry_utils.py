"""
Утилиты для повторных попыток с экспоненциальной задержкой и джиттером.
Используется во всех асинхронных операциях ввода-вывода.
"""

import asyncio
import random
import logging
from functools import wraps
from typing import Callable, Any, Type, Tuple, Optional

logger = logging.getLogger(__name__)

# Базовые классы исключений, которые считаются временными (retryable)
RETRYABLE_EXCEPTIONS = (
    asyncio.TimeoutError,
    ConnectionError,
    OSError,
    # aiohttp.ClientError добавляется динамически, если aiohttp импортирован
)


def is_retryable(exc: Exception) -> bool:
    """Определяет, стоит ли повторять попытку при данной ошибке."""
    if isinstance(exc, RETRYABLE_EXCEPTIONS):
        return True
    try:
        import aiohttp
        if isinstance(exc, aiohttp.ClientError):
            return True
    except ImportError:
        pass
    return False


def retry_with_backoff(
    attempts: int = 5,
    base_delay: float = 0.2,
    max_delay: float = 5.0,
    retryable_exceptions: Optional[Tuple[Type[Exception], ...]] = None,
    deadline: float = 30.0
):
    """
    Декоратор для асинхронных функций с повторными попытками и экспоненциальной задержкой с джиттером.
    
    Аргументы:
        attempts: максимальное число попыток
        base_delay: базовая задержка (сек)
        max_delay: максимальная задержка (сек)
        retryable_exceptions: кортеж типов исключений, при которых повторяем (по умолчанию сетевые)
        deadline: общее время выполнения (сек) — если превышено, бросаем TimeoutError
    
    Использование:
        @retry_with_backoff(attempts=3, deadline=10.0)
        async def fetch_data(url):
            ...
    """
    if retryable_exceptions is None:
        retryable_exceptions = RETRYABLE_EXCEPTIONS

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Внутренняя функция, выполняющая попытки
            async def _attempt_loop():
                for attempt in range(attempts):
                    try:
                        return await func(*args, **kwargs)
                    except asyncio.CancelledError:
                        # Никогда не повторяем при отмене
                        raise
                    except Exception as e:
                        # Проверяем, является ли исключение retryable
                        if not isinstance(e, retryable_exceptions) or attempt == attempts - 1:
                            raise
                        # Рассчитываем задержку с джиттером (0.5x–1.5x от базовой)
                        delay = min(max_delay, base_delay * (2 ** attempt))
                        jittered = delay * (0.5 + random.random())
                        logger.debug(
                            f"Retry {func.__name__} attempt {attempt+1}/{attempts} "
                            f"after {jittered:.2f}s due to {e.__class__.__name__}"
                        )
                        await asyncio.sleep(jittered)
                # Если все попытки исчерпаны
                raise TimeoutError(f"{func.__name__} failed after {attempts} attempts")
            
            # Используем asyncio.wait_for для ограничения общего времени (совместимо с Python 3.10)
            return await asyncio.wait_for(_attempt_loop(), timeout=deadline)
        return wrapper
    return decorator
