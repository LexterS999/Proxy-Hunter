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
    """
    if retryable_exceptions is None:
        retryable_exceptions = RETRYABLE_EXCEPTIONS

    # Включаем aiohttp.ClientError, если он доступен
    try:
        import aiohttp
        retryable_exceptions = retryable_exceptions + (aiohttp.ClientError,)
    except ImportError:
        pass

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            async def _attempt_loop():
                for attempt in range(attempts):
                    try:
                        return await func(*args, **kwargs)
                    except asyncio.CancelledError:
                        raise
                    except Exception as e:
                        if not isinstance(e, retryable_exceptions) or attempt == attempts - 1:
                            raise
                        delay = min(max_delay, base_delay * (2 ** attempt))
                        jittered = delay * (0.5 + random.random())
                        logger.debug(
                            f"Retry {func.__name__} attempt {attempt+1}/{attempts} "
                            f"after {jittered:.2f}s due to {e.__class__.__name__}"
                        )
                        await asyncio.sleep(jittered)
                raise TimeoutError(f"{func.__name__} failed after {attempts} attempts")
            return await asyncio.wait_for(_attempt_loop(), timeout=deadline)
        return wrapper
    return decorator
