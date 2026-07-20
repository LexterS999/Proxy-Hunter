"""
Декоратор для единой обработки ошибок с логированием.
"""

import functools
import logging
import traceback
from typing import Callable, Optional, Type, Tuple, Any
import asyncio


def handle_errors(
    logger: Optional[logging.Logger] = None,
    context: str = "",
    retry: int = 0,
    retryable_exceptions: Tuple[Type[Exception], ...] = (Exception,),
    default_return: Any = None,
    reraise: bool = False
):
    """
    Декоратор для единой обработки ошибок в функциях.

    Args:
        logger: Логгер для записи ошибок
        context: Контекст ошибки (например, имя функции)
        retry: Количество повторных попыток
        retryable_exceptions: Исключения, при которых стоит повторять
        default_return: Значение по умолчанию при ошибке
        reraise: Пробрасывать ли исключение дальше
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            last_error = None
            for attempt in range(retry + 1):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    last_error = e
                    if not isinstance(e, retryable_exceptions) or attempt >= retry:
                        error_context = context or func.__name__
                        logger.error(
                            f"Error in {error_context}: {e}\n"
                            f"Args: {args[:2] if len(args) > 2 else args}\n"
                            f"Traceback: {traceback.format_exc()}"
                        )
                        if reraise:
                            raise
                        return default_return
                    wait = 0.5 * (2 ** attempt)
                    logger.warning(f"Retry {attempt+1}/{retry} in {wait:.2f}s for {func.__name__}: {e}")
                    await asyncio.sleep(wait)
            if reraise and last_error:
                raise last_error
            return default_return

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                error_context = context or func.__name__
                logger.error(
                    f"Error in {error_context}: {e}\n"
                    f"Args: {args[:2] if len(args) > 2 else args}\n"
                    f"Traceback: {traceback.format_exc()}"
                )
                if reraise:
                    raise
                return default_return

        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator
