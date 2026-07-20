"""
config_validator.py - Валидация прокси-конфигов
"""

import re
import logging
from typing import Tuple, Optional

from config_identity import ConfigIdentity

logger = logging.getLogger(__name__)


class ConfigValidator:
    """Валидатор прокси-конфигов"""

    # Минимально допустимые значения
    MIN_PORT = 1
    MAX_PORT = 65535

    def validate(self, config: str) -> bool:
        """Проверяет, является ли конфиг валидным"""
        if not config or not isinstance(config, str):
            return False

        host, port = self._extract_host_port(config)
        if not host:
            return False
        if not (self.MIN_PORT <= port <= self.MAX_PORT):
            return False

        # Должен быть распознан протокол
        ep = ConfigIdentity.get_endpoint(config)
        return ep.is_valid

    @staticmethod
    def _extract_host_port(config: str) -> Tuple[str, int]:
        """
        [CHANGE] извлечение через единый ConfigIdentity; regex — fallback для битых URI.
        Ранее здесь была собственная независимая реализация.
        """
        ep = ConfigIdentity.get_endpoint(config)
        if ep.is_valid:
            return ep.host, ep.port

        # Fallback regex
        match = re.search(r'@([^:/\[\]]+):(\d+)', config)
        if match:
            try:
                return match.group(1), int(match.group(2))
            except (ValueError, TypeError):
                pass
        return '', 0

    def is_supported_protocol(self, config: str) -> bool:
        ep = ConfigIdentity.get_endpoint(config)
        return bool(ep.proto)
