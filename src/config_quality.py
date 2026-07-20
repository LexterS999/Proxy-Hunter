"""
config_quality.py - Оценка качества прокси-конфигов
"""

import re
import logging
from typing import Tuple

from config_identity import ConfigIdentity

logger = logging.getLogger(__name__)


class ConfigQuality:
    """Оценка качества конфигов"""

    @staticmethod
    def extract_server_info(config: str) -> Tuple[str, str]:
        """
        [CHANGE] извлечение через единый ConfigIdentity; regex — fallback.
        Ранее — собственная независимая реализация.
        """
        ep = ConfigIdentity.get_endpoint(config)
        if ep.is_valid:
            return ep.host, str(ep.port)

        # Fallback regex
        match = re.search(r'@([^:/\[\]]+):(\d+)', config)
        if match:
            return match.group(1), match.group(2)
        return '', ''

    @staticmethod
    def assess(config: str) -> float:
        """Быстрая оценка качества конфига (0..1) без сети."""
        ep = ConfigIdentity.get_endpoint(config)
        if not ep.is_valid:
            return 0.0

        score = 0.5
        # Наличие TLS/Reality повышает оценку
        if ep.security in ('tls', 'reality'):
            score += 0.2
        # Наличие credential
        if ep.cred:
            score += 0.2
        # Предпочтительные транспорты
        if ep.network in ('ws', 'grpc', 'httpupgrade', 'splithttp'):
            score += 0.1

        return round(max(0.0, min(1.0, score)), 3)
