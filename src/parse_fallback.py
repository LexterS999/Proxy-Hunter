"""
parse_fallback.py - Резервный парсер для битых/нестандартных конфигов
"""

import re
import logging
from typing import Optional, Dict, Any

from config_identity import ConfigIdentity

logger = logging.getLogger(__name__)


class FallbackParser:
    """Резервный парсер, пытающийся восстановить битые конфиги"""

    def parse_broken_config(self, config: str) -> Optional[Dict[str, Any]]:
        """
        Пытается распарсить битый конфиг.
        [CHANGE] сначала использует единый ConfigIdentity; regex — только fallback.
        """
        if not config or not isinstance(config, str):
            return None

        config = config.strip()

        # 1. Пробуем штатный парсер идентичности
        ep = ConfigIdentity.get_endpoint(config)
        if ep.is_valid:
            return {
                'protocol': ep.proto,
                'address': ep.host,
                'port': ep.port,
                'credential': ep.cred,
                'network': ep.network,
                'security': ep.security,
                'fingerprint': ep.fingerprint(),
                'raw': config,
                'source': 'config_identity',
            }

        # 2. Fallback: regex-извлечение для битых URI
        host = self._extract_field(config, r'(?:@|\[)?([a-zA-Z0-9.\-]+):(\d+)')
        if not host:
            return None

        addr, port_s = host
        try:
            port = int(port_s)
        except (ValueError, TypeError):
            return None

        proto = self._guess_protocol(config)

        return {
            'protocol': proto,
            'address': addr,
            'port': port,
            'credential': self._extract_credential(config),
            'fingerprint': ConfigIdentity.get_fingerprint(config),
            'raw': config,
            'source': 'regex_fallback',
        }

    @staticmethod
    def _extract_field(config: str, pattern: str):
        match = re.search(pattern, config)
        if match and len(match.groups()) >= 2:
            return match.group(1), match.group(2)
        return None

    @staticmethod
    def _extract_credential(config: str) -> str:
        # uuid / password между :// и @
        match = re.search(r'://([^@/]+)@', config)
        if match:
            return match.group(1)
        return ''

    @staticmethod
    def _guess_protocol(config: str) -> str:
        lower = config.lower()
        for proto in ('vless', 'vmess', 'trojan', 'hysteria2', 'hy2',
                      'wireguard', 'tuic', 'ss'):
            if f'{proto}://' in lower:
                return 'shadowsocks' if proto == 'ss' else proto
        return 'unknown'
