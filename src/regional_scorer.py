"""
Модуль регионального скоринга.
Добавляет бонусы/штрафы на основе региона, протокола, порта, SNI и техник обхода.
"""

import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)

class RegionalScorer:
    # Региональные бонусы для разных стран
    REGIONAL_BONUS = {
        'RU': {
            'protocols': {'vless': 1.2, 'vmess': 1.1, 'trojan': 1.0, 'ss': 0.9},
            'ports': {443: 1.3, 8443: 1.2, 2053: 1.1, 2083: 1.0, 2096: 1.0, 8880: 1.0},
            'sni': {
                'cloudflare.com': 1.3,
                'dl.google.com': 1.2,
                'www.google.com': 1.0,
                'youtube.com': 0.8,  # часто блокируется
                'www.youtube.com': 0.8,
                'google.com': 1.0,
                'www.cloudflare.com': 1.3,
            },
            'reality_bonus': 1.4,
            'tls_fragmentation_bonus': 1.1,
            'http2_bonus': 1.1,
        },
        'IR': {
            'protocols': {'vless': 1.3, 'vmess': 1.2, 'trojan': 1.1, 'ss': 0.8},
            'ports': {443: 1.2, 8443: 1.3, 2053: 1.1, 2083: 1.0, 2096: 1.0, 8880: 1.0},
            'sni': {
                'cloudflare.com': 1.4,
                'www.cloudflare.com': 1.3,
                'dl.google.com': 1.1,
                'www.google.com': 0.9,
                'google.com': 0.9,
                'youtube.com': 0.7,
                'www.youtube.com': 0.7,
            },
            'reality_bonus': 1.3,
            'tls_fragmentation_bonus': 1.2,
            'http2_bonus': 1.0,
        }
    }

    # Штрафы за "плохие" SNI (регионы, где они часто блокируются)
    SNI_PENALTY = {
        'RU': {
            'google.com': 0.8,
            'youtube.com': 0.7,
            'www.youtube.com': 0.7,
        },
        'IR': {
            'google.com': 0.7,
            'youtube.com': 0.6,
            'www.youtube.com': 0.6,
            'dl.google.com': 0.8,
        }
    }

    def __init__(self, region: str = 'RU'):
        self.region = region.upper()
        if self.region not in self.REGIONAL_BONUS:
            logger.warning(f"Unknown region {self.region}, using default (RU)")
            self.region = 'RU'

    def get_protocol_bonus(self, protocol: str) -> float:
        return self.REGIONAL_BONUS[self.region]['protocols'].get(protocol, 1.0)

    def get_port_bonus(self, port: int) -> float:
        return self.REGIONAL_BONUS[self.region]['ports'].get(port, 1.0)

    def get_sni_bonus(self, sni: str) -> float:
        if not sni:
            return 1.0
        # Проверяем точное совпадение, потом частичное
        for key, val in self.REGIONAL_BONUS[self.region]['sni'].items():
            if sni == key or sni.endswith('.' + key):
                return val
        return 1.0

    def get_sni_penalty(self, sni: str) -> float:
        if not sni:
            return 1.0
        for key, val in self.SNI_PENALTY.get(self.region, {}).items():
            if sni == key or sni.endswith('.' + key):
                return val
        return 1.0

    def get_reality_bonus(self, parsed: Dict) -> float:
        if parsed.get('security') == 'reality':
            return self.REGIONAL_BONUS[self.region]['reality_bonus']
        return 1.0

    def get_tls_fragmentation_bonus(self, parsed: Dict) -> float:
        # Проверяем, использует ли конфиг TLS-фрагментацию (например, параметр fragment)
        if parsed.get('fragment') or parsed.get('frag'):
            return self.REGIONAL_BONUS[self.region]['tls_fragmentation_bonus']
        return 1.0

    def get_http2_bonus(self, parsed: Dict) -> float:
        # Проверяем ALPN: если есть h2
        alpn = parsed.get('alpn', '')
        if 'h2' in alpn or 'http/2' in alpn:
            return self.REGIONAL_BONUS[self.region]['http2_bonus']
        return 1.0

    def calculate_region_score(self, config: str, parsed: Dict, base_score: float = 50.0) -> float:
        """
        Вычисляет региональный множитель и применяет к базовому скору.
        """
        protocol = parsed.get('protocol') or config.split('://')[0].lower()
        port = int(parsed.get('port', 443))
        sni = parsed.get('sni', '')

        bonus = 1.0
        bonus *= self.get_protocol_bonus(protocol)
        bonus *= self.get_port_bonus(port)
        bonus *= self.get_sni_bonus(sni)
        bonus *= self.get_sni_penalty(sni)  # штраф
        bonus *= self.get_reality_bonus(parsed)
        bonus *= self.get_tls_fragmentation_bonus(parsed)
        bonus *= self.get_http2_bonus(parsed)

        # Ограничиваем бонус разумными пределами (0.5 - 2.0)
        bonus = max(0.5, min(2.0, bonus))
        return base_score * bonus
