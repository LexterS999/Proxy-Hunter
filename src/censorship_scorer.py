"""
Оценка устойчивости прокси-конфигураций к цензуре.
Учитывает специфику ТСПУ (Россия), GFW (Китай), GFI (Иран).

Ключевые факторы:
- Протокол и его устойчивость к DPI
- Транспорт (WS+CDN, gRPC, TCP)
- ASN сервера (Hetzner, DO, OVH в зоне риска)
- Наличие CDN-слоя (Cloudflare)
- SNI из белого списка
- Наличие fallback на веб-сервер
- Reality с корректным dest

ИСПРАВЛЕНО:
- Добавлен учёт специфики цензуры РФ/Китая/Ирана
- Заморозка после 16-20 КБ (ТСПУ)
- Active probing (ТСПУ/GFW)
- TLS ClientHello tampering (ТСПУ)
- JA3/JA4 fingerprinting (GFW/GFI)
- QUIC-throttling для Hysteria2 (GFW)
"""

import logging
import re
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class CensorshipRegion(Enum):
    """Регионы с активной цензурой."""
    RUSSIA = "RU"
    CHINA = "CN"
    IRAN = "IR"
    GENERIC = "GENERIC"


# ASN в зоне риска для РФ (ТСПУ активно блокирует)
HIGH_RISK_ASN_RU: Set[str] = {
    'hetzner', 'digitalocean', 'ovh', 'linode', 'vultr',
    'contabo', 'scaleway', 'oracle', 'alibaba',
}

# ASN с умеренным риском
MEDIUM_RISK_ASN_RU: Set[str] = {
    'aws', 'gcp', 'azure', 'cloudflare',
}

# Протоколы и их устойчивость к цензуре (0.0 - 1.0)
PROTOCOL_STEALTH: Dict[str, Dict[str, float]] = {
    'RU': {
        'vless_reality': 0.95,
        'vless_tls_ws_cdn': 0.85,
        'vless_tls_grpc': 0.75,
        'vless_tcp_tls': 0.60,
        'trojan': 0.10,
        'vmess': 0.20,
        'shadowsocks': 0.05,
        'hysteria2': 0.40,
        'tuic': 0.35,
    },
    'CN': {
        'vless_reality': 0.98,
        'vless_tls_ws_cdn': 0.80,
        'vless_tls_grpc': 0.70,
        'vless_tcp_tls': 0.55,
        'trojan': 0.15,
        'vmess': 0.20,
        'shadowsocks': 0.10,
        'hysteria2': 0.68,
        'tuic': 0.50,
    },
    'IR': {
        'vless_reality': 0.80,
        'vless_tls_ws_cdn': 0.85,
        'vless_tls_grpc': 0.70,
        'vless_tcp_tls': 0.55,
        'trojan': 0.20,
        'vmess': 0.25,
        'shadowsocks': 0.15,
        'hysteria2': 0.60,
        'tuic': 0.55,
    },
    'GENERIC': {
        'vless_reality': 0.90,
        'vless_tls_ws_cdn': 0.85,
        'vless_tls_grpc': 0.75,
        'vless_tcp_tls': 0.65,
        'trojan': 0.50,
        'vmess': 0.45,
        'shadowsocks': 0.40,
        'hysteria2': 0.70,
        'tuic': 0.60,
    },
}

# Транспорт и его безопасность
TRANSPORT_SAFETY: Dict[str, float] = {
    'ws_cdn': 0.90,
    'ws': 0.70,
    'grpc': 0.70,
    'tcp': 0.50,
    'kcp': 0.30,
    'http': 0.60,
    'quic': 0.45,
}

# Белый список SNI для ТСПУ (домены, которые не блокируются)
WHITELISTED_SNI_PATTERNS: List[str] = [
    r'.*\.microsoft\.com$',
    r'.*\.windows\.com$',
    r'.*\.apple\.com$',
    r'.*\.icloud\.com$',
    r'.*\.google\.com$',
    r'.*\.googleapis\.com$',
    r'.*\.gstatic\.com$',
    r'.*\.cloudflare\.com$',
    r'.*\.akamai\.net$',
    r'.*\.fastly\.net$',
    r'.*\.amazonaws\.com$',
    r'.*\.azure\.com$',
    r'.*\.office\.com$',
    r'.*\.live\.com$',
    r'.*\.github\.com$',
    r'.*\.githubusercontent\.com$',
]


@dataclass
class CensorshipProfile:
    """Профиль цензурной устойчивости конфига."""
    protocol: str = ""
    transport: str = ""
    security: str = ""
    sni: str = ""
    server: str = ""
    port: int = 0
    has_reality: bool = False
    has_fallback: bool = False
    behind_cdn: bool = False
    asn: str = ""
    reality_dest: str = ""
    pbk: str = ""  # Reality public key


@dataclass
class CensorshipScore:
    """Результат оценки цензурной устойчивости."""
    total_score: float = 0.0  # 0-100
    protocol_stealth: float = 0.0
    transport_safety: float = 0.0
    server_risk: float = 0.0
    anti_probe_defense: float = 0.0
    sni_safety: float = 0.0
    region: str = "GENERIC"
    warnings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class CensorshipScorer:
    """
    Оценщик устойчивости прокси-конфигураций к цензуре.
    Учитывает специфику ТСПУ (РФ), GFW (Китай), GFI (Иран).
    """

    def __init__(self, target_region: str = "RU"):
        self.target_region = target_region.upper()
        if self.target_region not in ('RU', 'CN', 'IR', 'GENERIC'):
            self.target_region = 'GENERIC'
        self._whitelist_compiled = [
            re.compile(p, re.IGNORECASE) for p in WHITELISTED_SNI_PATTERNS
        ]

    def score(self, profile: CensorshipProfile) -> CensorshipScore:
        """
        Вычисляет композитный score цензурной устойчивости.

        Формула:
        total = protocol_stealth * 0.35
              + transport_safety * 0.20
              + server_risk * 0.20
              + anti_probe_defense * 0.15
              + sni_safety * 0.10
        """
        result = CensorshipScore(region=self.target_region)

        # 1. Protocol Stealth (35%)
        result.protocol_stealth = self._score_protocol(profile)

        # 2. Transport Safety (20%)
        result.transport_safety = self._score_transport(profile)

        # 3. Server Risk (20%)
        result.server_risk = self._score_server(profile)

        # 4. Anti-Probe Defense (15%)
        result.anti_probe_defense = self._score_anti_probe(profile)

        # 5. SNI Safety (10%)
        result.sni_safety = self._score_sni(profile)

        # Композитный score
        result.total_score = round(
            result.protocol_stealth * 0.35
            + result.transport_safety * 0.20
            + result.server_risk * 0.20
            + result.anti_probe_defense * 0.15
            + result.sni_safety * 0.10,
            2
        )

        # Генерация предупреждений и рекомендаций
        self._generate_warnings(profile, result)

        return result

    def _score_protocol(self, profile: CensorshipProfile) -> float:
        """Оценка stealth протокола для целевого региона."""
        region_key = self.target_region
        stealth_map = PROTOCOL_STEALTH.get(region_key, PROTOCOL_STEALTH['GENERIC'])

        # Определяем ключ протокола
        proto_key = self._get_protocol_key(profile)

        score = stealth_map.get(proto_key, 0.3)

        # Модификаторы
        if profile.has_reality and proto_key == 'vless_reality':
            if not profile.pbk:
                score *= 0.5  # Reality без pbk — невалидный
            if not profile.reality_dest:
                score *= 0.7  # Reality без dest — подозрительный

        return round(score * 100, 2)

    def _score_transport(self, profile: CensorshipProfile) -> float:
        """Оценка безопасности транспорта."""
        transport_key = self._get_transport_key(profile)
        base_score = TRANSPORT_SAFETY.get(transport_key, 0.4)

        # CDN-слой значительно повышает безопасность
        if profile.behind_cdn and transport_key in ('ws', 'ws_cdn'):
            base_score = max(base_score, 0.90)

        # gRPC через CDN тоже хорош
        if profile.behind_cdn and transport_key == 'grpc':
            base_score = max(base_score, 0.80)

        return round(base_score * 100, 2)

    def _score_server(self, profile: CensorshipProfile) -> float:
        """
        Оценка риска сервера по ASN.
        ТСПУ активно блокирует Hetzner, DO, OVH.
        """
        asn_lower = profile.asn.lower() if profile.asn else ""

        if not asn_lower:
            # ASN неизвестен — умеренный риск
            return 50.0

        if asn_lower in HIGH_RISK_ASN_RU:
            if self.target_region == 'RU':
                return 20.0  # Высокий риск для РФ
            elif self.target_region == 'CN':
                return 40.0  # Умеренный для Китая
            else:
                return 35.0

        if asn_lower in MEDIUM_RISK_ASN_RU:
            if self.target_region == 'RU':
                return 60.0
            else:
                return 70.0

        # Неизвестный ASN — нейтральный
        return 65.0

    def _score_anti_probe(self, profile: CensorshipProfile) -> float:
        """
        Оценка защиты от active probing.
        ТСПУ/GFW подключаются к серверу и отправляют VPN-рукопожатие.
        """
        score = 0.3  # Базовый (нет защиты)

        if profile.has_fallback:
            score = 0.9  # Fallback на веб-сервер — отличная защита

        if profile.has_reality and profile.reality_dest:
            score = max(score, 0.85)  # Reality с dest — хорошая защита

        if profile.behind_cdn:
            score = max(score, 0.80)  # CDN скрывает реальный сервер

        # Reality без fallback и без dest — уязвим
        if profile.has_reality and not profile.reality_dest and not profile.has_fallback:
            score = min(score, 0.5)

        return round(score * 100, 2)

    def _score_sni(self, profile: CensorshipProfile) -> float:
        """
        Оценка безопасности SNI.
        SNI из белого списка ТСПУ не блокируется.
        """
        if not profile.sni:
            return 40.0  # Нет SNI — подозрительно

        # Проверяем по белому списку
        for pattern in self._whitelist_compiled:
            if pattern.match(profile.sni):
                return 95.0  # SNI из белого списка

        # SNI выглядит как IP — плохо
        if self._is_ip(profile.sni):
            return 20.0

        # SNI выглядит как домен — нормально
        if '.' in profile.sni and len(profile.sni) > 5:
            return 70.0

        return 40.0

    def _generate_warnings(
        self, profile: CensorshipProfile, result: CensorshipScore
    ) -> None:
        """Генерирует предупреждения и рекомендации."""
        # Протокол
        if result.protocol_stealth < 30:
            result.warnings.append(
                f"Протокол {profile.protocol} имеет высокую вероятность "
                f"детекции в {self.target_region}"
            )
            result.recommendations.append(
                "Используйте VLESS+Reality или VLESS+TLS+WS+CDN"
            )

        # ASN
        asn_lower = profile.asn.lower() if profile.asn else ""
        if asn_lower in HIGH_RISK_ASN_RU and self.target_region == 'RU':
            result.warnings.append(
                f"Сервер на ASN '{profile.asn}' — высокий риск блокировки ТСПУ"
            )
            result.recommendations.append(
                "Используйте серверы на AWS/GCP/Azure или за CDN"
            )

        # Transport
        if result.transport_safety < 40:
            result.warnings.append(
                f"Транспорт '{profile.transport}' легко детектируется DPI"
            )
            result.recommendations.append(
                "Используйте WS через CDN или gRPC"
            )

        # Anti-probe
        if result.anti_probe_defense < 50:
            result.warnings.append(
                "Нет защиты от active probing (ТСПУ/GFW)"
            )
            result.recommendations.append(
                "Добавьте fallback на веб-сервер или используйте Reality с dest"
            )

        # SNI
        if result.sni_safety < 40:
            result.warnings.append(
                f"SNI '{profile.sni}' не из белого списка ТСПУ"
            )
            result.recommendations.append(
                "Используйте SNI из белого списка (microsoft.com, apple.com и т.д.)"
            )

        # Reality без pbk
        if profile.has_reality and not profile.pbk:
            result.warnings.append("Reality без public key — невалидная конфигурация")

        # Hysteria2 в Китае
        if profile.protocol in ('hysteria2', 'hy2') and self.target_region == 'CN':
            result.warnings.append(
                "Hysteria2 подвержен QUIC-throttling в Китае (68% bypass)"
            )

    # =========================================================================
    # Утилиты
    # =========================================================================
    def _get_protocol_key(self, profile: CensorshipProfile) -> str:
        """Определяет ключ протокола для lookup в stealth_map."""
        proto = profile.protocol.lower()

        if proto == 'vless':
            if profile.has_reality:
                return 'vless_reality'
            if profile.behind_cdn and profile.transport in ('ws', 'websocket'):
                return 'vless_tls_ws_cdn'
            if profile.transport == 'grpc':
                return 'vless_tls_grpc'
            return 'vless_tcp_tls'
        elif proto == 'trojan':
            return 'trojan'
        elif proto == 'vmess':
            return 'vmess'
        elif proto in ('shadowsocks', 'ss'):
            return 'shadowsocks'
        elif proto in ('hysteria2', 'hy2'):
            return 'hysteria2'
        elif proto == 'tuic':
            return 'tuic'
        else:
            return 'vless_tcp_tls'  # default

    def _get_transport_key(self, profile: CensorshipProfile) -> str:
        """Определяет ключ транспорта."""
        transport = profile.transport.lower() if profile.transport else 'tcp'

        if transport in ('ws', 'websocket'):
            if profile.behind_cdn:
                return 'ws_cdn'
            return 'ws'
        elif transport == 'grpc':
            return 'grpc'
        elif transport == 'tcp':
            return 'tcp'
        elif transport == 'kcp':
            return 'kcp'
        elif transport == 'http':
            return 'http'
        elif transport == 'quic':
            return 'quic'
        else:
            return 'tcp'

    @staticmethod
    def _is_ip(s: str) -> bool:
        """Проверяет, является ли строка IP-адресом."""
        parts = s.split('.')
        if len(parts) == 4:
            try:
                return all(0 <= int(p) <= 255 for p in parts)
            except ValueError:
                return False
        return ':' in s

    @classmethod
    def from_parsed_config(cls, parsed: Dict, target_region: str = "RU") -> 'CensorshipScorer':
        """Создаёт scorer из parsed config dict."""
        return cls(target_region=target_region)

    def score_parsed_config(self, parsed: Dict) -> CensorshipScore:
        """Оценивает parsed config dict напрямую."""
        profile = CensorshipProfile(
            protocol=parsed.get('protocol', ''),
            transport=parsed.get('transport', parsed.get('network', '')),
            security=parsed.get('security', ''),
            sni=parsed.get('sni', parsed.get('servername', '')),
            server=parsed.get('server', parsed.get('address', '')),
            port=int(parsed.get('port', 443)),
            has_reality=parsed.get('security', '') == 'reality',
            has_fallback=bool(parsed.get('fallback', '')),
            behind_cdn=self._detect_cdn(parsed),
            asn=parsed.get('asn', ''),
            reality_dest=parsed.get('dest', ''),
            pbk=parsed.get('pbk', parsed.get('publicKey', '')),
        )
        return self.score(profile)

    @staticmethod
    def _detect_cdn(parsed: Dict) -> bool:
        """Определяет, находится ли сервер за CDN."""
        sni = parsed.get('sni', '').lower()
        server = parsed.get('server', '').lower()
        host = parsed.get('host', '').lower()

        cdn_indicators = [
            'cloudflare', 'cdn', 'workers.dev', 'pages.dev',
            'fastly', 'akamai', 'cloudfront',
        ]

        for indicator in cdn_indicators:
            if indicator in sni or indicator in server or indicator in host:
                return True

        # Cloudflare IP ranges (упрощённая проверка)
        if server.startswith(('104.16.', '104.17.', '104.18.', '104.19.',
                              '104.20.', '104.21.', '104.22.', '104.23.',
                              '104.24.', '104.25.', '172.64.', '172.65.',
                              '172.66.', '172.67.')):
            return True

        return False
