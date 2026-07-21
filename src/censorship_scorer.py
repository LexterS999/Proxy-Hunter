"""
Оценка устойчивости прокси-конфигураций к цензуре.
Учитывает специфику ТСПУ (Россия), GFW (Китай), GFI (Иран).

НОВОЕ: добавлены REGION_TEST_DOMAINS для интеграции с region_tester.py.
НОВОЕ: score_parsed_config() теперь учитывает результаты регионального теста.
"""

import logging
import re
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class CensorshipRegion(Enum):
    RUSSIA = "RU"
    CHINA = "CN"
    IRAN = "IR"
    GENERIC = "GENERIC"


# =============================================================================
# Региональные тестовые домены (единый источник для всего проекта)
# =============================================================================
REGION_TEST_DOMAINS: Dict[str, Dict[str, object]] = {
    'RU': {
        'primary': 'rutracker.org',
        'fallback': ['linkedin.com', 'bbc.com', 'meduza.io', 'dw.com'],
        'whitelisted': ['gosuslugi.ru', 'yandex.ru', 'vk.com', 'mail.ru'],
        'description': 'Домены, заблокированные Роскомнадзором / ТСПУ',
    },
    'CN': {
        'primary': 'google.com',
        'fallback': ['youtube.com', 'twitter.com', 'facebook.com', 'wikipedia.org'],
        'whitelisted': ['baidu.com', 'qq.com', 'taobao.com', 'jd.com'],
        'description': 'Домены, заблокированные GFW (Great Firewall)',
    },
    'IR': {
        'primary': 'twitter.com',
        'fallback': ['telegram.org', 'youtube.com', 'instagram.com', 'facebook.com'],
        'whitelisted': ['aparat.com', 'digikala.com', 'snapp.ir', 'divar.ir'],
        'description': 'Домены, заблокированные GFI (Government Filtering Infrastructure)',
    },
    'GENERIC': {
        'primary': 'google.com',
        'fallback': ['cloudflare.com', 'github.com', 'wikipedia.org'],
        'whitelisted': ['example.com', 'iana.org'],
        'description': 'Базовая проверка доступности',
    },
}


# ASN в зоне риска для РФ (ТСПУ активно блокирует)
HIGH_RISK_ASN_RU: Set[str] = {
    'hetzner', 'digitalocean', 'ovh', 'linode', 'vultr',
    'contabo', 'scaleway', 'oracle', 'alibaba',
}

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

TRANSPORT_SAFETY: Dict[str, float] = {
    'ws_cdn': 0.90,
    'ws': 0.70,
    'grpc': 0.70,
    'tcp': 0.50,
    'kcp': 0.30,
    'http': 0.60,
    'quic': 0.45,
}

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
    pbk: str = ""
    # НОВОЕ: результат регионального теста
    region_test_passed: Optional[bool] = None
    region_test_latency_ms: float = -1.0


@dataclass
class CensorshipScore:
    total_score: float = 0.0
    protocol_stealth: float = 0.0
    transport_safety: float = 0.0
    server_risk: float = 0.0
    anti_probe_defense: float = 0.0
    sni_safety: float = 0.0
    region_test_bonus: float = 0.0
    region: str = "GENERIC"
    warnings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class CensorshipScorer:
    """Оценщик устойчивости к цензуре с учётом регионального теста."""

    def __init__(self, target_region: str = "RU"):
        self.target_region = target_region.upper()
        if self.target_region not in ('RU', 'CN', 'IR', 'GENERIC'):
            self.target_region = 'GENERIC'
        self._whitelist_compiled = [
            re.compile(p, re.IGNORECASE) for p in WHITELISTED_SNI_PATTERNS
        ]

    def score(self, profile: CensorshipProfile) -> CensorshipScore:
        """
        Композитный score цензурной устойчивости.

        Формула (с учётом регионального теста):
        total = protocol_stealth * 0.30
              + transport_safety * 0.15
              + server_risk * 0.15
              + anti_probe_defense * 0.15
              + sni_safety * 0.10
              + region_test_bonus * 0.15
        """
        result = CensorshipScore(region=self.target_region)

        result.protocol_stealth = self._score_protocol(profile)
        result.transport_safety = self._score_transport(profile)
        result.server_risk = self._score_server(profile)
        result.anti_probe_defense = self._score_anti_probe(profile)
        result.sni_safety = self._score_sni(profile)
        result.region_test_bonus = self._score_region_test(profile)

        result.total_score = round(
            result.protocol_stealth * 0.30
            + result.transport_safety * 0.15
            + result.server_risk * 0.15
            + result.anti_probe_defense * 0.15
            + result.sni_safety * 0.10
            + result.region_test_bonus * 0.15,
            2
        )

        self._generate_warnings(profile, result)
        return result

    def _score_region_test(self, profile: CensorshipProfile) -> float:
        """
        НОВОЕ: Бонус/штраф на основе результата регионального теста.
        Если прокси реально открыл заблокированный домен → максимальный бонус.
        """
        if profile.region_test_passed is None:
            return 50.0  # Нет данных — нейтрально

        if profile.region_test_passed:
            # Успех: бонус зависит от задержки
            if profile.region_test_latency_ms > 0:
                latency_bonus = max(0, 1.0 - profile.region_test_latency_ms / 5000.0)
                return round((0.8 + 0.2 * latency_bonus) * 100, 2)
            return 90.0
        else:
            return 10.0  # Провал: профиль не работает в регионе

    def _score_protocol(self, profile: CensorshipProfile) -> float:
        region_key = self.target_region
        stealth_map = PROTOCOL_STEALTH.get(region_key, PROTOCOL_STEALTH['GENERIC'])
        proto_key = self._get_protocol_key(profile)
        score = stealth_map.get(proto_key, 0.3)

        if profile.has_reality and proto_key == 'vless_reality':
            if not profile.pbk:
                score *= 0.5
            if not profile.reality_dest:
                score *= 0.7

        return round(score * 100, 2)

    def _score_transport(self, profile: CensorshipProfile) -> float:
        transport_key = self._get_transport_key(profile)
        base_score = TRANSPORT_SAFETY.get(transport_key, 0.4)

        if profile.behind_cdn and transport_key in ('ws', 'ws_cdn'):
            base_score = max(base_score, 0.90)
        if profile.behind_cdn and transport_key == 'grpc':
            base_score = max(base_score, 0.80)

        return round(base_score * 100, 2)

    def _score_server(self, profile: CensorshipProfile) -> float:
        asn_lower = profile.asn.lower() if profile.asn else ""
        if not asn_lower:
            return 50.0
        if asn_lower in HIGH_RISK_ASN_RU:
            if self.target_region == 'RU':
                return 20.0
            elif self.target_region == 'CN':
                return 40.0
            else:
                return 35.0
        if asn_lower in MEDIUM_RISK_ASN_RU:
            if self.target_region == 'RU':
                return 60.0
            else:
                return 70.0
        return 65.0

    def _score_anti_probe(self, profile: CensorshipProfile) -> float:
        score = 0.3
        if profile.has_fallback:
            score = 0.9
        if profile.has_reality and profile.reality_dest:
            score = max(score, 0.85)
        if profile.behind_cdn:
            score = max(score, 0.80)
        if profile.has_reality and not profile.reality_dest and not profile.has_fallback:
            score = min(score, 0.5)
        return round(score * 100, 2)

    def _score_sni(self, profile: CensorshipProfile) -> float:
        if not profile.sni:
            return 40.0
        for pattern in self._whitelist_compiled:
            if pattern.match(profile.sni):
                return 95.0
        if self._is_ip(profile.sni):
            return 20.0
        if '.' in profile.sni and len(profile.sni) > 5:
            return 70.0
        return 40.0

    def _generate_warnings(self, profile: CensorshipProfile, result: CensorshipScore) -> None:
        if result.protocol_stealth < 30:
            result.warnings.append(
                f"Протокол {profile.protocol} имеет высокую вероятность "
                f"детекции в {self.target_region}"
            )
            result.recommendations.append("Используйте VLESS+Reality или VLESS+TLS+WS+CDN")

        asn_lower = profile.asn.lower() if profile.asn else ""
        if asn_lower in HIGH_RISK_ASN_RU and self.target_region == 'RU':
            result.warnings.append(f"Сервер на ASN '{profile.asn}' — высокий риск блокировки ТСПУ")
            result.recommendations.append("Используйте серверы на AWS/GCP/Azure или за CDN")

        if result.transport_safety < 40:
            result.warnings.append(f"Транспорт '{profile.transport}' легко детектируется DPI")
            result.recommendations.append("Используйте WS через CDN или gRPC")

        if result.anti_probe_defense < 50:
            result.warnings.append("Нет защиты от active probing (ТСПУ/GFW)")
            result.recommendations.append("Добавьте fallback на веб-сервер или используйте Reality с dest")

        if result.sni_safety < 40:
            result.warnings.append(f"SNI '{profile.sni}' не из белого списка ТСПУ")
            result.recommendations.append("Используйте SNI из белого списка (microsoft.com, apple.com и т.д.)")

        if profile.has_reality and not profile.pbk:
            result.warnings.append("Reality без public key — невалидная конфигурация")

        if profile.protocol in ('hysteria2', 'hy2') and self.target_region == 'CN':
            result.warnings.append("Hysteria2 подвержен QUIC-throttling в Китае (68% bypass)")

        # НОВОЕ: предупреждение по результатам регионального теста
        if profile.region_test_passed is False:
            result.warnings.append(
                f"Региональный тест ПРОВАЛЕН: прокси не смог открыть "
                f"заблокированный домен в {self.target_region}"
            )

    def _get_protocol_key(self, profile: CensorshipProfile) -> str:
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
        return 'vless_tcp_tls'

    def _get_transport_key(self, profile: CensorshipProfile) -> str:
        transport = profile.transport.lower() if profile.transport else 'tcp'
        if transport in ('ws', 'websocket'):
            return 'ws_cdn' if profile.behind_cdn else 'ws'
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
        return 'tcp'

    @staticmethod
    def _is_ip(s: str) -> bool:
        parts = s.split('.')
        if len(parts) == 4:
            try:
                return all(0 <= int(p) <= 255 for p in parts)
            except ValueError:
                return False
        return ':' in s

    def score_parsed_config(
        self,
        parsed: Dict,
        region_test_passed: Optional[bool] = None,
        region_test_latency_ms: float = -1.0,
    ) -> CensorshipScore:
        """Оценивает parsed config dict напрямую, с учётом регионального теста."""
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
            region_test_passed=region_test_passed,
            region_test_latency_ms=region_test_latency_ms,
        )
        return self.score(profile)

    @staticmethod
    def _detect_cdn(parsed: Dict) -> bool:
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

        if server.startswith(('104.16.', '104.17.', '104.18.', '104.19.',
                              '104.20.', '104.21.', '104.22.', '104.23.',
                              '104.24.', '104.25.', '172.64.', '172.65.',
                              '172.66.', '172.67.')):
            return True
        return False

    @staticmethod
    def get_test_domain(region: str) -> str:
        """Возвращает тестовый домен для региона."""
        region = region.upper()
        info = REGION_TEST_DOMAINS.get(region, REGION_TEST_DOMAINS['GENERIC'])
        return info['primary']

    @staticmethod
    def get_fallback_domains(region: str) -> List[str]:
        """Возвращает fallback-домены для региона."""
        region = region.upper()
        info = REGION_TEST_DOMAINS.get(region, REGION_TEST_DOMAINS['GENERIC'])
        return list(info.get('fallback', []))

    @staticmethod
    def get_whitelisted_domains(region: str) -> List[str]:
        """Возвращает белые домены для региона."""
        region = region.upper()
        info = REGION_TEST_DOMAINS.get(region, REGION_TEST_DOMAINS['GENERIC'])
        return list(info.get('whitelisted', []))
