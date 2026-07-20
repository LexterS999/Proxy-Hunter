"""
config_identity.py - Единый модуль извлечения идентификатора прокси-конфига

Устраняет дублирование логики извлечения server/port/credential, которая ранее
была независимо реализована в config_parser.py, parse_fallback.py,
config_validator.py, active_checker.py, config_quality.py, deep_deduplicate.py
и pipeline_optimized.py.

Использование:
    from config_identity import ConfigIdentity
    ep = ConfigIdentity.get_endpoint(config)   # -> Endpoint(host, port, proto, cred, ...)
    key = ConfigIdentity.get_config_key(config)
    fp = ConfigIdentity.get_fingerprint(config)
"""

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from typing import Optional, Tuple
from urllib.parse import urlparse, parse_qs, unquote

try:
    import xxhash
    _HAS_XXHASH = True
except ImportError:
    _HAS_XXHASH = False


def _stable_hash(text: str) -> str:
    """Детерминированный хеш (не зависит от PYTHONHASHSEED)."""
    data = text.encode('utf-8', errors='ignore')
    if _HAS_XXHASH:
        return xxhash.xxh64(data).hexdigest()
    return hashlib.sha256(data).hexdigest()[:16]


def safe_b64decode(data: str) -> Optional[str]:
    """Безопасное base64-декодирование с нормализацией URL-safe алфавита."""
    if not data:
        return None
    try:
        s = data.strip().replace('-', '+').replace('_', '/')
        padding = 4 - len(s) % 4
        if padding != 4:
            s += '=' * padding
        return base64.b64decode(s).decode('utf-8', errors='ignore')
    except Exception:
        return None


@dataclass(frozen=True)
class Endpoint:
    """Неизменяемый идентификатор прокси-конфига."""
    host: str = ''
    port: int = 0
    proto: str = ''
    cred: str = ''          # id / uuid / password / method:password / privatekey
    network: str = ''       # tcp / ws / grpc / httpupgrade / splithttp
    security: str = ''      # tls / reality / none
    extra: Tuple[Tuple[str, str], ...] = ()   # доп. параметры для отпечатка

    @property
    def is_valid(self) -> bool:
        return bool(self.host and self.port and self.proto)

    def key(self) -> str:
        """Короткий ключ группировки (host:port:proto:cred)."""
        return f"{self.host}:{self.port}:{self.proto}:{self.cred}"

    def fingerprint(self) -> str:
        """Детерминированный отпечаток для дедупликации."""
        parts = [self.proto, self.host, str(self.port), self.cred,
                 self.network, self.security]
        parts.extend(f"{k}={v}" for k, v in self.extra)
        return _stable_hash('|'.join(parts))


class ConfigIdentity:
    """Единая точка извлечения идентификатора прокси-конфига."""

    _PROTO_PREFIXES = {
        'vmess://': 'vmess',
        'vless://': 'vless',
        'trojan://': 'trojan',
        'ss://': 'ss',
        'hysteria2://': 'hysteria2',
        'hy2://': 'hysteria2',
        'wireguard://': 'wireguard',
        'tuic://': 'tuic',
    }

    # Параметры, влияющие на уникальность отпечатка
    _EXTRA_KEYS = (
        'sni', 'host', 'path', 'type', 'headerType', 'serviceName', 'mode',
        'fp', 'pbk', 'sid', 'spx', 'flow', 'scy', 'alpn', 'encryption',
        'insecure', 'publickey', 'reserved', 'mtu', 'congestion_control',
        'udp_relay_mode', 'obfs', 'obfs-password', 'auth', 'password',
    )

    @classmethod
    def get_endpoint(cls, config: str) -> Endpoint:
        """Извлекает Endpoint из строки конфига любого поддерживаемого протокола."""
        if not config or not isinstance(config, str):
            return Endpoint()
        config = config.strip()
        lower = config.lower()
        for prefix, proto in cls._PROTO_PREFIXES.items():
            if lower.startswith(prefix):
                if proto == 'vmess':
                    return cls._parse_vmess(config)
                return cls._parse_uri(config, proto)
        return Endpoint()

    @classmethod
    def get_config_key(cls, config: str) -> str:
        """Ключ для дедупликации/группировки. Для нераспознанных — хеш сырой строки."""
        ep = cls.get_endpoint(config)
        if ep.is_valid:
            return ep.key()
        return 'raw:' + _stable_hash(config.strip())

    @classmethod
    def get_fingerprint(cls, config: str) -> str:
        """Детерминированный отпечаток конфига."""
        return cls.get_endpoint(config).fingerprint()

    # ------------------------------------------------------------------ #
    #  Внутренние парсеры
    # ------------------------------------------------------------------ #

    @classmethod
    def _parse_vmess(cls, config: str) -> Endpoint:
        try:
            decoded = safe_b64decode(config[8:].strip())
            if not decoded:
                return Endpoint()
            obj = json.loads(decoded)
            host = str(obj.get('add') or obj.get('host') or obj.get('server') or '')
            try:
                port = int(obj.get('port', 0) or 0)
            except (ValueError, TypeError):
                port = 0
            cred = str(obj.get('id', '') or '')
            network = str(obj.get('net', 'tcp') or 'tcp')
            security = str(obj.get('tls', '') or '')
            extra = []
            for k in cls._EXTRA_KEYS:
                v = obj.get(k)
                if v:
                    extra.append((k, str(v)))
            return Endpoint(host=host, port=port, proto='vmess', cred=cred,
                            network=network, security=security,
                            extra=tuple(sorted(extra)))
        except Exception:
            return Endpoint()

    @classmethod
    def _parse_uri(cls, config: str, proto: str) -> Endpoint:
        try:
            parsed = urlparse(config)
            host = parsed.hostname or ''
            port = parsed.port or 0

            # credential из userinfo (username[:password])
            cred = ''
            if parsed.username:
                cred = unquote(parsed.username)
                if parsed.password:
                    cred += ':' + unquote(parsed.password)

            params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

            # SS: credential может быть base64(method:password) в userinfo
            if proto == 'ss' and cred and ':' not in cred:
                decoded = safe_b64decode(cred)
                if decoded and ':' in decoded:
                    cred = decoded

            network = params.get('type', params.get('network', 'tcp'))
            security = params.get('security', '')

            extra = []
            for k in cls._EXTRA_KEYS:
                v = params.get(k)
                if v:
                    extra.append((k, str(v)))

            return Endpoint(host=host, port=port, proto=proto, cred=cred,
                            network=network, security=security,
                            extra=tuple(sorted(extra)))
        except Exception:
            return Endpoint()
