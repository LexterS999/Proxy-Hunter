"""
Единый модуль для извлечения идентификатора прокси-конфигурации.
Возвращает (host, port, protocol, credential) для любого поддерживаемого протокола.
"""

import re
from typing import Optional, Tuple
from urllib.parse import urlparse, parse_qs

import xxhash

from config_parser import decode_vmess, parse_vless, parse_trojan, parse_shadowsocks
from parse_fallback import FallbackParser


class ConfigIdentity:
    """Статический класс для работы с идентификаторами конфигураций."""

    @staticmethod
    def get_endpoint(config: str) -> Optional[Tuple[str, int, str, str]]:
        """
        Возвращает (host, port, protocol, credential) или None.
        protocol: 'vmess', 'vless', 'trojan', 'ss', 'hysteria2', 'tuic' и т.п.
        credential: строка, уникальная для протокола (uuid, пароль и т.д.)
        """
        if not config:
            return None

        proto = config.split('://')[0].lower()
        if proto == 'vmess':
            data = decode_vmess(config)
            if data:
                host = data.get('add')
                port = data.get('port')
                cred = data.get('id')
                if host and port and cred:
                    return (host, int(port), 'vmess', cred)
        elif proto == 'vless':
            data = parse_vless(config)
            if data:
                host = data.get('address')
                port = data.get('port')
                cred = data.get('uuid')
                if host and port and cred:
                    return (host, int(port), 'vless', cred)
        elif proto == 'trojan':
            data = parse_trojan(config)
            if data:
                host = data.get('address')
                port = data.get('port')
                cred = data.get('password')
                if host and port and cred:
                    return (host, int(port), 'trojan', cred)
        elif proto == 'ss':
            data = parse_shadowsocks(config)
            if data:
                host = data.get('address')
                port = data.get('port')
                cred = f"{data.get('method', '')}:{data.get('password', '')}"
                if host and port and cred:
                    return (host, int(port), 'ss', cred)
        elif proto in ('hysteria2', 'hy2'):
            data = FallbackParser.parse_any(config)  # FallbackParser умеет парсить hysteria2
            if data:
                host = data.get('address')
                port = data.get('port')
                cred = data.get('password')
                if host and port and cred:
                    return (host, int(port), 'hysteria2', cred)
        elif proto == 'tuic':
            data = FallbackParser.parse_any(config)
            if data:
                host = data.get('address')
                port = data.get('port')
                cred = f"{data.get('uuid', '')}:{data.get('password', '')}"
                if host and port and cred:
                    return (host, int(port), 'tuic', cred)
        # fallback через urlparse
        try:
            parsed = urlparse(config)
            if parsed.hostname and parsed.port:
                host = parsed.hostname
                port = parsed.port
                # Определяем протокол
                proto = parsed.scheme.lower() if parsed.scheme else 'unknown'
                # Пытаемся извлечь credential из username/password или query
                cred = parsed.username or ''
                if parsed.password:
                    cred += f":{parsed.password}"
                if not cred:
                    params = parse_qs(parsed.query)
                    cred = params.get('uuid', [''])[0] or params.get('password', [''])[0] or params.get('id', [''])[0]
                if host and port:
                    return (host, int(port), proto, cred or '')
        except Exception:
            pass
        return None

    @staticmethod
    def get_key(config: str) -> str:
        """Генерирует детерминированный ключ для дедупликации."""
        endpoint = ConfigIdentity.get_endpoint(config)
        if endpoint:
            host, port, proto, cred = endpoint
            key_str = f"{host}:{port}:{proto}:{cred}"
        else:
            key_str = config
        return xxhash.xxh64(key_str.encode()).hexdigest()

    @staticmethod
    def get_server_key(config: str) -> Optional[str]:
        """Ключ для группировки по серверу: host:port:proto."""
        endpoint = ConfigIdentity.get_endpoint(config)
        if endpoint:
            host, port, proto, _ = endpoint
            return f"{host}:{port}:{proto}"
        return None

    @staticmethod
    def get_credential(config: str) -> Optional[str]:
        endpoint = ConfigIdentity.get_endpoint(config)
        return endpoint[3] if endpoint else None
