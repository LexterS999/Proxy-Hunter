"""
Модуль парсинга прокси-конфигураций с поддержкой fallback-стратегий.
Использует строгий парсинг через библиотечные функции и эвристический парсинг
как резервный вариант.
"""

import json
import base64
import re
import logging
import shutil
from typing import Dict, Optional, Tuple, Any
from urllib.parse import urlparse, parse_qs, unquote
import binascii
from functools import lru_cache

from parse_fallback import FallbackParser

logger = logging.getLogger(__name__)

VALID_SS_METHODS = {
    'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm',
    'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305',
    '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm',
    'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb',
    'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr',
    'chacha20', 'chacha20-ietf', 'rc4-md5'
}

VALID_VLESS_FLOWS = {'', 'xtls-rprx-origin', 'xtls-rprx-direct', 'xtls-rprx-vision'}
VALID_VLESS_SECURITY = {'none', 'tls', 'reality', 'xtls'}
VALID_TRANSPORT_TYPES = {'tcp', 'kcp', 'ws', 'http', 'h2', 'quic', 'grpc', 'httpupgrade', 'splithttp', 'xhttp', 'raw'}


def validate_port(port: int) -> bool:
    """Проверяет, что порт находится в допустимом диапазоне 1–65535."""
    return isinstance(port, int) and 1 <= port <= 65535


def is_base64(s: str) -> bool:
    if not s or len(s) < 4:
        return False
    try:
        s = s.rstrip('=')
        return bool(re.match(r'^[A-Za-z0-9+/\-_]+$', s)) and len(s) % 4 in (0, 2, 3)
    except Exception:
        return False


@lru_cache(maxsize=2048)
def safe_b64decode(s: str) -> Optional[str]:
    if not s:
        return None
    try:
        s = s.replace('-', '+').replace('_', '/')
        padding = '=' * (-len(s) % 4)
        decoded = base64.b64decode(s + padding, validate=True)
        return decoded.decode('utf-8', errors='strict')
    except (binascii.Error, UnicodeDecodeError, ValueError) as e:
        logger.debug(f"Base64 decode error (strict): {e}")
    # fallback
    try:
        s_original = s.replace('-', '+').replace('_', '/')
        decoded = base64.b64decode(s_original)
        return decoded.decode('utf-8', errors='ignore')
    except (binascii.Error, UnicodeDecodeError, ValueError) as e:
        logger.debug(f"Base64 decode error (fallback): {e}")
        return None


def safe_json_loads(text: str) -> Optional[Dict]:
    """Безопасный парсинг JSON с восстановлением повреждённых данных."""
    try:
        return json.loads(text, strict=False, parse_constant=lambda x: None)
    except json.JSONDecodeError:
        cleaned = re.sub(r'\bNaN\b', 'null', text)
        cleaned = re.sub(r'\bInfinity\b', 'null', cleaned)
        try:
            return json.loads(cleaned)
        except:
            return None


def decode_vmess(config: str) -> Optional[Dict]:
    """Декодирует VMess-конфигурацию с fallback-стратегией."""
    if not config or not isinstance(config, str) or not config.startswith('vmess://'):
        return None

    # Пробуем стандартный парсинг
    try:
        encoded = config[8:].strip()
        if not encoded:
            return None

        decoded = safe_b64decode(encoded)
        if not decoded:
            return None

        data = safe_json_loads(decoded)
        if not data:
            return None

        required_fields = ['add', 'port', 'id']
        if not all(field in data and data[field] for field in required_fields):
            return None

        try:
            port = int(data['port'])
            if not validate_port(port):
                logger.debug(f"VMess invalid port: {port}")
                return None
            data['port'] = port
        except (ValueError, TypeError) as e:
            logger.debug(f"VMess port conversion error: {e}")
            return None

        data['name'] = data.get('ps', data.get('name', ''))
        data['net'] = data.get('net', 'tcp').lower()
        data['tls'] = data.get('tls', 'none').lower()

        if data['net'] not in VALID_TRANSPORT_TYPES:
            data['net'] = 'tcp'

        return data
    except Exception as e:
        logger.debug(f"VMess standard parse failed: {e}")
    
    # Пробуем fallback-парсинг
    return FallbackParser.parse_vmess_fallback(config)


def parse_vless(config: str) -> Optional[Dict]:
    """Парсит VLESS-конфигурацию с fallback-стратегией."""
    if not config or not isinstance(config, str) or not config.startswith('vless://'):
        return None

    # Стандартный парсинг
    try:
        url = urlparse(config)
        if not url.hostname or not url.username:
            return FallbackParser.parse_vless_fallback(config)

        port = url.port or 443
        if not validate_port(port):
            logger.debug(f"VLESS invalid port: {port}")
            return FallbackParser.parse_vless_fallback(config)

        params = parse_qs(url.query)
        security = params.get('security', ['none'])[0].lower()
        if security not in VALID_VLESS_SECURITY:
            security = 'none'

        flow = params.get('flow', [''])[0].lower()
        if flow and flow not in VALID_VLESS_FLOWS:
            flow = ''

        transport_type = params.get('type', ['tcp'])[0].lower()
        if transport_type not in VALID_TRANSPORT_TYPES:
            transport_type = 'tcp'

        return {
            'uuid': url.username,
            'address': url.hostname,
            'port': port,
            'flow': flow,
            'sni': params.get('sni', [url.hostname])[0],
            'type': transport_type,
            'path': params.get('path', [''])[0],
            'host': params.get('host', [url.hostname])[0],
            'security': security,
            'alpn': params.get('alpn', [''])[0],
            'fp': params.get('fp', [''])[0],
            'pbk': params.get('pbk', [''])[0],
            'sid': params.get('sid', [''])[0],
            'spx': params.get('spx', [''])[0],
            'name': unquote(url.fragment) if url.fragment else ''
        }
    except Exception as e:
        logger.debug(f"VLESS standard parse failed: {e}")
    
    return FallbackParser.parse_vless_fallback(config)


def parse_trojan(config: str) -> Optional[Dict]:
    """Парсит Trojan-конфигурацию с fallback-стратегией."""
    if not config or not isinstance(config, str) or not config.startswith('trojan://'):
        return None

    try:
        url = urlparse(config)
        if not url.hostname or not url.username:
            return FallbackParser.parse_trojan_fallback(config)

        port = url.port or 443
        if not validate_port(port):
            logger.debug(f"Trojan invalid port: {port}")
            return FallbackParser.parse_trojan_fallback(config)

        params = parse_qs(url.query)
        transport_type = params.get('type', ['tcp'])[0].lower()
        if transport_type not in VALID_TRANSPORT_TYPES:
            transport_type = 'tcp'

        return {
            'password': url.username,
            'address': url.hostname,
            'port': port,
            'sni': params.get('sni', [url.hostname])[0],
            'alpn': params.get('alpn', [''])[0],
            'type': transport_type,
            'path': params.get('path', [''])[0],
            'host': params.get('host', [url.hostname])[0],
            'security': params.get('security', ['tls'])[0],
            'fp': params.get('fp', [''])[0],
            'flow': params.get('flow', [''])[0],
            'name': unquote(url.fragment) if url.fragment else ''
        }
    except Exception as e:
        logger.debug(f"Trojan standard parse failed: {e}")
    
    return FallbackParser.parse_trojan_fallback(config)


def parse_hysteria2(config: str) -> Optional[Dict]:
    """Парсит Hysteria2-конфигурацию."""
    if not config or not isinstance(config, str) or not config.startswith(('hysteria2://', 'hy2://')):
        return None

    try:
        url = urlparse(config)
        if not url.hostname:
            return None

        port = url.port or 443
        if not validate_port(port):
            logger.debug(f"Hysteria2 invalid port: {port}")
            return None

        params = parse_qs(url.query)
        password = url.username or params.get('password', [''])[0]
        if not password:
            return None

        return {
            'address': url.hostname,
            'port': port,
            'password': password,
            'sni': params.get('sni', [url.hostname])[0],
            'obfs': params.get('obfs', [''])[0],
            'obfs-password': params.get('obfs-password', [''])[0],
            'insecure': params.get('insecure', ['0'])[0],
            'pinSHA256': params.get('pinSHA256', [''])[0],
            'name': unquote(url.fragment) if url.fragment else ''
        }
    except Exception as e:
        logger.debug(f"Hysteria2 parse failed: {e}")
        return None


def parse_shadowsocks(config: str) -> Optional[Dict]:
    """Парсит Shadowsocks-конфигурацию с fallback-стратегией."""
    if not config or not isinstance(config, str) or not config.startswith('ss://'):
        return None

    try:
        fragment_index = config.find('#')
        if fragment_index != -1:
            url_part = config[:fragment_index]
            fragment = config[fragment_index+1:]
        else:
            url_part = config
            fragment = ''

        url_part = url_part[5:]

        if '@' in url_part:
            credential_part, server_part = url_part.split('@', 1)

            if ':' not in server_part:
                return FallbackParser.parse_ss_fallback(config)

            host, port_str = server_part.rsplit(':', 1)
            host = host.strip('[]')
            try:
                port = int(port_str)
                if not validate_port(port):
                    logger.debug(f"SS invalid port: {port}")
                    return FallbackParser.parse_ss_fallback(config)
            except ValueError as e:
                logger.debug(f"SS port conversion error: {e}")
                return FallbackParser.parse_ss_fallback(config)

            credential_decoded = unquote(credential_part)

            if is_base64(credential_decoded):
                method_pass = safe_b64decode(credential_decoded)
                if not method_pass or ':' not in method_pass:
                    return FallbackParser.parse_ss_fallback(config)
                method, password = method_pass.split(':', 1)
            else:
                if ':' not in credential_decoded:
                    return FallbackParser.parse_ss_fallback(config)
                method, password = credential_decoded.split(':', 1)
        else:
            full_decoded = safe_b64decode(url_part)
            if not full_decoded:
                return FallbackParser.parse_ss_fallback(config)

            if '@' not in full_decoded:
                return FallbackParser.parse_ss_fallback(config)

            credential_part, server_part = full_decoded.split('@', 1)

            if ':' not in server_part:
                return FallbackParser.parse_ss_fallback(config)

            host, port_str = server_part.rsplit(':', 1)
            host = host.strip('[]')
            try:
                port = int(port_str)
                if not validate_port(port):
                    logger.debug(f"SS invalid port: {port}")
                    return FallbackParser.parse_ss_fallback(config)
            except ValueError as e:
                logger.debug(f"SS port conversion error: {e}")
                return FallbackParser.parse_ss_fallback(config)

            if ':' not in credential_part:
                return FallbackParser.parse_ss_fallback(config)

            method, password = credential_part.split(':', 1)

        if not method or not password:
            return FallbackParser.parse_ss_fallback(config)

        method = method.lower().strip()
        if method not in VALID_SS_METHODS:
            return FallbackParser.parse_ss_fallback(config)

        return {
            'method': method,
            'password': password,
            'address': host,
            'port': port,
            'plugin': '',
            'name': unquote(fragment) if fragment else ''
        }
    except Exception as e:
        logger.debug(f"Shadowsocks parse failed: {e}")
        return FallbackParser.parse_ss_fallback(config)


def parse_wireguard(config: str) -> Optional[Dict]:
    """Парсит WireGuard-конфигурацию."""
    if not config or not isinstance(config, str) or not config.startswith('wireguard://'):
        return None

    try:
        url = urlparse(config)
        if not url.hostname:
            return None

        port = url.port or 51820
        if not validate_port(port):
            logger.debug(f"WireGuard invalid port: {port}")
            return None

        params = parse_qs(url.query)
        private_key = url.username or params.get('privatekey', [''])[0]
        if not private_key:
            return None

        return {
            'address': url.hostname,
            'port': port,
            'private_key': private_key,
            'public_key': params.get('publickey', [''])[0],
            'preshared_key': params.get('presharedkey', [''])[0],
            'reserved': params.get('reserved', [''])[0],
            'mtu': params.get('mtu', ['1420'])[0],
            'local_address': params.get('address', [''])[0],
            'peers': params.get('peer', []),
            'name': unquote(url.fragment) if url.fragment else ''
        }
    except Exception as e:
        logger.debug(f"WireGuard parse failed: {e}")
        return None


def parse_tuic(config: str) -> Optional[Dict]:
    """Парсит TUIC-конфигурацию."""
    if not config or not isinstance(config, str) or not config.startswith('tuic://'):
        return None

    try:
        url = urlparse(config)
        if not url.hostname:
            return None

        port = url.port or 443
        if not validate_port(port):
            logger.debug(f"TUIC invalid port: {port}")
            return None

        if not url.username or ':' not in url.username:
            return None

        try:
            uuid, password = url.username.split(':', 1)
        except ValueError as e:
            logger.debug(f"TUIC split error: {e}")
            return None

        params = parse_qs(url.query)

        return {
            'address': url.hostname,
            'port': port,
            'uuid': uuid,
            'password': password,
            'congestion_control': params.get('congestion_control', ['bbr'])[0],
            'udp_relay_mode': params.get('udp_relay_mode', ['native'])[0],
            'alpn': params.get('alpn', ['h3'])[0],
            'sni': params.get('sni', [url.hostname])[0],
            'allow_insecure': params.get('allow_insecure', ['0'])[0],
            'disable_sni': params.get('disable_sni', ['0'])[0],
            'name': unquote(url.fragment) if url.fragment else ''
        }
    except Exception as e:
        logger.debug(f"TUIC parse failed: {e}")
        return None


# Экспортируем функции для обратной совместимости
def parse_with_fallback(config: str) -> Tuple[Optional[Dict], str]:
    """Парсит конфигурацию с возвратом метода парсинга."""
    return FallbackParser.parse_with_stats(config)
