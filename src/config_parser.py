"""
Модуль парсинга прокси-конфигураций с поддержкой fallback-стратегий.
Использует паттерн «Стратегия» с динамической регистрацией парсеров.
"""

import json
import base64
import re
import logging
from typing import Dict, Optional, Tuple, Any, List, Callable
from urllib.parse import urlparse, parse_qs, unquote
import binascii
from functools import lru_cache

from validators import validate_port_for_protocol, validate_protocol, VALID_TRANSPORT_TYPES
from parse_fallback import FallbackParser

logger = logging.getLogger(__name__)

# Реестр парсеров протоколов
_PARSER_REGISTRY: Dict[str, Dict[str, Any]] = {}
_METHODS_REGISTRY: Dict[str, str] = {}


def register_parser(protocol: str, method: str = 'strict'):
    """Декоратор для регистрации парсера протокола."""
    def decorator(func: Callable):
        _PARSER_REGISTRY[protocol] = {'func': func, 'method': method}
        _METHODS_REGISTRY[protocol] = method
        return func
    return decorator


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
    try:
        s_original = s.replace('-', '+').replace('_', '/')
        decoded = base64.b64decode(s_original)
        return decoded.decode('utf-8', errors='ignore')
    except (binascii.Error, UnicodeDecodeError, ValueError) as e:
        logger.debug(f"Base64 decode error (fallback): {e}")
        return None


def safe_json_loads(text: str) -> Optional[Dict]:
    try:
        return json.loads(text, strict=False, parse_constant=lambda x: None)
    except json.JSONDecodeError:
        cleaned = re.sub(r'\bNaN\b', 'null', text)
        cleaned = re.sub(r'\bInfinity\b', 'null', cleaned)
        try:
            return json.loads(cleaned)
        except:
            return None


# === Зарегистрированные парсеры ===

@register_parser('vmess://', 'strict')
def decode_vmess(config: str) -> Optional[Dict]:
    """Декодирует VMess-конфигурацию с fallback-стратегией."""
    if not config or not isinstance(config, str) or not config.startswith('vmess://'):
        return None

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
            if not validate_port_for_protocol(port, 'vmess'):
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

    return FallbackParser.parse_vmess_fallback(config)


@register_parser('vless://', 'strict')
def parse_vless(config: str) -> Optional[Dict]:
    """Парсит VLESS-конфигурацию с fallback-стратегией."""
    if not config or not isinstance(config, str) or not config.startswith('vless://'):
        return None

    try:
        url = urlparse(config)
        if not url.hostname or not url.username:
            return FallbackParser.parse_vless_fallback(config)

        port = url.port or 443
        if not validate_port_for_protocol(port, 'vless'):
            logger.debug(f"VLESS invalid port: {port}")
            return FallbackParser.parse_vless_fallback(config)

        params = parse_qs(url.query)
        security = params.get('security', ['none'])[0].lower()
        if security not in ('none', 'tls', 'reality', 'xtls'):
            security = 'none'

        flow = params.get('flow', [''])[0].lower()
        valid_flows = {'', 'xtls-rprx-origin', 'xtls-rprx-direct', 'xtls-rprx-vision'}
        if flow and flow not in valid_flows:
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


@register_parser('trojan://', 'strict')
def parse_trojan(config: str) -> Optional[Dict]:
    """Парсит Trojan-конфигурацию с fallback-стратегией."""
    if not config or not isinstance(config, str) or not config.startswith('trojan://'):
        return None

    try:
        url = urlparse(config)
        if not url.hostname or not url.username:
            return FallbackParser.parse_trojan_fallback(config)

        port = url.port or 443
        if not validate_port_for_protocol(port, 'trojan'):
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


@register_parser('ss://', 'strict')
def parse_shadowsocks(config: str) -> Optional[Dict]:
    """Парсит Shadowsocks-конфигурацию с fallback-стратегией."""
    if not config or not isinstance(config, str) or not config.startswith('ss://'):
        return None

    VALID_SS_METHODS = {
        'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm',
        'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305',
        '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm',
        'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb',
        'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr',
        'chacha20', 'chacha20-ietf', 'rc4-md5'
    }

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
                if not validate_port_for_protocol(port, 'ss'):
                    logger.debug(f"SS invalid port: {port}")
                    return FallbackParser.parse_ss_fallback(config)
            except ValueError as e:
                logger.debug(f"SS port conversion error: {e}")
                return FallbackParser.parse_ss_fallback(config)

            credential_decoded = unquote(credential_part)

            if safe_b64decode(credential_decoded) is not None:
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
                if not validate_port_for_protocol(port, 'ss'):
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


# Функция для получения парсера по протоколу
def get_parser(protocol: str) -> Optional[Callable]:
    """Возвращает зарегистрированный парсер для протокола."""
    return _PARSER_REGISTRY.get(protocol, {}).get('func')


def get_parser_method(protocol: str) -> str:
    """Возвращает метод парсинга для протокола."""
    return _METHODS_REGISTRY.get(protocol, 'unknown')


def parse_with_fallback(config: str) -> Tuple[Optional[Dict], str]:
    """Парсит конфигурацию с автоматическим определением протокола."""
    protocol = None
    for p in _PARSER_REGISTRY:
        if config.startswith(p):
            protocol = p
            break

    if protocol:
        parser = get_parser(protocol)
        if parser:
            try:
                data = parser(config)
                if data:
                    return data, get_parser_method(protocol)
            except Exception:
                pass

    return FallbackParser.parse_any(config), 'fallback'


# Экспортируем функции для обратной совместимости
def parse_hysteria2(config: str) -> Optional[Dict]:
    """Парсит Hysteria2-конфигурацию (заглушка для обратной совместимости)."""
    return FallbackParser.parse_any(config)
