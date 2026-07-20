"""
Модуль валидации для прокси-конфигураций.
Содержит проверки портов, протоколов и других параметров.
"""

from typing import Dict, List, Set, Optional

# Допустимые типы транспорта
VALID_TRANSPORT_TYPES = {
    'tcp', 'kcp', 'ws', 'http', 'h2', 'quic', 'grpc',
    'httpupgrade', 'splithttp', 'xhttp', 'raw'
}

# Допустимые порты для протоколов
PORT_RANGES = {
    'tcp': range(1, 65536),
    'udp': range(1, 65536),
    'wireguard': [51820, 51821, 51822] + list(range(1, 65536)),
    'quic': [443, 8443] + list(range(1, 65536)),
    'vmess': range(1, 65536),
    'vless': range(1, 65536),
    'trojan': range(1, 65536),
    'ss': range(1, 65536),
    'hysteria2': range(1, 65536),
    'tuic': range(1, 65536),
}


def validate_port_for_protocol(port: int, protocol: str) -> bool:
    """
    Проверяет, что порт допустим для данного протокола.

    Args:
        port: Номер порта для проверки
        protocol: Имя протокола ('vmess', 'vless', 'trojan', 'ss', ...)

    Returns:
        True если порт допустим, иначе False
    """
    if not isinstance(port, int) or port < 1 or port > 65535:
        return False
    valid_ranges = PORT_RANGES.get(protocol, range(1, 65536))
    if isinstance(valid_ranges, list):
        return port in valid_ranges
    return port in valid_ranges


def validate_port(port: int) -> bool:
    """Устаревшая функция, использует 'tcp' как протокол по умолчанию."""
    return validate_port_for_protocol(port, 'tcp')


def validate_protocol(protocol: str) -> bool:
    """
    Проверяет, поддерживается ли протокол.

    Args:
        protocol: Имя протокола (с '://' или без)

    Returns:
        True если протокол поддерживается, иначе False
    """
    if not protocol:
        return False
    clean = protocol.rstrip(':').rstrip('/').lower()
    # Проверяем без '://'
    for p in PORT_RANGES:
        if p == clean:
            return True
    # Проверяем с '://'
    if clean + '://' in PORT_RANGES:
        return True
    return False


def validate_transport_type(transport: str) -> bool:
    """Проверяет, является ли тип транспорта допустимым."""
    return transport in VALID_TRANSPORT_TYPES


def validate_ss_method(method: str) -> bool:
    """Проверяет, является ли метод шифрования Shadowsocks допустимым."""
    VALID_SS_METHODS = {
        'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm',
        'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305',
        '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm',
        'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb',
        'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr',
        'chacha20', 'chacha20-ietf', 'rc4-md5'
    }
    return method in VALID_SS_METHODS


def validate_vless_flow(flow: str) -> bool:
    """Проверяет, является ли VLESS flow допустимым."""
    VALID_FLOWS = {'', 'xtls-rprx-origin', 'xtls-rprx-direct', 'xtls-rprx-vision'}
    return flow in VALID_FLOWS


def validate_vless_security(security: str) -> bool:
    """Проверяет, является ли VLESS security допустимым."""
    VALID_SECURITY = {'none', 'tls', 'reality', 'xtls'}
    return security in VALID_SECURITY


def validate_uuid(uuid: str) -> bool:
    """Проверяет, является ли строка валидным UUID."""
    import re
    pattern = re.compile(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
        re.IGNORECASE
    )
    return bool(pattern.match(uuid))
