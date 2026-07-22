#!/usr/bin/env python3

"""
Модуль для определения, принадлежит ли IP-адрес дата-центру или частному VPS.
Использует базу MaxMind GeoLite2 ASN (если доступна) или встроенный список ASN.
"""

import os
import logging
import ipaddress
from typing import Optional

from user_settings import GEOLITE2_ASN_PATH, BUILTIN_DATACENTER_ASNS

logger = logging.getLogger(__name__)

# Глобальный кеш для ускорения
_cache = {}
_asn_reader = None
_loaded = False          # флаг, что мы уже пытались загрузить базу


def _load_asn_reader():
    """Загружает MaxMind ASN-ридер, если файл существует. Предупреждение только один раз."""
    global _asn_reader, _loaded
    if _loaded:
        return _asn_reader
    _loaded = True
    if os.path.exists(GEOLITE2_ASN_PATH):
        try:
            import maxminddb
            _asn_reader = maxminddb.open_database(GEOLITE2_ASN_PATH)
            logger.info(f"Загружена база ASN из {GEOLITE2_ASN_PATH}")
        except Exception as e:
            logger.warning(f"Не удалось загрузить MaxMind базу: {e}. Используется встроенный список.")
            _asn_reader = None
    else:
        logger.info(f"Файл {GEOLITE2_ASN_PATH} не найден. Используется встроенный список датацентров.")
    return _asn_reader


def get_asn(ip: str) -> Optional[str]:
    """
    Возвращает ASN для указанного IP (например, 'AS15169') или None.
    """
    reader = _load_asn_reader()
    if reader is not None:
        try:
            response = reader.get(ip)
            if response and 'autonomous_system_number' in response:
                return f"AS{response['autonomous_system_number']}"
        except Exception as e:
            logger.debug(f"Ошибка при запросе ASN для {ip}: {e}")
    return None


def is_datacenter_ip(ip: str) -> bool:
    """
    Определяет, является ли IP адресом дата-центра.
    Возвращает True, если IP принадлежит известному дата-центру.
    """
    if not ip:
        return False

    # Проверяем кеш
    if ip in _cache:
        return _cache[ip]

    asn = get_asn(ip)
    if asn is not None:
        is_dc = asn in BUILTIN_DATACENTER_ASNS
        _cache[ip] = is_dc
        return is_dc

    # Если ASN не определён, считаем, что это не дата-центр (частный VPS)
    _cache[ip] = False
    return False


def reload_cache():
    """Очищает кеш (полезно при обновлении базы)."""
    global _cache
    _cache.clear()
    logger.info("Кеш дата-центров очищен.")
