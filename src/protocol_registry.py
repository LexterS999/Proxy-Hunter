"""
Единый реестр протоколов для парсинга, извлечения информации и дедупликации.
"""

import logging
from typing import Dict, Optional, Callable, Any, Tuple

import config_parser as parser
from parse_fallback import FallbackParser

logger = logging.getLogger(__name__)

# Тип функции парсинга: принимает строку, возвращает dict или None
ParseFunc = Callable[[str], Optional[Dict]]

# Тип функции извлечения серверной информации: принимает dict, возвращает (host, port, tls) или None
ServerInfoFunc = Callable[[Dict], Optional[Tuple[str, int, bool]]]

class ProtocolRegistry:
    def __init__(self):
        self._parsers: Dict[str, ParseFunc] = {}
        self._server_info_extractors: Dict[str, ServerInfoFunc] = {}
        self._protocol_names: Dict[str, str] = {}  # префикс -> имя

    def register(self, prefix: str, name: str, parser: ParseFunc, server_info_extractor: ServerInfoFunc):
        self._parsers[prefix] = parser
        self._server_info_extractors[prefix] = server_info_extractor
        self._protocol_names[prefix] = name

    def parse(self, config: str) -> Optional[Dict]:
        for prefix, parser_func in self._parsers.items():
            if config.startswith(prefix):
                return parser_func(config)
        return None

    def parse_with_fallback(self, config: str) -> Tuple[Optional[Dict], str]:
        return FallbackParser.parse_with_stats(config)

    def get_server_info(self, config: str) -> Optional[Tuple[str, int, bool]]:
        parsed = self.parse(config)
        if not parsed:
            return None
        for prefix, extractor in self._server_info_extractors.items():
            if config.startswith(prefix):
                return extractor(parsed)
        return None

    def get_protocol_prefix(self, config: str) -> Optional[str]:
        for prefix in self._parsers:
            if config.startswith(prefix):
                return prefix
        return None

# Создаём глобальный экземпляр реестра и регистрируем протоколы
registry = ProtocolRegistry()

# Функции извлечения серверной информации
def _extract_vmess(data: Dict) -> Optional[Tuple[str, int, bool]]:
    if data.get('add') and data.get('port'):
        tls = data.get('tls', '').lower() in ('tls', 'xtls', 'reality')
        return data['add'], int(data['port']), tls
    return None

def _extract_vless(data: Dict) -> Optional[Tuple[str, int, bool]]:
    if data.get('address') and data.get('port'):
        tls = data.get('security', '').lower() in ('tls', 'reality')
        return data['address'], int(data['port']), tls
    return None

def _extract_trojan(data: Dict) -> Optional[Tuple[str, int, bool]]:
    if data.get('address') and data.get('port'):
        tls = data.get('security', 'tls').lower() in ('tls', 'reality')
        return data['address'], int(data['port']), tls
    return None

def _extract_ss(data: Dict) -> Optional[Tuple[str, int, bool]]:
    if data.get('address') and data.get('port'):
        return data['address'], int(data['port']), False
    return None

def _extract_hysteria2(data: Dict) -> Optional[Tuple[str, int, bool]]:
    if data.get('address') and data.get('port'):
        tls = data.get('tls', '').lower() in ('tls', 'reality') or data.get('security', '') in ('tls', 'reality')
        return data['address'], int(data['port']), tls
    return None

def _extract_tuic(data: Dict) -> Optional[Tuple[str, int, bool]]:
    if data.get('address') and data.get('port'):
        return data['address'], int(data['port']), True
    return None

registry.register('vmess://', 'VMess', parser.decode_vmess, _extract_vmess)
registry.register('vless://', 'VLESS', parser.parse_vless, _extract_vless)
registry.register('trojan://', 'Trojan', parser.parse_trojan, _extract_trojan)
registry.register('ss://', 'Shadowsocks', parser.parse_shadowsocks, _extract_ss)
registry.register('hysteria2://', 'Hysteria2', parser.parse_hysteria2, _extract_hysteria2)
registry.register('hy2://', 'Hysteria2', parser.parse_hysteria2, _extract_hysteria2)  # алиас
registry.register('tuic://', 'TUIC', parser.parse_tuic, _extract_tuic)
