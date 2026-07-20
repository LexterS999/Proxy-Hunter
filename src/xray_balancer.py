"""
xray_balancer.py - Генерация Xray-конфига с балансировкой и распределением нагрузки
"""

import json
import re
import ipaddress
import logging
from typing import List, Dict, Any
from collections import defaultdict

# [CHANGE] убран logging.basicConfig — логирование настраивается только в точке входа
logger = logging.getLogger(__name__)


class XrayBalancer:
    """Генератор Xray-конфига с балансировкой"""

    # [CHANGE] RFC 1123 hostname regex для валидации доменных адресов
    _HOSTNAME_RE = re.compile(
        r'^(?=.{1,253}$)'
        r'((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+'
        r'(?!-)[A-Za-z0-9-]{1,63}(?<!-)$'
    )

    def __init__(self):
        self.configs = []

    def generate_config(self, configs: List[Dict[str, Any]],
                        output_path: str = 'configs/xray_balanced.json') -> bool:
        """Генерирует Xray-конфиг с балансировкой"""
        try:
            logger.info(f"🔄 Генерация Xray-конфига для {len(configs)} прокси...")

            # Группируем по протоколам
            by_protocol = defaultdict(list)
            for config in configs:
                protocol = config.get('protocol', 'unknown')
                by_protocol[protocol].append(config)

            # Создаём outbounds
            outbounds = []
            balancer_tags = []

            for protocol, protocol_configs in by_protocol.items():
                if not protocol_configs:
                    continue

                # Сортируем по скору
                protocol_configs.sort(key=lambda x: x.get('score', 0), reverse=True)

                # Создаём outbound для каждого протокола
                outbound = self._create_protocol_outbound(protocol, protocol_configs)
                if outbound:
                    outbounds.append(outbound)
                    balancer_tags.append(outbound['tag'])

            if not outbounds:
                logger.warning("⚠️ Нет валидных конфигов для Xray")
                return False

            # Создаём основной конфиг
            xray_config = self._create_xray_config(outbounds, balancer_tags)

            # Сохраняем
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(xray_config, f, indent=2, ensure_ascii=False)

            logger.info(f"✅ Xray-конфиг сохранён: {output_path}")
            logger.info(f"   📊 Протоколы: {dict((k, len(v)) for k, v in by_protocol.items())}")
            return True

        except Exception as e:
            logger.error(f"❌ Ошибка генерации Xray-конфига: {e}")
            return False

    def _create_protocol_outbound(self, protocol: str, configs: List[Dict]) -> Dict:
        """Создаёт outbound для протокола"""
        try:
            if protocol == 'vmess':
                return self._create_vmess_outbound(configs)
            elif protocol == 'vless':
                return self._create_vless_outbound(configs)
            elif protocol == 'trojan':
                return self._create_trojan_outbound(configs)
            elif protocol == 'shadowsocks':
                return self._create_shadowsocks_outbound(configs)
            elif protocol == 'wireguard':
                return self._create_wireguard_outbound(configs)
            else:
                logger.warning(f"⚠️ Неподдерживаемый протокол: {protocol}")
                return {}
        except Exception as e:
            logger.error(f"❌ Ошибка создания outbound для {protocol}: {e}")
            return {}

    def _create_vmess_outbound(self, configs: List[Dict]) -> Dict:
        """Создаёт VMess outbound"""
        servers = []
        for i, config in enumerate(configs[:50]):  # Максимум 50 серверов
            server = self.convert_vmess_to_xray(config)
            if server:
                servers.append(server)

        if not servers:
            return {}

        return {
            "tag": "vmess-balancer",
            "protocol": "vmess",
            "settings": {
                "vnext": servers
            },
            "streamSettings": {
                "network": configs[0].get('network', 'tcp'),
                "security": configs[0].get('security', 'none'),
            },
            "balancerTag": "vmess-balancer"
        }

    def _create_vless_outbound(self, configs: List[Dict]) -> Dict:
        """Создаёт VLESS outbound"""
        servers = []
        for config in configs[:50]:
            server = self.convert_vless_to_xray(config)
            if server:
                servers.append(server)

        if not servers:
            return {}

        return {
            "tag": "vless-balancer",
            "protocol": "vless",
            "settings": {
                "vnext": servers
            },
            "streamSettings": {
                "network": configs[0].get('network', 'tcp'),
                "security": configs[0].get('security', 'none'),
            },
            "balancerTag": "vless-balancer"
        }

    def _create_trojan_outbound(self, configs: List[Dict]) -> Dict:
        """Создаёт Trojan outbound"""
        servers = []
        for config in configs[:50]:
            server = self.convert_trojan_to_xray(config)
            if server:
                servers.append(server)

        if not servers:
            return {}

        return {
            "tag": "trojan-balancer",
            "protocol": "trojan",
            "settings": {
                "servers": servers
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
            },
            "balancerTag": "trojan-balancer"
        }

    def _create_shadowsocks_outbound(self, configs: List[Dict]) -> Dict:
        """Создаёт Shadowsocks outbound"""
        servers = []
        for config in configs[:50]:
            server = self.convert_shadowsocks_to_xray(config)
            if server:
                servers.append(server)

        if not servers:
            return {}

        return {
            "tag": "shadowsocks-balancer",
            "protocol": "shadowsocks",
            "settings": {
                "servers": servers
            },
            "balancerTag": "shadowsocks-balancer"
        }

    def _create_wireguard_outbound(self, configs: List[Dict]) -> Dict:
        """Создаёт WireGuard outbound"""
        # WireGuard в Xray требует отдельной настройки
        # Пока пропускаем
        return {}

    def _create_xray_config(self, outbounds: List[Dict], balancer_tags: List[str]) -> Dict:
        """Создаёт основной Xray-конфиг"""
        return {
            "log": {
                "loglevel": "warning"
            },
            "inbounds": [
                {
                    "tag": "socks-in",
                    "port": 10808,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {
                        "auth": "noauth",
                        "udp": True,
                        "ip": "127.0.0.1"
                    },
                    "sniffing": {
                        "enabled": True,
                        "destOverride": ["http", "tls"]
                    }
                },
                {
                    "tag": "http-in",
                    "port": 10809,
                    "listen": "127.0.0.1",
                    "protocol": "http",
                    "settings": {
                        "timeout": 300
                    }
                }
            ],
            "outbounds": outbounds + [
                {
                    "tag": "direct",
                    "protocol": "freedom",
                    "settings": {}
                },
                {
                    "tag": "block",
                    "protocol": "blackhole",
                    "settings": {}
                }
            ],
            "routing": {
                "domainStrategy": "IPIfNonMatch",
                "rules": [
                    {
                        "type": "field",
                        "ip": ["geoip:private"],
                        "outboundTag": "direct"
                    },
                    {
                        "type": "field",
                        "domain": ["domain:ir", "geosite:category-ir"],
                        "outboundTag": "direct"
                    },
                    {
                        "type": "field",
                        "ip": ["geoip:ir"],
                        "outboundTag": "direct"
                    },
                    {
                        "type": "field",
                        "network": "tcp,udp",
                        "balancerTag": balancer_tags[0] if balancer_tags else None
                    }
                ],
                "balancers": [
                    {
                        "tag": tag,
                        "selector": [tag],
                        "strategy": {
                            "type": "leastPing"
                        }
                    } for tag in balancer_tags
                ]
            },
            "dns": {
                "servers": [
                    "8.8.8.8",
                    "1.1.1.1",
                    "localhost"
                ]
            }
        }

    # ------------------------------------------------------------------ #
    #  Конвертеры
    # ------------------------------------------------------------------ #

    @staticmethod
    def convert_vmess_to_xray(config: Dict) -> Dict:
        """Конвертирует VMess конфиг в Xray формат"""
        try:
            address = config.get('address', '')
            port = config.get('port', 0)
            uuid = config.get('uuid', '')

            if not XrayBalancer.is_valid_address(address) or not port or not uuid:
                return {}

            return {
                "address": address,
                "port": port,
                "users": [
                    {
                        "id": uuid,
                        "alterId": config.get('alter_id', 0),
                        "security": config.get('security', 'auto'),
                        "level": 8
                    }
                ]
            }
        except Exception:
            return {}

    @staticmethod
    def convert_vless_to_xray(config: Dict) -> Dict:
        """Конвертирует VLESS конфиг в Xray формат"""
        try:
            address = config.get('address', '')
            port = config.get('port', 0)
            uuid = config.get('uuid', '')

            if not XrayBalancer.is_valid_address(address) or not port or not uuid:
                return {}

            return {
                "address": address,
                "port": port,
                "users": [
                    {
                        "id": uuid,
                        "encryption": config.get('encryption', 'none'),
                        "flow": config.get('flow', ''),
                        "level": 8
                    }
                ]
            }
        except Exception:
            return {}

    @staticmethod
    def convert_trojan_to_xray(config: Dict) -> Dict:
        """Конвертирует Trojan конфиг в Xray формат"""
        try:
            address = config.get('address', '')
            port = config.get('port', 0)
            password = config.get('password', '')

            if not XrayBalancer.is_valid_address(address) or not port or not password:
                return {}

            return {
                "address": address,
                "port": port,
                "password": password,
                "level": 8
            }
        except Exception:
            return {}

    @staticmethod
    def convert_shadowsocks_to_xray(config: Dict) -> Dict:
        """Конвертирует Shadowsocks конфиг в Xray формат"""
        try:
            address = config.get('address', '')
            port = config.get('port', 0)
            password = config.get('password', '')
            method = config.get('method', 'aes-256-gcm')

            if not XrayBalancer.is_valid_address(address) or not port or not password:
                return {}

            return {
                "address": address,
                "port": port,
                "password": password,
                "method": method,
                "level": 8
            }
        except Exception:
            return {}

    @staticmethod
    def is_valid_address(address: str) -> bool:
        """
        [CHANGE] Валидирует адрес: IP (v4/v6, в т.ч. в скобках) ИЛИ домен (RFC 1123).
        Ранее принимались только IP, из-за чего отбрасывались все доменные прокси
        (Reality/CDN/WebSocket).
        """
        if not address or not isinstance(address, str):
            return False
        address = address.strip()
        if not address:
            return False

        # 1. Обычный IP-адрес (v4 / v6)
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
            pass

        # 2. IPv6 в квадратных скобках: [::1]
        if address.startswith('[') and address.endswith(']'):
            try:
                ipaddress.ip_address(address[1:-1])
                return True
