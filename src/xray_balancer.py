import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import json
import ipaddress
import logging
import socket
import asyncio
from typing import Dict, Optional

import config_parser as parser
import transport_builder

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ConfigToXray:
    def __init__(self, input_file: str, output_file: str):
        self.input_file = input_file
        self.output_file = output_file
        self.outbounds = []

    async def is_valid_address_async(self, address: str) -> bool:
        if not address:
            return False
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
            pass
        loop = asyncio.get_event_loop()
        try:
            result = await loop.run_in_executor(None, socket.getaddrinfo, address, 443)
            return bool(result)
        except:
            return False

    @staticmethod
    def get_xray_template() -> Dict:
        return {
            "log": {"loglevel": "warning"},
            "remarks": "👽 Anonymous Multi Balanced",
            "dns": {
                "servers": [
                    "https://dns.google/dns-query",
                    "https://cloudflare-dns.com/dns-query",
                    {
                        "address": "1.1.1.2",
                        "domains": ["domain:ir", "geosite:category-ir"],
                        "skipFallback": True,
                        "tag": "domestic-dns"
                    }
                ]
            },
            "fakedns": [{"ipPool": "198.18.0.0/15", "poolSize": 10000}],
            "inbounds": [
                {
                    "port": 10808,
                    "protocol": "socks",
                    "settings": {"auth": "noauth", "udp": True, "userLevel": 8},
                    "sniffing": {"destOverride": ["http", "tls", "fakedns"], "enabled": True, "routeOnly": False},
                    "tag": "socks"
                }
            ],
            "observatory": {
                "enableConcurrency": True,
                "probeInterval": "3m",
                "probeUrl": "https://www.gstatic.com/generate_204",
                "subjectSelector": ["proxy-"]
            },
            "outbounds": [],
            "policy": {
                "levels": {"8": {"connIdle": 300, "downlinkOnly": 1, "handshake": 4, "uplinkOnly": 1}},
                "system": {"statsOutboundUplink": True, "statsOutboundDownlink": True}
            },
            "routing": {
                "balancers": [
                    {"selector": ["proxy-"], "strategy": {"type": "leastPing"}, "tag": "proxy-round"}
                ],
                "domainStrategy": "AsIs",
                "rules": [
                    {"inboundTag": ["socks"], "outboundTag": "dns-out", "port": "53", "type": "field"},
                    {"ip": ["geoip:private"], "outboundTag": "direct", "type": "field"},
                    {"domain": ["geosite:private"], "outboundTag": "direct", "type": "field"},
                    {"domain": ["domain:ir", "geosite:category-ir"], "outboundTag": "direct", "type": "field"},
                    {"ip": ["geoip:ir"], "outboundTag": "direct", "type": "field"},
                    {"inboundTag": ["domestic-dns"], "outboundTag": "direct", "type": "field"},
                    {"balancerTag": "proxy-round", "network": "tcp,udp", "type": "field"}
                ]
            }
        }

    def convert_vmess(self, data: Dict) -> Optional[Dict]:
        if not data.get('add') or not data.get('port') or not data.get('id'):
            return None
        valid = asyncio.run(self.is_valid_address_async(data.get('add', '')))
        if not valid:
            logger.debug(f"Skipping VMess config: address '{data.get('add')}' invalid")
            return None
        outbound = {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": data.get('add'),
                    "port": int(data.get('port')),
                    "users": [{
                        "id": data.get('id'),
                        "alterId": int(data.get('aid', 0)),
                        "security": data.get('scy', 'auto'),
                        "level": 8
                    }]
                }]
            },
            "streamSettings": transport_builder.build_xray_settings(data)
        }
        return outbound

    def convert_vless(self, data: Dict) -> Optional[Dict]:
        if not data.get('address') or not data.get('port') or not data.get('uuid'):
            return None
        valid = asyncio.run(self.is_valid_address_async(data.get('address', '')))
        if not valid:
            logger.debug(f"Skipping VLESS config: address '{data.get('address')}' invalid")
            return None
        outbound = {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": data['address'],
                    "port": data['port'],
                    "users": [{
                        "id": data['uuid'],
                        "flow": data.get('flow', ''),
                        "encryption": "none",
                        "level": 8
                    }]
                }]
            },
            "streamSettings": transport_builder.build_xray_settings(data)
        }
        return outbound

    def convert_trojan(self, data: Dict) -> Optional[Dict]:
        if not data.get('address') or not data.get('port') or not data.get('password'):
            return None
        valid = asyncio.run(self.is_valid_address_async(data.get('address', '')))
        if not valid:
            logger.debug(f"Skipping Trojan config: address '{data.get('address')}' invalid")
            return None
        outbound = {
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": data['address'],
                    "port": data['port'],
                    "password": data['password'],
                    "level": 8
                }]
            },
            "streamSettings": transport_builder.build_xray_settings(data)
        }
        return outbound

    def convert_shadowsocks(self, data: Dict) -> Optional[Dict]:
        if not data.get('address') or not data.get('port') or not data.get('method') or not data.get('password'):
            return None
        valid = asyncio.run(self.is_valid_address_async(data.get('address', '')))
        if not valid:
            logger.debug(f"Skipping Shadowsocks config: address '{data.get('address')}' invalid")
            return None
        return {
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": data['address'],
                    "port": data['port'],
                    "method": data['method'],
                    "password": data['password'],
                    "level": 8
                }]
            },
            "streamSettings": {"network": "tcp"}
        }

    def process_configs(self):
        try:
            with open(self.input_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except FileNotFoundError:
            logger.error(f"{self.input_file} not found!")
            return
        except Exception as e:
            logger.error(f"Error reading {self.input_file}: {e}")
            return

        final_config = self.get_xray_template()
        temp_outbounds = []

        for line in lines:
            line = line.strip()
            if not line or line.startswith('//'):
                continue
            line_lower = line.lower()

            if line_lower.startswith(('hysteria2://', 'hy2://')):
                logger.warning(f"Hysteria2 config skipped: Xray does not support this protocol. Use sing-box instead.")
                continue

            outbound = None
            data = None

            try:
                if line_lower.startswith('vmess://'):
                    data = parser.decode_vmess(line)
                    if data:
                        outbound = self.convert_vmess(data)
                elif line_lower.startswith('vless://'):
                    data = parser.parse_vless(line)
                    if data:
                        outbound = self.convert_vless(data)
                elif line_lower.startswith('trojan://'):
                    data = parser.parse_trojan(line)
                    if data:
                        outbound = self.convert_trojan(data)
                elif line_lower.startswith('ss://'):
                    data = parser.parse_shadowsocks(line)
                    if data:
                        outbound = self.convert_shadowsocks(data)
            except Exception as e:
                logger.warning(f"Failed to parse config {line[:30]}...: {e}")

            if outbound:
                outbound["tag"] = f"proxy-{len(temp_outbounds) + 1}"
                temp_outbounds.append(outbound)

        if not temp_outbounds:
            logger.error("No valid configs found to convert.")
            return

        temp_outbounds.sort(key=lambda x: x.get('protocol', 'unknown'))

        temp_outbounds.extend([
            {"protocol": "freedom", "settings": {}, "tag": "direct"},
            {"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"},
            {"protocol": "dns", "tag": "dns-out"}
        ])

        final_config["outbounds"] = temp_outbounds

        try:
            os.makedirs(os.path.dirname(self.output_file) or '.', exist_ok=True)
            with open(self.output_file, 'w', encoding='utf-8') as f:
                json.dump(final_config, f, indent=2, ensure_ascii=False)
            logger.info(f"Successfully converted {len(temp_outbounds) - 3} configs to {self.output_file}")
        except Exception as e:
            logger.error(f"Failed to write output file: {e}")

def main():
    input_file = 'configs/proxy_configs.txt'
    output_file = 'configs/xray_loadbalanced_config.json'
    converter = ConfigToXray(input_file, output_file)
    converter.process_configs()

if __name__ == '__main__':
    main()
