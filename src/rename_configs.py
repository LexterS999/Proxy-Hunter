import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import json
import base64
import logging
import shutil
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse, parse_qs, unquote
import pycountry
import config_parser as parser
from profile_scorer import ProfileScorer
from geo_loader import GeoLoader
from user_settings import GEO_COUNTRY_URL, GEO_ASN_URL, NAMING_FORMAT, NAMING_SEPARATOR, SHOW_DC_TAG
from enrich_configs import load_location_cache_safe

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

COUNTRY_BLACKLIST = os.getenv('PROXY_HUNTER_COUNTRY_BLACKLIST', 'CN,RU,IR').split(',')

def is_country_allowed(country_code: str) -> bool:
    return country_code not in COUNTRY_BLACKLIST

class ConfigRenamer:
    def __init__(self, location_file: str):
        self.location_cache = {}
        self.scorer = ProfileScorer()
        self.geo = GeoLoader(GEO_COUNTRY_URL, GEO_ASN_URL)
        self.load_location_cache(location_file)

    def load_location_cache(self, location_file: str):
        self.location_cache = load_location_cache_safe(location_file)
        logger.info(f"Loaded {len(self.location_cache)} location entries")

    def get_location(self, address: str) -> tuple:
        if address in self.location_cache:
            return self.location_cache[address]
        self.geo.ensure_databases()
        country_code, country_name = self.geo.get_country(address)
        if country_code != 'XX':
            try:
                flag = ''.join(chr(0x1F1E6 + ord(c.upper()) - ord('A')) for c in country_code)
            except:
                flag = "🏳️"
            result = (flag, country_code)
        else:
            result = ("🏳️", "XX")
        self.location_cache[address] = result
        return result

    def get_asn_info(self, address: str) -> tuple:
        self.geo.ensure_databases()
        return self.geo.get_asn(address)

    def is_datacenter(self, address: str) -> bool:
        self.geo.ensure_databases()
        return self.geo.is_datacenter(address)

    def build_protocol_info(self, protocol_type: str, data: Dict) -> str:
        net = data.get('net') or data.get('type') or 'tcp'
        security = data.get('security') or data.get('tls') or 'none'
        net = net.upper()
        if security.lower() == 'reality':
            sec = 'REALITY'
        elif security.lower() in ('tls', 'xtls'):
            sec = 'TLS'
        else:
            sec = 'NONE'
        return f"{protocol_type}|{net}|{sec}"

    def rename_config(self, config: str, index: int) -> Optional[str]:
        try:
            config_lower = config.lower()
            parsed_data = None
            protocol = None
            address = None
            port = None

            if config_lower.startswith('vmess://'):
                data = parser.decode_vmess(config)
                if data:
                    parsed_data = data
                    protocol = 'VMess'
                    address = data.get('add')
                    port = data.get('port')
            elif config_lower.startswith('vless://'):
                data = parser.parse_vless(config)
                if data:
                    parsed_data = data
                    protocol = 'VLESS'
                    address = data.get('address')
                    port = data.get('port')
            elif config_lower.startswith('trojan://'):
                data = parser.parse_trojan(config)
                if data:
                    parsed_data = data
                    protocol = 'Trojan'
                    address = data.get('address')
                    port = data.get('port')
            elif config_lower.startswith('ss://'):
                data = parser.parse_shadowsocks(config)
                if data:
                    parsed_data = data
                    protocol = 'SS'
                    address = data.get('address')
                    port = data.get('port')
            else:
                return config

            if not parsed_data or not address:
                return config

            flag, country_code = self.get_location(address)

            if not is_country_allowed(country_code):
                logger.debug(f"Skipping config from {country_code} (blacklisted)")
                return None

            asn_num, asn_name = self.get_asn_info(address)
            asn_display = asn_name if asn_name else f"AS{asn_num}" if asn_num else ""

            is_dc = self.is_datacenter(address) if SHOW_DC_TAG else False
            dc_tag = " [DC]" if is_dc else ""

            score_info = self.scorer.score_profile(config, parsed_data, success=True)
            score = score_info.get('score', 50)

            proto_info = self.build_protocol_info(protocol, parsed_data)

            name = NAMING_FORMAT.format(
                flag=flag,
                country_code=country_code,
                asn_name=asn_display,
                dc_tag=dc_tag,
                protocol_info=proto_info,
                score=round(score, 1)
            )
            name = NAMING_SEPARATOR.join(name.split())

            if config_lower.startswith('vmess://'):
                parsed_data['ps'] = name
                encoded = base64.b64encode(json.dumps(parsed_data, ensure_ascii=False).encode('utf-8')).decode('utf-8')
                return f"vmess://{encoded}"
            else:
                if '#' in config:
                    base = config.split('#')[0]
                else:
                    base = config
                return f"{base}#{name}"

        except Exception as e:
            logger.error(f"Rename failed for config {index}: {e}")
            return config

    def process_configs(self, input_file: str, output_file: str):
        try:
            with open(input_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except Exception as e:
            logger.error(f"Error reading {input_file}: {e}")
            return

        renamed = []
        configs = []
        header = []
        for line in lines:
            line = line.strip()
            if line.startswith('//') or not line:
                if not configs:
                    header.append(line)
            else:
                configs.append(line)

        for idx, cfg in enumerate(configs, 1):
            new_cfg = self.rename_config(cfg, idx)
            if new_cfg:
                renamed.append(new_cfg)

        try:
            # Используем буферизированную запись с большим буфером
            with open(output_file, 'w', encoding='utf-8', buffering=1024*1024) as f:
                for h in header:
                    f.write(h + '\n')
                if header and renamed:
                    f.write('\n')
                for cfg in renamed:
                    f.write(cfg + '\n\n')
            logger.info(f"Renamed {len(renamed)} configs to {output_file}")
        except Exception as e:
            logger.error(f"Failed to write output: {e}")

        self.geo.close_and_cleanup()

def main():
    if len(sys.argv) < 4:
        print("Usage: python rename_configs.py <location.json> <input.txt> <output.txt>")
        sys.exit(1)
    location_file = sys.argv[1]
    input_file = sys.argv[2]
    output_file = sys.argv[3]
    renamer = ConfigRenamer(location_file)
    renamer.process_configs(input_file, output_file)

if __name__ == '__main__':
    main()
