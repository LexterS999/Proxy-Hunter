import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import json
import logging
from pathlib import Path
from typing import Optional, Tuple
import config_parser as parser
from user_settings import GEO_COUNTRY_URL, GEO_ASN_URL
from geo_loader import GeoLoader

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

COUNTRY_BLACKLIST = os.getenv('PROXY_HUNTER_COUNTRY_BLACKLIST', 'CN,RU,IR').split(',')

def is_country_allowed(country_code: str) -> bool:
    return country_code not in COUNTRY_BLACKLIST

class ConfigEnricher:
    def __init__(self):
        self.geo = GeoLoader(GEO_COUNTRY_URL, GEO_ASN_URL)
        self.location_cache = {}

    def extract_address(self, config: str) -> Optional[str]:
        try:
            config_lower = config.lower()
            data = None
            if config_lower.startswith('vmess://'):
                data = parser.decode_vmess(config)
                if data and 'add' in data:
                    return data['add']
            elif config_lower.startswith('vless://'):
                data = parser.parse_vless(config)
            elif config_lower.startswith('trojan://'):
                data = parser.parse_trojan(config)
            elif config_lower.startswith(('hysteria2://', 'hy2://')):
                data = parser.parse_hysteria2(config)
            elif config_lower.startswith('ss://'):
                data = parser.parse_shadowsocks(config)
            if data and 'address' in data:
                return data['address']
            return None
        except Exception as e:
            logger.debug(f"Failed to extract address: {e}")
            return None

    def get_location(self, address: str) -> Tuple[str, str]:
        """Возвращает (флаг, код_страны) для адреса."""
        if address in self.location_cache:
            return self.location_cache[address]

        self.geo.ensure_databases()
        country_code, country_name = self.geo.get_country(address)

        # Фильтр по стране
        if not is_country_allowed(country_code):
            logger.info(f"Address {address} in blacklisted country {country_code}, skipping")
            # Возвращаем "XX", но для совместимости с форматом флага
            country_code = 'XX'

        if country_code != 'XX' and country_code:
            try:
                flag = ''.join(chr(0x1F1E6 + ord(c.upper()) - ord('A')) for c in country_code)
            except:
                flag = "🏳️"
            result = (flag, country_code)
        else:
            result = ("🏳️", "XX")

        self.location_cache[address] = result
        logger.info(f"Location for {address}: {result}")
        return result

    def process_configs(self, input_file: str, output_file: str):
        input_path = Path(input_file)
        if not input_path.exists():
            logger.error(f"{input_file} not found!")
            return

        with open(input_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        configs = [line.strip() for line in lines if line.strip() and not line.startswith('//')]
        unique_addresses = set()
        for config in configs:
            addr = self.extract_address(config)
            if addr:
                unique_addresses.add(addr)

        logger.info(f"Found {len(unique_addresses)} unique server addresses")
        for idx, addr in enumerate(unique_addresses, 1):
            self.get_location(addr)
            if idx % 10 == 0 or idx == len(unique_addresses):
                logger.info(f"Progress: {idx}/{len(unique_addresses)} addresses processed")

        # Сохраняем кэш
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            cache_for_json = {k: list(v) for k, v in self.location_cache.items()}
            json.dump(cache_for_json, f, indent=2, ensure_ascii=False)

        logger.info(f"Saved location cache to {output_file}")

        # Очистка временных баз
        self.geo.close_and_cleanup()

def main():
    if len(sys.argv) < 3:
        print("Usage: python enrich_configs.py <input.txt> <output.json>")
        sys.exit(1)
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    enricher = ConfigEnricher()
    enricher.process_configs(input_file, output_file)

if __name__ == '__main__':
    main()
