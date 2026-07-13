import os
import re
from urllib.parse import urlparse

# Загрузка каналов из внешнего файла, если он существует
CUSTOM_CHANNELS_FILE = 'custom_channels.txt'

def normalize_url(url: str) -> str:
    """Нормализует URL канала для дедупликации."""
    url = url.strip()
    if not url:
        return ''
    # Приводим к нижнему регистру, убираем трейлинг слеши
    url = url.lower()
    parsed = urlparse(url)
    if parsed.scheme and parsed.netloc:
        # Убираем www если есть
        netloc = parsed.netloc.replace('www.', '')
        path = parsed.path.rstrip('/')
        return f"{parsed.scheme}://{netloc}{path}"
    return url

def load_channels_from_file(filepath: str) -> list:
    """Загружает список каналов из текстового файла с дедупликацией и нормализацией."""
    seen = set()
    channels = []
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        norm = normalize_url(line)
                        if norm and norm not in seen:
                            seen.add(norm)
                            channels.append(norm)
        except Exception as e:
            print(f"Warning: Failed to load channels from {filepath}: {e}")
    return channels

# Базовый список каналов (используется, если нет внешнего файла)
DEFAULT_SOURCE_URLS = [
    "https://t.me/s/LonUp_M",
    "https://t.me/s/SOSkeyNET",
]

# Объединяем с пользовательскими каналами из файла
custom_channels = load_channels_from_file(CUSTOM_CHANNELS_FILE)
SOURCE_URLS = custom_channels if custom_channels else DEFAULT_SOURCE_URLS

# Переменные окружения имеют приоритет над файловыми настройками
USE_MAXIMUM_POWER = os.getenv('PROXY_HUNTER_USE_MAXIMUM_POWER', 'True').lower() in ('true', '1', 'yes')
SPECIFIC_CONFIG_COUNT = int(os.getenv('PROXY_HUNTER_SPECIFIC_CONFIG_COUNT', '1000'))
MAX_CONFIG_AGE_DAYS = int(os.getenv('PROXY_HUNTER_MAX_CONFIG_AGE_DAYS', '1'))

# Протоколы из переменных окружения
ENABLED_PROTOCOLS = {
    "wireguard://": os.getenv('PROXY_HUNTER_ENABLE_WIREGUARD', 'False').lower() in ('true', '1', 'yes'),
    "hysteria2://": os.getenv('PROXY_HUNTER_ENABLE_HYSTERIA2', 'True').lower() in ('true', '1', 'yes'),
    "vless://": os.getenv('PROXY_HUNTER_ENABLE_VLESS', 'True').lower() in ('true', '1', 'yes'),
    "vmess://": os.getenv('PROXY_HUNTER_ENABLE_VMESS', 'False').lower() in ('true', '1', 'yes'),
    "ss://": os.getenv('PROXY_HUNTER_ENABLE_SS', 'False').lower() in ('true', '1', 'yes'),
    "trojan://": os.getenv('PROXY_HUNTER_ENABLE_TROJAN', 'True').lower() in ('true', '1', 'yes'),
    "tuic://": os.getenv('PROXY_HUNTER_ENABLE_TUIC', 'False').lower() in ('true', '1', 'yes'),
}

GEO_COUNTRY_URL = "https://media.githubusercontent.com/media/iplocate/ip-address-databases/refs/heads/main/ip-to-country/ip-to-country.mmdb"
GEO_ASN_URL = "https://media.githubusercontent.com/media/iplocate/ip-address-databases/refs/heads/main/ip-to-asn/ip-to-asn.mmdb"
GEO_COUNTRY_CACHE_PATH = None
GEO_ASN_CACHE_PATH = None

NAMING_FORMAT = "[{country_code}]{dc_tag}{protocol_info}⚡{score}"
NAMING_SEPARATOR = ""
SHOW_DC_TAG = True

DC_KEYWORDS = [
    'cloud', 'host', 'data', 'server', 'vps', 'dedicated',
    'colocation', 'infrastructure', 'digitalocean', 'aws',
    'amazon', 'azure', 'google cloud', 'oracle cloud',
    'linode', 'vultr', 'hetzner', 'ovh', 'scaleway', 'leaseweb'
]

SCORE_WEIGHTS = {
    'stability': 0.3,
    'success_rate': 0.25,
    'reputation': 0.2,
    'lifetime': 0.15,
    'config_quality': 0.1
}

DECAY_PERIOD_HOURS = 72
MIN_RUNS_FOR_ADAPTIVE_THRESHOLDS = 9
ANOMALY_Z_SCORE_THRESHOLD = 2.5
ANOMALY_IQR_MULTIPLIER = 1.5
ANOMALY_DROP_THRESHOLD = 0.5
MAX_HISTORY_RUNS = 100
SAVE_INTERVAL_SECONDS = 30
ENCRYPT_IPS = True
ENCRYPTION_SALT = 'proxy_hunter_salt_2026'
USE_COMPOSITE_SCORE = True
