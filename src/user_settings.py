import os
import re
import logging
from urllib.parse import urlparse
from typing import List

logger = logging.getLogger(__name__)

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

# Валидатор переменных окружения
def get_safe_env(key: str, default: str, valid_values: List[str] = None, value_type: type = str) -> object:
    """
    Безопасно получает переменную окружения, проверяя её на соответствие допустимым значениям.
    Если значение невалидно, возвращает default.
    """
    value = os.getenv(key, default)
    if valid_values is not None:
        if value not in valid_values:
            logger.warning(f"Invalid value for {key}: {value}, using {default}")
            return default
    if value_type == bool:
        return value.lower() in ('true', '1', 'yes')
    if value_type == int:
        try:
            return int(value)
        except ValueError:
            logger.warning(f"Invalid integer for {key}: {value}, using {default}")
            return int(default)
    if value_type == float:
        try:
            return float(value)
        except (ValueError, TypeError):
            logger.warning(f"Invalid float for {key}: {value}, using {default}")
            return float(default)
    return value

# Применяем валидацию ко всем переменным окружения
USE_MAXIMUM_POWER = get_safe_env('PROXY_HUNTER_USE_MAXIMUM_POWER', 'True', value_type=bool)
SPECIFIC_CONFIG_COUNT = get_safe_env('PROXY_HUNTER_SPECIFIC_CONFIG_COUNT', '1000', value_type=int)
MAX_CONFIG_AGE_DAYS = get_safe_env('PROXY_HUNTER_MAX_CONFIG_AGE_DAYS', '3', value_type=int)

# Протоколы из переменных окружения
_ENABLED_PROTOCOLS_RAW = {
    "wireguard://": os.getenv('PROXY_HUNTER_ENABLE_WIREGUARD', 'False'),
    "hysteria2://": os.getenv('PROXY_HUNTER_ENABLE_HYSTERIA2', 'True'),
    "vless://": os.getenv('PROXY_HUNTER_ENABLE_VLESS', 'True'),
    "vmess://": os.getenv('PROXY_HUNTER_ENABLE_VMESS', 'False'),
    "ss://": os.getenv('PROXY_HUNTER_ENABLE_SS', 'False'),
    "trojan://": os.getenv('PROXY_HUNTER_ENABLE_TROJAN', 'True'),
    "tuic://": os.getenv('PROXY_HUNTER_ENABLE_TUIC', 'False'),
}

ENABLED_PROTOCOLS = {}
for proto, val in _ENABLED_PROTOCOLS_RAW.items():
    ENABLED_PROTOCOLS[proto] = get_safe_env(f'PROXY_HUNTER_ENABLE_{proto.replace("://", "").upper()}', val, value_type=bool)

GEO_COUNTRY_URL = "https://media.githubusercontent.com/media/iplocate/ip-address-databases/refs/heads/main/ip-to-country/ip-to-country.mmdb"
GEO_ASN_URL = "https://media.githubusercontent.com/media/iplocate/ip-address-databases/refs/heads/main/ip-to-asn/ip-to-asn.mmdb"
GEO_COUNTRY_CACHE_PATH = None
GEO_ASN_CACHE_PATH = None

NAMING_FORMAT = "{protocol_info}"
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

DECAY_PERIOD_HOURS = 24
MIN_RUNS_FOR_ADAPTIVE_THRESHOLDS = 9
ANOMALY_Z_SCORE_THRESHOLD = 2.5
ANOMALY_IQR_MULTIPLIER = 1.5
ANOMALY_DROP_THRESHOLD = 0.5
MAX_HISTORY_RUNS = 100
SAVE_INTERVAL_SECONDS = 30
ENCRYPT_IPS = True
ENCRYPTION_SALT = 'proxy_hunter_salt_2026'
USE_COMPOSITE_SCORE = True

# === Настройки анализа каналов ===
CHANNEL_HEALTH_THRESHOLD = get_safe_env('PROXY_HUNTER_CHANNEL_HEALTH_THRESHOLD', '25.0', value_type=float)
CHANNEL_MIN_CONFIGS = get_safe_env('PROXY_HUNTER_CHANNEL_MIN_CONFIGS', '5', value_type=int)
CHANNEL_MIN_VALID_RATIO = get_safe_env('PROXY_HUNTER_CHANNEL_MIN_VALID_RATIO', '0.1', value_type=float)
CHANNEL_MIN_PROTOCOLS = get_safe_env('PROXY_HUNTER_CHANNEL_MIN_PROTOCOLS', '1', value_type=int)
CHANNEL_HISTORY_DAYS = get_safe_env('PROXY_HUNTER_CHANNEL_HISTORY_DAYS', '7', value_type=int)
# Белый список каналов (разделённые запятыми URL)
_whitelist_raw = os.getenv('PROXY_HUNTER_CHANNEL_WHITELIST', '')
CHANNEL_WHITELIST = [url.strip() for url in _whitelist_raw.split(',') if url.strip()]

# === НОВЫЕ НАСТРОЙКИ ДЛЯ РАСШИРЕННОГО АНАЛИЗА ===
# Пороги для адаптивной системы
ADAPTIVE_THRESHOLDS_ENABLED = get_safe_env('PROXY_HUNTER_ADAPTIVE_THRESHOLDS', 'True', value_type=bool)
HEALTH_CLASSIFIER_ENABLED = get_safe_env('PROXY_HUNTER_HEALTH_CLASSIFIER', 'True', value_type=bool)
LIFETIME_PREDICTOR_ENABLED = get_safe_env('PROXY_HUNTER_LIFETIME_PREDICTOR', 'True', value_type=bool)
CLUSTERING_ENABLED = get_safe_env('PROXY_HUNTER_CLUSTERING', 'True', value_type=bool)
GRACEFUL_REMOVAL_ENABLED = get_safe_env('PROXY_HUNTER_GRACEFUL_REMOVAL', 'True', value_type=bool)
AB_TEST_ENABLED = get_safe_env('PROXY_HUNTER_AB_TEST', 'True', value_type=bool)

# Параметры моделей
HEALTH_CLASSIFIER_FEATURES = [
    'total_configs', 'valid_rate', 'success_rate',
    'protocol_diversity', 'avg_response_time',
    'update_frequency', 'consecutive_failures',
    'score_trend', 'config_volatility'
]
LIFETIME_PREDICTOR_LOOKBACK = 30  # дней
LIFETIME_PREDICTOR_FORECAST = 30  # дней
GRACEFUL_REMOVAL_WATCH_PERIOD = 3  # циклов
AB_TEST_INTERVAL = 5  # циклов

# Пороги для кластеров
CLUSTER_COUNT = 4
CLUSTER_FEATURES = ['total_configs', 'overall_score', 'success_rate', 'config_volatility']
