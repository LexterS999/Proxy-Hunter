import os
import re
import logging
from urllib.parse import urlparse
from typing import List

logger = logging.getLogger(__name__)

# ============================================================
#  НАСТРОЙКИ ПРОЕКТА — ПРОЧТИ ЭТО ВНИМАТЕЛЬНО
# ============================================================
#  Все параметры можно переопределить через переменные окружения.
# ============================================================

# --------------------- Источники конфигураций ---------------------

CUSTOM_CHANNELS_FILE = 'custom_channels.txt'

# Расширенный список каналов по умолчанию
DEFAULT_SOURCE_URLS = [
    "https://t.me/s/SOSkeyNET",
    "https://t.me/s/GozargahAzad",
    "https://t.me/s/generalconfiig",
    "https://t.me/s/kurdconfig",
    "https://t.me/s/MiTiVPN",
    "https://t.me/s/WangCai2",
    "https://t.me/s/NebulaVPNx",
    "https://t.me/s/MARAMBASHI_MARAMBASHI_MARAMBASHI",
    "https://t.me/s/Marisa_kristi",
    "https://t.me/s/MAconnectt",
    "https://t.me/s/alaUK",
    "https://t.me/s/V2WRAY",
    "https://t.me/s/Arshiavpn12",
    "https://t.me/s/R3MRCG00129437X",
    "https://t.me/s/MoftConfig",
    "https://t.me/s/proxyshareCN",
]

def normalize_url(url: str) -> str:
    url = url.strip()
    if not url:
        return ''
    url = url.lower()
    parsed = urlparse(url)
    if parsed.scheme and parsed.netloc:
        netloc = parsed.netloc.replace('www.', '')
        path = parsed.path.rstrip('/')
        return f"{parsed.scheme}://{netloc}{path}"
    return url

def load_channels_from_file(filepath: str) -> list:
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

custom_channels = load_channels_from_file(CUSTOM_CHANNELS_FILE)
SOURCE_URLS = custom_channels if custom_channels else DEFAULT_SOURCE_URLS

# --------------------- Вспомогательная функция ---------------------

def get_safe_env(key: str, default: str, valid_values: List[str] = None, value_type: type = str) -> object:
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

# --------------------- Основные настройки ---------------------

USE_MAXIMUM_POWER = get_safe_env('PROXY_HUNTER_USE_MAXIMUM_POWER', 'True', value_type=bool)
SPECIFIC_CONFIG_COUNT = get_safe_env('PROXY_HUNTER_SPECIFIC_CONFIG_COUNT', '5000', value_type=int)
MAX_CONFIG_AGE_DAYS = get_safe_env('PROXY_HUNTER_MAX_CONFIG_AGE_DAYS', '14', value_type=int)

# Включаемые протоколы
_ENABLED_PROTOCOLS_RAW = {
    "wireguard://": os.getenv('PROXY_HUNTER_ENABLE_WIREGUARD', 'False'),
    "hysteria2://": os.getenv('PROXY_HUNTER_ENABLE_HYSTERIA2', 'True'),
    "vless://": os.getenv('PROXY_HUNTER_ENABLE_VLESS', 'True'),
    "vmess://": os.getenv('PROXY_HUNTER_ENABLE_VMESS', 'True'),
    "ss://": os.getenv('PROXY_HUNTER_ENABLE_SS', 'True'),
    "trojan://": os.getenv('PROXY_HUNTER_ENABLE_TROJAN', 'True'),
    "tuic://": os.getenv('PROXY_HUNTER_ENABLE_TUIC', 'False'),
}

ENABLED_PROTOCOLS = {}
for proto, val in _ENABLED_PROTOCOLS_RAW.items():
    ENABLED_PROTOCOLS[proto] = get_safe_env(f'PROXY_HUNTER_ENABLE_{proto.replace("://", "").upper()}', val, value_type=bool)

# --------------------- Настройки активной проверки (ICMP, TCP, HTTP) ---------------------

ENABLE_ICMP_PING = get_safe_env('PROXY_HUNTER_ENABLE_ICMP', 'False', value_type=bool)  # отключаем ICMP
ICMP_TIMEOUT = get_safe_env('PROXY_HUNTER_ICMP_TIMEOUT', '1.0', value_type=float)
TCP_TIMEOUT = get_safe_env('PROXY_HUNTER_TCP_TIMEOUT', '5.0', value_type=float)        # было 1.0 → 5.0
HTTP_TIMEOUT = get_safe_env('PROXY_HUNTER_HTTP_TIMEOUT', '5.0', value_type=float)      # было 2.0 → 5.0
MAX_LATENCY_MS = get_safe_env('PROXY_HUNTER_MAX_LATENCY', '6000.0', value_type=float)
ACTIVE_CHECKER_WORKERS = get_safe_env('PROXY_HUNTER_ACTIVE_WORKERS', '100', value_type=int)
PER_HOST_LIMIT = get_safe_env('PROXY_HUNTER_PER_HOST_LIMIT', '10', value_type=int)

# --------------------- Настройки повторных попыток и Rate Limiting ---------------------

CHANNEL_RETRY_ATTEMPTS = get_safe_env('PROXY_HUNTER_CHANNEL_RETRIES', '3', value_type=int)
CHANNEL_RETRY_BASE_DELAY = get_safe_env('PROXY_HUNTER_CHANNEL_RETRY_DELAY', '0.5', value_type=float)
CHANNEL_RETRY_MAX_DELAY = get_safe_env('PROXY_HUNTER_CHANNEL_RETRY_MAX_DELAY', '10.0', value_type=float)
CHANNEL_RETRY_DEADLINE = get_safe_env('PROXY_HUNTER_CHANNEL_RETRY_DEADLINE', '60.0', value_type=float)

TELEGRAM_CALLS_PER_SECOND = get_safe_env('PROXY_HUNTER_TELEGRAM_RATE', '1.5', value_type=float)
MAX_RESPONSE_SIZE_BYTES = get_safe_env('PROXY_HUNTER_MAX_RESPONSE_SIZE', '1048576', value_type=int)  # 1 МБ

# --------------------- Именование конфигураций (без гео) ---------------------

NAMING_FORMAT = "PROTOCOL{protocol_info}"
NAMING_SEPARATOR = "-"

# --------------------- Оценка качества ---------------------

SCORE_WEIGHTS = {
    'stability': 0.3,
    'success_rate': 0.25,
    'reputation': 0.2,      # репутация теперь всегда 0.5 (без гео)
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

# --------------------- Настройки анализа каналов ---------------------

CHANNEL_HEALTH_THRESHOLD = get_safe_env('PROXY_HUNTER_CHANNEL_HEALTH_THRESHOLD', '30.0', value_type=float)
CHANNEL_MIN_CONFIGS = get_safe_env('PROXY_HUNTER_CHANNEL_MIN_CONFIGS', '3', value_type=int)
CHANNEL_MIN_VALID_RATIO = get_safe_env('PROXY_HUNTER_CHANNEL_MIN_VALID_RATIO', '0.05', value_type=float)
CHANNEL_MIN_PROTOCOLS = get_safe_env('PROXY_HUNTER_CHANNEL_MIN_PROTOCOLS', '1', value_type=int)
CHANNEL_HISTORY_DAYS = get_safe_env('PROXY_HUNTER_CHANNEL_HISTORY_DAYS', '7', value_type=int)

CHANNEL_RECOVERING_TREND_THRESHOLD = get_safe_env('PROXY_HUNTER_RECOVERING_TREND_THRESHOLD', '0.1', value_type=float)
CHANNEL_MIN_RECENT_DAYS_FOR_TREND = get_safe_env('PROXY_HUNTER_MIN_RECENT_DAYS_FOR_TREND', '2', value_type=int)

_whitelist_raw = os.getenv('PROXY_HUNTER_CHANNEL_WHITELIST', '')
CHANNEL_WHITELIST = [url.strip() for url in _whitelist_raw.split(',') if url.strip()]
