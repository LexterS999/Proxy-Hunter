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
#  Для этого перед запуском установи нужную переменную, например:
#    export PROXY_HUNTER_USE_MAXIMUM_POWER=false
#  или добавь её в GitHub Secrets / .env файл.
# ============================================================

# --------------------- Источники конфигураций ---------------------

# Файл со списком Telegram-каналов (по одному URL на строку).
# Если файл не найден или пуст, используются каналы по умолчанию.
CUSTOM_CHANNELS_FILE = 'custom_channels.txt'

# Каналы по умолчанию (если нет custom_channels.txt)
DEFAULT_SOURCE_URLS = [
    "https://t.me/s/LonUp_M",
    "https://t.me/s/SOSkeyNET",
]


def normalize_url(url: str) -> str:
    """
    Приводит URL к каноническому виду: убирает 'www.', удаляет завершающий слэш,
    приводит к нижнему регистру.

    Аргументы:
        url (str): Сырой URL.

    Возвращает:
        str: Нормализованный URL или пустую строку при ошибке.
    """
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
    """
    Загружает список URL из текстового файла (по одному на строку).
    Пропускает пустые строки и строки, начинающиеся с '#'.
    Удаляет дубликаты.

    Аргументы:
        filepath (str): Путь к файлу.

    Возвращает:
        list: Список нормализованных URL.
    """
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


# Загружаем пользовательские каналы или используем стандартные
custom_channels = load_channels_from_file(CUSTOM_CHANNELS_FILE)
SOURCE_URLS = custom_channels if custom_channels else DEFAULT_SOURCE_URLS


# --------------------- Вспомогательная функция для переменных окружения ---------------------

def get_safe_env(key: str, default: str, valid_values: List[str] = None, value_type: type = str) -> object:
    """
    Безопасно читает переменную окружения, приводит к нужному типу и проверяет допустимые значения.

    Аргументы:
        key (str): Имя переменной.
        default (str): Значение по умолчанию.
        valid_values (List[str], optional): Список допустимых строковых значений.
        value_type (type): Тип, в который преобразовать значение (str, int, float, bool).

    Возвращает:
        object: Преобразованное значение или значение по умолчанию.
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


# --------------------- Основные настройки ---------------------

# Режим работы: True — собирать максимально возможное количество конфигураций,
# False — ограничиться SPECIFIC_CONFIG_COUNT.
USE_MAXIMUM_POWER = get_safe_env('PROXY_HUNTER_USE_MAXIMUM_POWER', 'True', value_type=bool)

# Количество конфигураций, которое нужно собрать в режиме НЕ максимальной мощности.
SPECIFIC_CONFIG_COUNT = get_safe_env('PROXY_HUNTER_SPECIFIC_CONFIG_COUNT', '5000', value_type=int)

# Максимальный возраст конфигураций (в днях). Конфигурации старше этого срока
# (по дате сообщения в Telegram) будут игнорироваться.
# Увеличение этого значения даёт больше профилей, но они могут быть менее актуальными.
MAX_CONFIG_AGE_DAYS = get_safe_env('PROXY_HUNTER_MAX_CONFIG_AGE_DAYS', '14', value_type=int)

# Включение/отключение конкретных протоколов.
# По умолчанию включены vless, trojan, hysteria2.
# Для увеличения количества профилей можно включить vmess и ss.
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


# --------------------- Геолокация и обогащение ---------------------

# URL для загрузки баз MaxMind (страны и ASN). Можно заменить на локальные пути.
GEO_COUNTRY_URL = "https://media.githubusercontent.com/media/iplocate/ip-address-databases/refs/heads/main/ip-to-country/ip-to-country.mmdb"
GEO_ASN_URL = "https://media.githubusercontent.com/media/iplocate/ip-address-databases/refs/heads/main/ip-to-asn/ip-to-asn.mmdb"

# (необязательно) Можно задать локальные пути к базам, если они уже скачаны.
GEO_COUNTRY_CACHE_PATH = None
GEO_ASN_CACHE_PATH = None


# --------------------- Именование конфигураций ---------------------

# Шаблон имени, который добавляется в конец URI.
# Доступные поля: {flag}, {country_code}, {asn_name}, {dc_tag}, {protocol_info}, {score}
NAMING_FORMAT = "{protocol_info}"
NAMING_SEPARATOR = ""

# Показывать тег [DC] для датацентров.
SHOW_DC_TAG = True

# Ключевые слова для определения датацентра (используются в GeoLoader).
DC_KEYWORDS = [
    'cloud', 'host', 'data', 'server', 'vps', 'dedicated',
    'colocation', 'infrastructure', 'digitalocean', 'aws',
    'amazon', 'azure', 'google cloud', 'oracle cloud',
    'linode', 'vultr', 'hetzner', 'ovh', 'scaleway', 'leaseweb'
]


# --------------------- Оценка качества ---------------------

# Веса для компонентов композитного скора (сумма = 1.0)
SCORE_WEIGHTS = {
    'stability': 0.3,
    'success_rate': 0.25,
    'reputation': 0.2,
    'lifetime': 0.15,
    'config_quality': 0.1
}

# Период деградации (часы) — через сколько часов без успешных проверок скор снижается.
DECAY_PERIOD_HOURS = 24

# Минимальное число запусков для адаптивных порогов.
MIN_RUNS_FOR_ADAPTIVE_THRESHOLDS = 9

# Пороги для детекции аномалий (Z-score и IQR).
ANOMALY_Z_SCORE_THRESHOLD = 2.5
ANOMALY_IQR_MULTIPLIER = 1.5
ANOMALY_DROP_THRESHOLD = 0.5

# Максимальное количество хранимых запусков в истории.
MAX_HISTORY_RUNS = 100

# Интервал автосохранения истории (секунды).
SAVE_INTERVAL_SECONDS = 30

# Шифровать IP в истории (для анонимности).
ENCRYPT_IPS = True
ENCRYPTION_SALT = 'proxy_hunter_salt_2026'

# Использовать композитный скор (True) или только простой рейтинг.
USE_COMPOSITE_SCORE = True


# --------------------- Настройки анализа каналов ---------------------

# Порог здоровья канала (0–100). Каналы с скором ниже этого могут быть отключены.
CHANNEL_HEALTH_THRESHOLD = get_safe_env('PROXY_HUNTER_CHANNEL_HEALTH_THRESHOLD', '30.0', value_type=float)

# Минимальное число конфигураций, которое должен давать канал, чтобы считаться здоровым.
CHANNEL_MIN_CONFIGS = get_safe_env('PROXY_HUNTER_CHANNEL_MIN_CONFIGS', '3', value_type=int)

# Минимальная доля валидных конфигураций (от общего числа) для здоровья канала.
CHANNEL_MIN_VALID_RATIO = get_safe_env('PROXY_HUNTER_CHANNEL_MIN_VALID_RATIO', '0.05', value_type=float)

# Минимальное количество различных протоколов в канале.
CHANNEL_MIN_PROTOCOLS = get_safe_env('PROXY_HUNTER_CHANNEL_MIN_PROTOCOLS', '1', value_type=int)

# Глубина истории (в днях), учитываемая при оценке здоровья канала.
CHANNEL_HISTORY_DAYS = get_safe_env('PROXY_HUNTER_CHANNEL_HISTORY_DAYS', '3', value_type=int)

# Белый список каналов (через запятую) — эти каналы всегда считаются здоровыми.
_whitelist_raw = os.getenv('PROXY_HUNTER_CHANNEL_WHITELIST', '')
CHANNEL_WHITELIST = [url.strip() for url in _whitelist_raw.split(',') if url.strip()]
