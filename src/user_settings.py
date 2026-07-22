#!/usr/bin/env python3

"""
Файл пользовательских настроек для Proxy-Hunter.
Все параметры сгруппированы по блокам и снабжены комментариями.
Измените значения под свои нужды.
"""

import os
import logging

logger = logging.getLogger(__name__)

# ============================================================
# БЛОК 1: ИСТОЧНИКИ КОНФИГУРАЦИЙ (каналы Telegram)
# ============================================================

# Список URL Telegram-каналов (или ssconf-ссылок), откуда собирать конфиги.
# Можно указать как прямые ссылки на каналы (https://t.me/s/...).
PROXY_SOURCE_URLS = [
    "https://t.me/s/SOSkeyNET",
    "https://t.me/s/GozargahAzad",
    "https://t.me/s/generalconfiig",
    "https://t.me/s/kurdconfig",
    "https://t.me/s/MiTiVPN",
    "https://t.me/s/WangCai2",
]

# Файл с пользовательскими каналами (построчный список URL).
# Если файл существует, он переопределяет PROXY_SOURCE_URLS.
PROXY_CUSTOM_CHANNELS_FILE = 'custom_channels.txt'

# ============================================================
# БЛОК 2: РЕЖИМ РАБОТЫ (количество собираемых конфигов)
# ============================================================

# Если True – собирать максимум возможного (до 20 000 конфигов).
# Если False – собирать ограниченное число (задаётся ниже).
PROXY_USE_MAXIMUM_POWER = True

# Целевое количество конфигов при PROXY_USE_MAXIMUM_POWER = False.
# Рекомендуемые значения: 50–500 (для теста) или 1000–5000 (для продакшена).
PROXY_SPECIFIC_CONFIG_COUNT = 5000

# ============================================================
# БЛОК 3: ВРЕМЕННЫЕ ОКНА ДЛЯ СОХРАНЕНИЯ
# ============================================================

# Максимальный возраст профиля (в днях) для попадания в output_archive.txt.
# Профили, у которых last_seen старше этого числа, не будут включены в архив.
PROXY_ARCHIVE_MAX_AGE_DAYS = 14   # пример: 14

# Максимальный возраст профиля (в днях) для попадания в output_simple.txt.
# Профили, у которых last_seen старше этого числа, не будут включены в простой вывод.
PROXY_SIMPLE_MAX_AGE_DAYS = 3     # пример: 3

# Максимальный возраст конфигурации (в днях) для проверки валидности.
# Используется в is_config_valid (fetch_configs.py) для фильтрации старых конфигов.
PROXY_MAX_CONFIG_AGE_DAYS = 14    # совпадает с ARCHIVE по умолчанию

# ============================================================
# БЛОК 4: СЕТЕВЫЕ ПАРАМЕТРЫ (таймауты, лимиты)
# ============================================================

# Таймаут TCP-соединения при активной проверке (секунды).
# Для быстрых сетей оставьте 5, для медленных или перегруженных – увеличьте до 10–15.
PROXY_CHECK_TCP_TIMEOUT = 5.0

# Таймаут HTTP-запроса при проверке (секунды).
# Используется для замеров скорости и получения ответа от прокси.
PROXY_CHECK_HTTP_TIMEOUT = 5.0

# Максимально допустимая задержка (мс). Профили с большей задержкой считаются непригодными.
# Рекомендуемый диапазон: 2000–10000 мс.
PROXY_MAX_LATENCY_MS = 6000.0

# Количество одновременных проверок (воркеров) в активном чекере.
# Не рекомендуется ставить > 200, чтобы не перегружать сеть.
PROXY_ACTIVE_CHECKER_WORKERS = 100

# Максимальное число одновременных проверок на один хост (IP/домен).
# Помогает избежать блокировок со стороны сервера.
PROXY_PER_HOST_LIMIT = 10

# ============================================================
# БЛОК 5: ОГРАНИЧЕНИЯ ЗАПРОСОВ К TELEGRAM
# ============================================================

# Количество запросов к Telegram в секунду (адаптивный лимитер).
# Стандартное ограничение Telegram – 1 запрос в секунду на метод.
# Можно увеличить до 2–3, если каналы отвечают быстро.
PROXY_TELEGRAM_CALLS_PER_SECOND = 1.5

# Максимальный размер ответа от Telegram (байт). Если ответ больше – обрезается.
PROXY_MAX_RESPONSE_SIZE_BYTES = 1_048_576  # 1 МБ

# ============================================================
# БЛОК 6: ПОВТОРНЫЕ ПОПЫТКИ (retry)
# ============================================================

# Количество попыток загрузки канала при ошибке.
PROXY_CHANNEL_RETRY_ATTEMPTS = 3

# Начальная задержка между попытками (секунды).
PROXY_CHANNEL_RETRY_BASE_DELAY = 0.5

# Максимальная задержка между попытками (секунды).
PROXY_CHANNEL_RETRY_MAX_DELAY = 10.0

# Общее время, отведённое на все попытки (секунды).
PROXY_CHANNEL_RETRY_DEADLINE = 60.0

# ============================================================
# БЛОК 7: ОЦЕНКА КАЧЕСТВА (скоринг)
# ============================================================

# Минимальный балл качества, при котором профиль попадает в финальный вывод.
# Баллы от 0 до 100. Рекомендуемые значения: 30–50.
PROXY_SCORE_MIN_THRESHOLD = 30.0

# Веса для расчёта итогового балла (сумма должна быть равна 1.0).
PROXY_SCORE_WEIGHTS = {
    'stability': 0.30,        # стабильность задержки (CV)
    'success_rate': 0.25,     # доля успешных проверок
    'reputation': 0.20,       # репутация сервера (датацентр/частный VPS)
    'lifetime': 0.15,         # ожидаемое время жизни (часы)
    'config_quality': 0.10,   # качество конфигурации (наличие SNI, flow и т.д.)
}

# Период полураспада для учёта старых данных (часы).
# Чем больше, тем дольше учитывается история.
PROXY_DECAY_PERIOD_HOURS = 24.0

# ============================================================
# БЛОК 8: ДЕТЕКЦИЯ ДАТАЦЕНТРОВ
# ============================================================

# Путь к файлу с базой данных MaxMind GeoLite2 ASN (mmdb).
# Если файл не найден, используется встроенный список популярных датацентров.
PROXY_GEOLITE2_ASN_PATH = 'configs/GeoLite2-ASN.mmdb'

# Встроенный список IP-диапазонов / ASN известных датацентров.
# Используется как резервный, если база MaxMind недоступна.
PROXY_BUILTIN_DATACENTER_ASNS = {
    'AS16509': 'AWS',      # Amazon
    'AS14618': 'AWS',
    'AS15169': 'Google',
    'AS396982': 'Google',
    'AS8075': 'Microsoft',
    'AS8068': 'Microsoft',
    'AS13335': 'Cloudflare',
    'AS14061': 'DigitalOcean',
    'AS24940': 'Hetzner',
    'AS16276': 'OVH',
    'AS45102': 'Alibaba',
    'AS31898': 'Oracle',
    'AS54113': 'Fastly',
    'AS20940': 'Akamai',
    'AS63949': 'Linode',
    'AS133752': 'Leaseweb',
    'AS20473': 'Vultr',
}

# ============================================================
# БЛОК 9: ПРОТОКОЛЫ (включить/выключить)
# ============================================================

# Словарь с флагами включения для каждого протокола.
# True – собирать и обрабатывать, False – игнорировать.
PROXY_ENABLED_PROTOCOLS = {
    "wireguard://": False,
    "hysteria2://": True,
    "vless://": True,
    "vmess://": True,
    "ss://": True,
    "trojan://": True,
    "tuic://": False,
}

# ============================================================
# БЛОК 10: ПАРАМЕТРЫ ЗДОРОВЬЯ КАНАЛОВ
# ============================================================

# Порог общего скора канала, ниже которого он считается нездоровым.
PROXY_CHANNEL_HEALTH_THRESHOLD = 30.0

# Минимальное число конфигов, которое должен дать канал, чтобы считаться рабочим.
PROXY_CHANNEL_MIN_CONFIGS = 3

# Минимальная доля валидных конфигов от общего числа.
PROXY_CHANNEL_MIN_VALID_RATIO = 0.05

# Минимальное число различных протоколов в канале.
PROXY_CHANNEL_MIN_PROTOCOLS = 1

# Сколько дней истории учитывать при оценке канала.
PROXY_CHANNEL_HISTORY_DAYS = 7

# Порог положительного тренда для восстановления канала.
PROXY_CHANNEL_RECOVERING_TREND_THRESHOLD = 0.1

# Минимальное число дней для расчёта тренда.
PROXY_CHANNEL_MIN_RECENT_DAYS_FOR_TREND = 2

# Список каналов, которые всегда считаются здоровыми (белый список).
PROXY_CHANNEL_WHITELIST = []   # пример: ["https://t.me/s/MyReliableChannel"]

# ============================================================
# БЛОК 11: СТАТИСТИКА И АНАЛИЗ
# ============================================================

# Минимальное число запусков для адаптивных порогов (аномалии).
PROXY_MIN_RUNS_FOR_ADAPTIVE_THRESHOLDS = 9

# Порог Z-скора для детекции аномалий.
PROXY_ANOMALY_Z_SCORE_THRESHOLD = 2.5

# Множитель межквартильного размаха (IQR) для детекции аномалий.
PROXY_ANOMALY_IQR_MULTIPLIER = 1.5

# Порог падения скора для детекции аномалий (относительно среднего).
PROXY_ANOMALY_DROP_THRESHOLD = 0.5

# Максимальное число записей в истории (runs).
PROXY_MAX_HISTORY_RUNS = 100

# Интервал автосохранения истории (секунды).
PROXY_SAVE_INTERVAL_SECONDS = 30

# Шифровать IP-адреса в истории (хешировать).
PROXY_ENCRYPT_IPS = True

# Соль для хеширования IP.
PROXY_ENCRYPTION_SALT = 'proxy_hunter_salt_2026'


# ============================================================
# ЗАГРУЗКА ПЕРЕМЕННЫХ ИЗ ОКРУЖЕНИЯ (переопределение через ENV)
# ============================================================

def _get_bool(key, default):
    val = os.getenv(key, str(default))
    return val.lower() in ('true', '1', 'yes', 'on')

def _get_int(key, default, min_val=None, max_val=None):
    try:
        val = int(os.getenv(key, str(default)))
        if min_val is not None and val < min_val:
            return default
        if max_val is not None and val > max_val:
            return default
        return val
    except:
        return default

def _get_float(key, default, min_val=None, max_val=None):
    try:
        val = float(os.getenv(key, str(default)))
        if min_val is not None and val < min_val:
            return default
        if max_val is not None and val > max_val:
            return default
        return val
    except:
        return default

# Загружаем каналы из файла, если он существует
def _load_channels():
    channels = []
    if os.path.exists(PROXY_CUSTOM_CHANNELS_FILE):
        try:
            with open(PROXY_CUSTOM_CHANNELS_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        channels.append(line)
        except Exception as e:
            logger.warning(f"Не удалось загрузить каналы из {PROXY_CUSTOM_CHANNELS_FILE}: {e}")
    if not channels:
        channels = PROXY_SOURCE_URLS[:]
    return channels

SOURCE_URLS = _load_channels()
USE_MAXIMUM_POWER = _get_bool('PROXY_USE_MAXIMUM_POWER', PROXY_USE_MAXIMUM_POWER)
SPECIFIC_CONFIG_COUNT = _get_int('PROXY_SPECIFIC_CONFIG_COUNT', PROXY_SPECIFIC_CONFIG_COUNT, 1, 50000)
ARCHIVE_MAX_AGE_DAYS = _get_int('PROXY_ARCHIVE_MAX_AGE_DAYS', PROXY_ARCHIVE_MAX_AGE_DAYS, 1, 90)
SIMPLE_MAX_AGE_DAYS = _get_int('PROXY_SIMPLE_MAX_AGE_DAYS', PROXY_SIMPLE_MAX_AGE_DAYS, 1, 30)
MAX_CONFIG_AGE_DAYS = _get_int('PROXY_MAX_CONFIG_AGE_DAYS', PROXY_MAX_CONFIG_AGE_DAYS, 1, 90)   # <-- НОВАЯ ПЕРЕМЕННАЯ
TCP_TIMEOUT = _get_float('PROXY_CHECK_TCP_TIMEOUT', PROXY_CHECK_TCP_TIMEOUT, 0.5, 30.0)
HTTP_TIMEOUT = _get_float('PROXY_CHECK_HTTP_TIMEOUT', PROXY_CHECK_HTTP_TIMEOUT, 0.5, 30.0)
MAX_LATENCY_MS = _get_float('PROXY_MAX_LATENCY_MS', PROXY_MAX_LATENCY_MS, 100.0, 60000.0)
ACTIVE_CHECKER_WORKERS = _get_int('PROXY_ACTIVE_CHECKER_WORKERS', PROXY_ACTIVE_CHECKER_WORKERS, 1, 500)
PER_HOST_LIMIT = _get_int('PROXY_PER_HOST_LIMIT', PROXY_PER_HOST_LIMIT, 1, 50)
TELEGRAM_CALLS_PER_SECOND = _get_float('PROXY_TELEGRAM_CALLS_PER_SECOND', PROXY_TELEGRAM_CALLS_PER_SECOND, 0.1, 10.0)
MAX_RESPONSE_SIZE_BYTES = _get_int('PROXY_MAX_RESPONSE_SIZE_BYTES', PROXY_MAX_RESPONSE_SIZE_BYTES, 65536, 10485760)
CHANNEL_RETRY_ATTEMPTS = _get_int('PROXY_CHANNEL_RETRY_ATTEMPTS', PROXY_CHANNEL_RETRY_ATTEMPTS, 1, 10)
CHANNEL_RETRY_BASE_DELAY = _get_float('PROXY_CHANNEL_RETRY_BASE_DELAY', PROXY_CHANNEL_RETRY_BASE_DELAY, 0.1, 10.0)
CHANNEL_RETRY_MAX_DELAY = _get_float('PROXY_CHANNEL_RETRY_MAX_DELAY', PROXY_CHANNEL_RETRY_MAX_DELAY, 1.0, 60.0)
CHANNEL_RETRY_DEADLINE = _get_float('PROXY_CHANNEL_RETRY_DEADLINE', PROXY_CHANNEL_RETRY_DEADLINE, 10.0, 300.0)
SCORE_MIN_THRESHOLD = _get_float('PROXY_SCORE_MIN_THRESHOLD', PROXY_SCORE_MIN_THRESHOLD, 0.0, 100.0)
SCORE_WEIGHTS = PROXY_SCORE_WEIGHTS
DECAY_PERIOD_HOURS = _get_float('PROXY_DECAY_PERIOD_HOURS', PROXY_DECAY_PERIOD_HOURS, 1.0, 720.0)
ENABLED_PROTOCOLS = PROXY_ENABLED_PROTOCOLS
CHANNEL_HEALTH_THRESHOLD = _get_float('PROXY_CHANNEL_HEALTH_THRESHOLD', PROXY_CHANNEL_HEALTH_THRESHOLD, 0.0, 100.0)
CHANNEL_MIN_CONFIGS = _get_int('PROXY_CHANNEL_MIN_CONFIGS', PROXY_CHANNEL_MIN_CONFIGS, 1, 100)
CHANNEL_MIN_VALID_RATIO = _get_float('PROXY_CHANNEL_MIN_VALID_RATIO', PROXY_CHANNEL_MIN_VALID_RATIO, 0.0, 1.0)
CHANNEL_MIN_PROTOCOLS = _get_int('PROXY_CHANNEL_MIN_PROTOCOLS', PROXY_CHANNEL_MIN_PROTOCOLS, 1, 10)
CHANNEL_HISTORY_DAYS = _get_int('PROXY_CHANNEL_HISTORY_DAYS', PROXY_CHANNEL_HISTORY_DAYS, 3, 30)
CHANNEL_RECOVERING_TREND_THRESHOLD = _get_float('PROXY_CHANNEL_RECOVERING_TREND_THRESHOLD', PROXY_CHANNEL_RECOVERING_TREND_THRESHOLD, 0.01, 0.5)
CHANNEL_MIN_RECENT_DAYS_FOR_TREND = _get_int('PROXY_CHANNEL_MIN_RECENT_DAYS_FOR_TREND', PROXY_CHANNEL_MIN_RECENT_DAYS_FOR_TREND, 1, 7)
CHANNEL_WHITELIST = PROXY_CHANNEL_WHITELIST
MIN_RUNS_FOR_ADAPTIVE_THRESHOLDS = _get_int('PROXY_MIN_RUNS_FOR_ADAPTIVE_THRESHOLDS', PROXY_MIN_RUNS_FOR_ADAPTIVE_THRESHOLDS, 3, 50)
ANOMALY_Z_SCORE_THRESHOLD = _get_float('PROXY_ANOMALY_Z_SCORE_THRESHOLD', PROXY_ANOMALY_Z_SCORE_THRESHOLD, 1.0, 5.0)
ANOMALY_IQR_MULTIPLIER = _get_float('PROXY_ANOMALY_IQR_MULTIPLIER', PROXY_ANOMALY_IQR_MULTIPLIER, 0.5, 3.0)
ANOMALY_DROP_THRESHOLD = _get_float('PROXY_ANOMALY_DROP_THRESHOLD', PROXY_ANOMALY_DROP_THRESHOLD, 0.1, 0.9)
MAX_HISTORY_RUNS = _get_int('PROXY_MAX_HISTORY_RUNS', PROXY_MAX_HISTORY_RUNS, 10, 1000)
SAVE_INTERVAL_SECONDS = _get_int('PROXY_SAVE_INTERVAL_SECONDS', PROXY_SAVE_INTERVAL_SECONDS, 5, 300)
ENCRYPT_IPS = _get_bool('PROXY_ENCRYPT_IPS', PROXY_ENCRYPT_IPS)
ENCRYPTION_SALT = os.getenv('PROXY_ENCRYPTION_SALT', PROXY_ENCRYPTION_SALT)
GEOLITE2_ASN_PATH = os.getenv('PROXY_GEOLITE2_ASN_PATH', PROXY_GEOLITE2_ASN_PATH)
BUILTIN_DATACENTER_ASNS = PROXY_BUILTIN_DATACENTER_ASNS
