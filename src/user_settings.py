"""
Настройки проекта с валидацией и единой точкой загрузки.
Используется синглтон для предотвращения побочных эффектов при импорте.

ИСПРАВЛЕНО:
- Сохранены ВСЕ оригинальные экспорты для обратной совместимости
  (config.py, fetch_configs.py, active_checker.py и др.)
- Добавлены новые настройки: target_region, test_domain, xray_path,
  region_test_top_n, skip_verification, survival, censorship
- reload_settings() обновляет ВСЕ глобальные переменные
"""

import os
import re
import logging
from urllib.parse import urlparse
from typing import List, Optional, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_SOURCE_URLS = [
    "https://t.me/s/SOSkeyNET",
    "https://t.me/s/GozargahAzad",
    "https://t.me/s/generalconfiig",
    "https://t.me/s/kurdconfig",
    "https://t.me/s/MiTiVPN",
    "https://t.me/s/WangCai2",
]

CUSTOM_CHANNELS_FILE = 'custom_channels.txt'

# Региональные тестовые домены (для авто-выбора при пустом TEST_DOMAIN)
_DEFAULT_TEST_DOMAINS = {
    'RU': 'rutracker.org',
    'CN': 'google.com',
    'IR': 'twitter.com',
    'GENERIC': 'google.com',
}


class Settings:
    """Единый класс настроек с валидацией и перезагрузкой."""
    _instance = None
    _initialized = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not self._initialized:
            self._load()
            self._initialized = True

    def _load(self):
        """Загружает настройки из окружения и файлов с валидацией."""
        # Каналы
        self._source_urls = self._load_channels()
        self._source_urls = self._validate_urls(self._source_urls)

        # Основные флаги
        self.use_maximum_power = self._get_bool('PROXY_HUNTER_USE_MAXIMUM_POWER', True)
        self.specific_config_count = self._get_int('PROXY_HUNTER_SPECIFIC_CONFIG_COUNT', 5000, min_val=1, max_val=50000)
        self.max_config_age_days = self._get_int('PROXY_HUNTER_MAX_CONFIG_AGE_DAYS', 14, min_val=1, max_val=90)

        # Протоколы
        self._enabled_protocols = {
            "wireguard://": self._get_bool('PROXY_HUNTER_ENABLE_WIREGUARD', False),
            "hysteria2://": self._get_bool('PROXY_HUNTER_ENABLE_HYSTERIA2', True),
            "vless://": self._get_bool('PROXY_HUNTER_ENABLE_VLESS', True),
            "vmess://": self._get_bool('PROXY_HUNTER_ENABLE_VMESS', True),
            "ss://": self._get_bool('PROXY_HUNTER_ENABLE_SS', True),
            "trojan://": self._get_bool('PROXY_HUNTER_ENABLE_TROJAN', True),
            "tuic://": self._get_bool('PROXY_HUNTER_ENABLE_TUIC', False),
        }

        # Таймауты и лимиты
        self.tcp_timeout = self._get_float('PROXY_HUNTER_TCP_TIMEOUT', 5.0, min_val=0.5, max_val=30.0)
        self.http_timeout = self._get_float('PROXY_HUNTER_HTTP_TIMEOUT', 5.0, min_val=0.5, max_val=30.0)
        self.max_latency_ms = self._get_float('PROXY_HUNTER_MAX_LATENCY', 6000.0, min_val=100.0, max_val=60000.0)
        self.active_checker_workers = self._get_int('PROXY_HUNTER_ACTIVE_WORKERS', 100, min_val=1, max_val=500)
        self.per_host_limit = self._get_int('PROXY_HUNTER_PER_HOST_LIMIT', 10, min_val=1, max_val=50)

        # Rate limiting
        self.telegram_calls_per_second = self._get_float('PROXY_HUNTER_TELEGRAM_RATE', 1.5, min_val=0.1, max_val=10.0)
        self.max_response_size_bytes = self._get_int('PROXY_HUNTER_MAX_RESPONSE_SIZE', 1048576, min_val=65536, max_val=10485760)

        # Повторные попытки
        self.channel_retry_attempts = self._get_int('PROXY_HUNTER_CHANNEL_RETRIES', 3, min_val=1, max_val=10)
        self.channel_retry_base_delay = self._get_float('PROXY_HUNTER_CHANNEL_RETRY_DELAY', 0.5, min_val=0.1, max_val=10.0)
        self.channel_retry_max_delay = self._get_float('PROXY_HUNTER_CHANNEL_RETRY_MAX_DELAY', 10.0, min_val=1.0, max_val=60.0)
        self.channel_retry_deadline = self._get_float('PROXY_HUNTER_CHANNEL_RETRY_DEADLINE', 60.0, min_val=10.0, max_val=300.0)

        # Оценка каналов
        self.channel_health_threshold = self._get_float('PROXY_HUNTER_CHANNEL_HEALTH_THRESHOLD', 30.0, min_val=0.0, max_val=100.0)
        self.channel_min_configs = self._get_int('PROXY_HUNTER_CHANNEL_MIN_CONFIGS', 3, min_val=1, max_val=100)
        self.channel_min_valid_ratio = self._get_float('PROXY_HUNTER_CHANNEL_MIN_VALID_RATIO', 0.05, min_val=0.0, max_val=1.0)
        self.channel_min_protocols = self._get_int('PROXY_HUNTER_CHANNEL_MIN_PROTOCOLS', 1, min_val=1, max_val=10)
        self.channel_history_days = self._get_int('PROXY_HUNTER_CHANNEL_HISTORY_DAYS', 7, min_val=3, max_val=30)
        self.channel_recovering_trend_threshold = self._get_float('PROXY_HUNTER_RECOVERING_TREND_THRESHOLD', 0.1, min_val=0.01, max_val=0.5)
        self.channel_min_recent_days_for_trend = self._get_int('PROXY_HUNTER_MIN_RECENT_DAYS_FOR_TREND', 2, min_val=1, max_val=7)

        whitelist_raw = os.getenv('PROXY_HUNTER_CHANNEL_WHITELIST', '')
        self.channel_whitelist = [url.strip() for url in whitelist_raw.split(',') if url.strip()]

        # Веса для оценки
        self.score_weights = {
            'stability': self._get_float('PROXY_HUNTER_WEIGHT_STABILITY', 0.3, min_val=0, max_val=1),
            'success_rate': self._get_float('PROXY_HUNTER_WEIGHT_SUCCESS_RATE', 0.25, min_val=0, max_val=1),
            'reputation': self._get_float('PROXY_HUNTER_WEIGHT_REPUTATION', 0.2, min_val=0, max_val=1),
            'lifetime': self._get_float('PROXY_HUNTER_WEIGHT_LIFETIME', 0.15, min_val=0, max_val=1),
            'config_quality': self._get_float('PROXY_HUNTER_WEIGHT_CONFIG_QUALITY', 0.1, min_val=0, max_val=1),
        }
        # Нормализуем веса
        total = sum(self.score_weights.values())
        if total > 0:
            for k in self.score_weights:
                self.score_weights[k] /= total

        # Прочие
        self.decay_period_hours = self._get_float('PROXY_HUNTER_DECAY_PERIOD', 24.0, min_val=1, max_val=720)
        self.min_runs_for_adaptive_thresholds = self._get_int('PROXY_HUNTER_MIN_RUNS_ADAPTIVE', 9, min_val=3, max_val=50)
        self.anomaly_z_score_threshold = self._get_float('PROXY_HUNTER_ANOMALY_Z_SCORE', 2.5, min_val=1.0, max_val=5.0)
        self.anomaly_iqr_multiplier = self._get_float('PROXY_HUNTER_ANOMALY_IQR', 1.5, min_val=0.5, max_val=3.0)
        self.anomaly_drop_threshold = self._get_float('PROXY_HUNTER_ANOMALY_DROP', 0.5, min_val=0.1, max_val=0.9)
        self.max_history_runs = self._get_int('PROXY_HUNTER_MAX_HISTORY_RUNS', 100, min_val=10, max_val=1000)
        self.save_interval_seconds = self._get_int('PROXY_HUNTER_SAVE_INTERVAL', 30, min_val=5, max_val=300)
        self.encrypt_ips = self._get_bool('PROXY_HUNTER_ENCRYPT_IPS', True)
        self.encryption_salt = os.getenv('PROXY_HUNTER_ENCRYPTION_SALT', 'proxy_hunter_salt_2026')

        # =================================================================
        # НОВЫЕ НАСТРОЙКИ: Региональное тестирование
        # =================================================================
        self.target_region = os.getenv('TARGET_REGION', 'RU').upper()
        if self.target_region not in ('RU', 'CN', 'IR', 'GENERIC'):
            self.target_region = 'GENERIC'

        self.test_domain = os.getenv(
            'TEST_DOMAIN',
            _DEFAULT_TEST_DOMAINS.get(self.target_region, 'google.com')
        )
        self.xray_path = os.getenv('XRAY_PATH', 'xray')
        self.region_test_top_n = self._get_int('REGION_TEST_TOP_N', 50, min_val=0, max_val=500)
        self.region_test_timeout = self._get_float('REGION_TEST_TIMEOUT', 15.0, min_val=5.0, max_val=60.0)
        self.region_test_concurrency = self._get_int('REGION_TEST_CONCURRENCY', 3, min_val=1, max_val=10)
        self.skip_verification = self._get_bool('SKIP_VERIFICATION', False)

        # =================================================================
        # НОВЫЕ НАСТРОЙКИ: Модель выживания
        # =================================================================
        self.survival_states_path = os.getenv('SURVIVAL_STATES_PATH', 'configs/survival_states.json')
        self.survival_death_threshold = self._get_float('SURVIVAL_DEATH_THRESHOLD', 5.0, min_val=0.0, max_val=50.0)

        # =================================================================
        # НОВЫЕ НАСТРОЙКИ: Оценка цензуры
        # =================================================================
        self.censorship_stats_path = os.getenv('CENSORSHIP_STATS_PATH', 'configs/censorship_stats.json')

        # =================================================================
        # НОВЫЕ НАСТРОЙКИ: Статистика верификации
        # =================================================================
        self.verification_stats_path = os.getenv('VERIFICATION_STATS_PATH', 'configs/verification_stats.json')

        # =================================================================
        # НОВЫЕ НАСТРОЙКИ: Bloom-фильтр
        # =================================================================
        self.bloom_hmac_key = os.getenv('BLOOM_HMAC_KEY', 'fallback-dev-key-change-me')
        self.bloom_shards_dir = os.getenv('BLOOM_SHARDS_DIR', 'bloom_shards')

        # =================================================================
        # НОВЫЕ НАСТРОЙКИ: Пути к файлам
        # =================================================================
        self.db_path = os.getenv('DB_PATH', 'configs/history.db')
        self.output_archive = os.getenv('OUTPUT_ARCHIVE', 'configs/output_archive.txt')
        self.output_simple = os.getenv('OUTPUT_SIMPLE', 'configs/output_simple.txt')
        self.parsed_cache_path = os.getenv('PARSED_CACHE_PATH', 'configs/parsed_cache.json')

        # =================================================================
        # НОВЫЕ НАСТРОЙКИ: Скоринг / фильтрация
        # =================================================================
        self.min_score = self._get_float('MIN_SCORE', 30.0, min_val=0.0, max_val=100.0)
        self.min_score_fallback = self._get_float('MIN_SCORE_FALLBACK', 10.0, min_val=0.0, max_val=100.0)
        self.fetch_concurrency = self._get_int('FETCH_CONCURRENCY', 50, min_val=1, max_val=200)
        self.check_concurrency = self._get_int('CHECK_CONCURRENCY', 100, min_val=1, max_val=500)

        # =================================================================
        # НОВЫЕ НАСТРОЙКИ: ML
        # =================================================================
        self.model_path = os.getenv('MODEL_PATH', 'configs/model.cbm')
        self.feature_importance_path = os.getenv('FEATURE_IMPORTANCE_PATH', 'configs/feature_importance.json')

        logger.info(
            f"Settings loaded and validated. "
            f"region={self.target_region}, test_domain={self.test_domain}, "
            f"skip_verification={self.skip_verification}"
        )

    def _get_bool(self, key: str, default: bool) -> bool:
        val = os.getenv(key, str(default))
        return val.lower() in ('true', '1', 'yes', 'on')

    def _get_int(self, key: str, default: int, min_val: Optional[int] = None, max_val: Optional[int] = None) -> int:
        try:
            val = int(os.getenv(key, str(default)))
            if min_val is not None and val < min_val:
                logger.warning(f"{key}={val} below minimum {min_val}, using {default}")
                return default
            if max_val is not None and val > max_val:
                logger.warning(f"{key}={val} above maximum {max_val}, using {default}")
                return default
            return val
        except (ValueError, TypeError):
            logger.warning(f"Invalid int for {key}, using {default}")
            return default

    def _get_float(self, key: str, default: float, min_val: Optional[float] = None, max_val: Optional[float] = None) -> float:
        try:
            val = float(os.getenv(key, str(default)))
            if min_val is not None and val < min_val:
                logger.warning(f"{key}={val} below minimum {min_val}, using {default}")
                return default
            if max_val is not None and val > max_val:
                logger.warning(f"{key}={val} above maximum {max_val}, using {default}")
                return default
            return val
        except (ValueError, TypeError):
            logger.warning(f"Invalid float for {key}, using {default}")
            return default

    def _load_channels(self) -> List[str]:
        """Загружает каналы из файла или возвращает список по умолчанию."""
        channels = []
        if Path(CUSTOM_CHANNELS_FILE).exists():
            try:
                with open(CUSTOM_CHANNELS_FILE, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            norm = self._normalize_url(line)
                            if norm and norm not in channels:
                                channels.append(norm)
            except Exception as e:
                logger.warning(f"Failed to load channels from {CUSTOM_CHANNELS_FILE}: {e}")
        if not channels:
            logger.info("No custom channels found, using defaults.")
            channels = DEFAULT_SOURCE_URLS[:]
        return channels

    def _normalize_url(self, url: str) -> str:
        url = url.strip().lower()
        if not url:
            return ''
        if url.startswith('ssconf://'):
            url = url.replace('ssconf://', 'https://', 1)
        parsed = urlparse(url)
        if parsed.scheme and parsed.netloc:
            netloc = parsed.netloc.replace('www.', '')
            path = parsed.path.rstrip('/')
            return f"{parsed.scheme}://{netloc}{path}"
        return url

    def _validate_urls(self, urls: List[str]) -> List[str]:
        valid = []
        for u in urls:
            if u.startswith(('http://', 'https://', 'ssconf://')):
                valid.append(u)
            else:
                logger.warning(f"Invalid URL format: {u}, skipping")
        return valid

    def reload(self):
        """Перезагружает настройки (каналы и переменные окружения)."""
        self._load()
        logger.info("Settings reloaded.")

    @property
    def source_urls(self) -> List[str]:
        return self._source_urls

    @property
    def enabled_protocols(self) -> Dict[str, bool]:
        return self._enabled_protocols

    @enabled_protocols.setter
    def enabled_protocols(self, value):
        self._enabled_protocols = value

    def to_dict(self) -> dict:
        """Экспорт настроек в dict (для логирования/отладки)."""
        return {
            'target_region': self.target_region,
            'test_domain': self.test_domain,
            'xray_path': self.xray_path,
            'region_test_top_n': self.region_test_top_n,
            'skip_verification': self.skip_verification,
            'use_maximum_power': self.use_maximum_power,
            'specific_config_count': self.specific_config_count,
            'tcp_timeout': self.tcp_timeout,
            'http_timeout': self.http_timeout,
            'max_latency_ms': self.max_latency_ms,
            'active_checker_workers': self.active_checker_workers,
            'telegram_calls_per_second': self.telegram_calls_per_second,
            'min_score': self.min_score,
            'min_score_fallback': self.min_score_fallback,
        }


# =============================================================================
# Глобальный экземпляр для обратной совместимости
# =============================================================================
_settings = Settings()


# =============================================================================
# ЭКСПОРТ ГЛОБАЛЬНЫХ ПЕРЕМЕННЫХ
# Все переменные, которые импортируются другими модулями проекта.
# config.py, fetch_configs.py, active_checker.py и др.
# =============================================================================

# --- config.py импортирует: ---
SOURCE_URLS = _settings.source_urls
USE_MAXIMUM_POWER = _settings.use_maximum_power
SPECIFIC_CONFIG_COUNT = _settings.specific_config_count
MAX_CONFIG_AGE_DAYS = _settings.max_config_age_days
ENABLED_PROTOCOLS = _settings.enabled_protocols
CHANNEL_HEALTH_THRESHOLD = _settings.channel_health_threshold

# --- fetch_configs.py импортирует: ---
CHANNEL_RETRY_ATTEMPTS = _settings.channel_retry_attempts
CHANNEL_RETRY_BASE_DELAY = _settings.channel_retry_base_delay
CHANNEL_RETRY_MAX_DELAY = _settings.channel_retry_max_delay
CHANNEL_RETRY_DEADLINE = _settings.channel_retry_deadline
TELEGRAM_CALLS_PER_SECOND = _settings.telegram_calls_per_second
MAX_RESPONSE_SIZE_BYTES = _settings.max_response_size_bytes

# --- active_checker.py импортирует: ---
TCP_TIMEOUT = _settings.tcp_timeout
HTTP_TIMEOUT = _settings.http_timeout
MAX_LATENCY_MS = _settings.max_latency_ms
ACTIVE_CHECKER_WORKERS = _settings.active_checker_workers
PER_HOST_LIMIT = _settings.per_host_limit

# --- channel_quality_analyzer.py импортирует: ---
CHANNEL_MIN_CONFIGS = _settings.channel_min_configs
CHANNEL_MIN_VALID_RATIO = _settings.channel_min_valid_ratio
CHANNEL_MIN_PROTOCOLS = _settings.channel_min_protocols
CHANNEL_HISTORY_DAYS = _settings.channel_history_days
CHANNEL_RECOVERING_TREND_THRESHOLD = _settings.channel_recovering_trend_threshold
CHANNEL_MIN_RECENT_DAYS_FOR_TREND = _settings.channel_min_recent_days_for_trend
CHANNEL_WHITELIST = _settings.channel_whitelist
SCORE_WEIGHTS = _settings.score_weights
DECAY_PERIOD_HOURS = _settings.decay_period_hours
MIN_RUNS_FOR_ADAPTIVE_THRESHOLDS = _settings.min_runs_for_adaptive_thresholds
ANOMALY_Z_SCORE_THRESHOLD = _settings.anomaly_z_score_threshold
ANOMALY_IQR_MULTIPLIER = _settings.anomaly_iqr_multiplier
ANOMALY_DROP_THRESHOLD = _settings.anomaly_drop_threshold
MAX_HISTORY_RUNS = _settings.max_history_runs
SAVE_INTERVAL_SECONDS = _settings.save_interval_seconds
ENCRYPT_IPS = _settings.encrypt_ips
ENCRYPTION_SALT = _settings.encryption_salt

# --- НОВЫЕ переменные (для pipeline_optimized.py, region_tester.py и др.): ---
TARGET_REGION = _settings.target_region
TEST_DOMAIN = _settings.test_domain
XRAY_PATH = _settings.xray_path
REGION_TEST_TOP_N = _settings.region_test_top_n
REGION_TEST_TIMEOUT = _settings.region_test_timeout
REGION_TEST_CONCURRENCY = _settings.region_test_concurrency
SKIP_VERIFICATION = _settings.skip_verification
SURVIVAL_STATES_PATH = _settings.survival_states_path
SURVIVAL_DEATH_THRESHOLD = _settings.survival_death_threshold
CENSORSHIP_STATS_PATH = _settings.censorship_stats_path
VERIFICATION_STATS_PATH = _settings.verification_stats_path
BLOOM_HMAC_KEY = _settings.bloom_hmac_key
BLOOM_SHARDS_DIR = _settings.bloom_shards_dir
DB_PATH = _settings.db_path
OUTPUT_ARCHIVE = _settings.output_archive
OUTPUT_SIMPLE = _settings.output_simple
PARSED_CACHE_PATH = _settings.parsed_cache_path
MIN_SCORE = _settings.min_score
MIN_SCORE_FALLBACK = _settings.min_score_fallback
FETCH_CONCURRENCY = _settings.fetch_concurrency
CHECK_CONCURRENCY = _settings.check_concurrency
MODEL_PATH = _settings.model_path
FEATURE_IMPORTANCE_PATH = _settings.feature_importance_path


# =============================================================================
# Функция доступа к синглтону (для нового кода)
# =============================================================================
def get_settings() -> Settings:
    """Возвращает синглтон настроек."""
    return _settings


# =============================================================================
# Функция перезагрузки (обновляет ВСЕ глобальные переменные)
# =============================================================================
def reload_settings():
    """Перезагружает настройки и обновляет все глобальные переменные."""
    _settings.reload()

    # Обновляем ВСЕ глобальные переменные
    global SOURCE_URLS, USE_MAXIMUM_POWER, SPECIFIC_CONFIG_COUNT, MAX_CONFIG_AGE_DAYS
    global ENABLED_PROTOCOLS, CHANNEL_HEALTH_THRESHOLD
    global CHANNEL_RETRY_ATTEMPTS, CHANNEL_RETRY_BASE_DELAY, CHANNEL_RETRY_MAX_DELAY
    global CHANNEL_RETRY_DEADLINE, TELEGRAM_CALLS_PER_SECOND, MAX_RESPONSE_SIZE_BYTES
    global TCP_TIMEOUT, HTTP_TIMEOUT, MAX_LATENCY_MS, ACTIVE_CHECKER_WORKERS, PER_HOST_LIMIT
    global CHANNEL_MIN_CONFIGS, CHANNEL_MIN_VALID_RATIO, CHANNEL_MIN_PROTOCOLS
    global CHANNEL_HISTORY_DAYS, CHANNEL_RECOVERING_TREND_THRESHOLD
    global CHANNEL_MIN_RECENT_DAYS_FOR_TREND, CHANNEL_WHITELIST, SCORE_WEIGHTS
    global DECAY_PERIOD_HOURS, MIN_RUNS_FOR_ADAPTIVE_THRESHOLDS
    global ANOMALY_Z_SCORE_THRESHOLD, ANOMALY_IQR_MULTIPLIER, ANOMALY_DROP_THRESHOLD
    global MAX_HISTORY_RUNS, SAVE_INTERVAL_SECONDS, ENCRYPT_IPS, ENCRYPTION_SALT
    global TARGET_REGION, TEST_DOMAIN, XRAY_PATH, REGION_TEST_TOP_N
    global REGION_TEST_TIMEOUT, REGION_TEST_CONCURRENCY, SKIP_VERIFICATION
    global SURVIVAL_STATES_PATH, SURVIVAL_DEATH_THRESHOLD
    global CENSORSHIP_STATS_PATH, VERIFICATION_STATS_PATH
    global BLOOM_HMAC_KEY, BLOOM_SHARDS_DIR
    global DB_PATH, OUTPUT_ARCHIVE, OUTPUT_SIMPLE, PARSED_CACHE_PATH
    global MIN_SCORE, MIN_SCORE_FALLBACK, FETCH_CONCURRENCY, CHECK_CONCURRENCY
    global MODEL_PATH, FEATURE_IMPORTANCE_PATH

    # Оригинальные переменные
    SOURCE_URLS = _settings.source_urls
    USE_MAXIMUM_POWER = _settings.use_maximum_power
    SPECIFIC_CONFIG_COUNT = _settings.specific_config_count
    MAX_CONFIG_AGE_DAYS = _settings.max_config_age_days
    ENABLED_PROTOCOLS = _settings.enabled_protocols
    CHANNEL_HEALTH_THRESHOLD = _settings.channel_health_threshold

    CHANNEL_RETRY_ATTEMPTS = _settings.channel_retry_attempts
    CHANNEL_RETRY_BASE_DELAY = _settings.channel_retry_base_delay
    CHANNEL_RETRY_MAX_DELAY = _settings.channel_retry_max_delay
    CHANNEL_RETRY_DEADLINE = _settings.channel_retry_deadline
    TELEGRAM_CALLS_PER_SECOND = _settings.telegram_calls_per_second
    MAX_RESPONSE_SIZE_BYTES = _settings.max_response_size_bytes

    TCP_TIMEOUT = _settings.tcp_timeout
    HTTP_TIMEOUT = _settings.http_timeout
    MAX_LATENCY_MS = _settings.max_latency_ms
    ACTIVE_CHECKER_WORKERS = _settings.active_checker_workers
    PER_HOST_LIMIT = _settings.per_host_limit

    CHANNEL_MIN_CONFIGS = _settings.channel_min_configs
    CHANNEL_MIN_VALID_RATIO = _settings.channel_min_valid_ratio
    CHANNEL_MIN_PROTOCOLS = _settings.channel_min_protocols
    CHANNEL_HISTORY_DAYS = _settings.channel_history_days
    CHANNEL_RECOVERING_TREND_THRESHOLD = _settings.channel_recovering_trend_threshold
    CHANNEL_MIN_RECENT_DAYS_FOR_TREND = _settings.channel_min_recent_days_for_trend
    CHANNEL_WHITELIST = _settings.channel_whitelist
    SCORE_WEIGHTS = _settings.score_weights
    DECAY_PERIOD_HOURS = _settings.decay_period_hours
    MIN_RUNS_FOR_ADAPTIVE_THRESHOLDS = _settings.min_runs_for_adaptive_thresholds
    ANOMALY_Z_SCORE_THRESHOLD = _settings.anomaly_z_score_threshold
    ANOMALY_IQR_MULTIPLIER = _settings.anomaly_iqr_multiplier
    ANOMALY_DROP_THRESHOLD = _settings.anomaly_drop_threshold
    MAX_HISTORY_RUNS = _settings.max_history_runs
    SAVE_INTERVAL_SECONDS = _settings.save_interval_seconds
    ENCRYPT_IPS = _settings.encrypt_ips
    ENCRYPTION_SALT = _settings.encryption_salt

    # Новые переменные
    TARGET_REGION = _settings.target_region
    TEST_DOMAIN = _settings.test_domain
    XRAY_PATH = _settings.xray_path
    REGION_TEST_TOP_N = _settings.region_test_top_n
    REGION_TEST_TIMEOUT = _settings.region_test_timeout
    REGION_TEST_CONCURRENCY = _settings.region_test_concurrency
    SKIP_VERIFICATION = _settings.skip_verification
    SURVIVAL_STATES_PATH = _settings.survival_states_path
    SURVIVAL_DEATH_THRESHOLD = _settings.survival_death_threshold
    CENSORSHIP_STATS_PATH = _settings.censorship_stats_path
    VERIFICATION_STATS_PATH = _settings.verification_stats_path
    BLOOM_HMAC_KEY = _settings.bloom_hmac_key
    BLOOM_SHARDS_DIR = _settings.bloom_shards_dir
    DB_PATH = _settings.db_path
    OUTPUT_ARCHIVE = _settings.output_archive
    OUTPUT_SIMPLE = _settings.output_simple
    PARSED_CACHE_PATH = _settings.parsed_cache_path
    MIN_SCORE = _settings.min_score
    MIN_SCORE_FALLBACK = _settings.min_score_fallback
    FETCH_CONCURRENCY = _settings.fetch_concurrency
    CHECK_CONCURRENCY = _settings.check_concurrency
    MODEL_PATH = _settings.model_path
    FEATURE_IMPORTANCE_PATH = _settings.feature_importance_path
