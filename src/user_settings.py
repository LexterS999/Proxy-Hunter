"""
Настройки проекта с валидацией и единой точкой загрузки.
Все константы задокументированы.
"""

import os
import re
import logging
from urllib.parse import urlparse
from typing import List, Optional, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)

# ============================================================================
# ИСТОЧНИКИ КОНФИГУРАЦИЙ
# ============================================================================

DEFAULT_SOURCE_URLS = [
    "https://t.me/s/SOSkeyNET",
    "https://t.me/s/GozargahAzad",
    "https://t.me/s/generalconfiig",
    "https://t.me/s/kurdconfig",
    "https://t.me/s/MiTiVPN",
    "https://t.me/s/WangCai2",
]

CUSTOM_CHANNELS_FILE = 'custom_channels.txt'


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
        self._source_urls = self._load_channels()
        self._source_urls = self._validate_urls(self._source_urls)

        self.use_maximum_power = self._get_bool('PROXY_HUNTER_USE_MAXIMUM_POWER', True)
        self.specific_config_count = self._get_int('PROXY_HUNTER_SPECIFIC_CONFIG_COUNT', 5000, min_val=1, max_val=50000)
        self.max_config_age_days = self._get_int('PROXY_HUNTER_MAX_CONFIG_AGE_DAYS', 14, min_val=1, max_val=90)

        self.enabled_protocols = {
            "wireguard://": self._get_bool('PROXY_HUNTER_ENABLE_WIREGUARD', False),
            "hysteria2://": self._get_bool('PROXY_HUNTER_ENABLE_HYSTERIA2', True),
            "vless://": self._get_bool('PROXY_HUNTER_ENABLE_VLESS', True),
            "vmess://": self._get_bool('PROXY_HUNTER_ENABLE_VMESS', True),
            "ss://": self._get_bool('PROXY_HUNTER_ENABLE_SS', True),
            "trojan://": self._get_bool('PROXY_HUNTER_ENABLE_TROJAN', True),
            "tuic://": self._get_bool('PROXY_HUNTER_ENABLE_TUIC', False),
        }

        self.tcp_timeout = self._get_float('PROXY_HUNTER_TCP_TIMEOUT', 5.0, min_val=0.5, max_val=30.0)
        self.http_timeout = self._get_float('PROXY_HUNTER_HTTP_TIMEOUT', 5.0, min_val=0.5, max_val=30.0)
        self.max_latency_ms = self._get_float('PROXY_HUNTER_MAX_LATENCY', 6000.0, min_val=100.0, max_val=60000.0)
        self.active_checker_workers = self._get_int('PROXY_HUNTER_ACTIVE_WORKERS', 100, min_val=1, max_val=500)
        self.per_host_limit = self._get_int('PROXY_HUNTER_PER_HOST_LIMIT', 10, min_val=1, max_val=50)

        self.telegram_calls_per_second = self._get_float('PROXY_HUNTER_TELEGRAM_RATE', 1.5, min_val=0.1, max_val=10.0)
        self.max_response_size_bytes = self._get_int('PROXY_HUNTER_MAX_RESPONSE_SIZE', 1048576,
                                                     min_val=65536, max_val=10485760)

        self.channel_retry_attempts = self._get_int('PROXY_HUNTER_CHANNEL_RETRIES', 3, min_val=1, max_val=10)
        self.channel_retry_base_delay = self._get_float('PROXY_HUNTER_CHANNEL_RETRY_DELAY', 0.5, min_val=0.1, max_val=10.0)
        self.channel_retry_max_delay = self._get_float('PROXY_HUNTER_CHANNEL_RETRY_MAX_DELAY', 10.0,
                                                       min_val=1.0, max_val=60.0)
        self.channel_retry_deadline = self._get_float('PROXY_HUNTER_CHANNEL_RETRY_DEADLINE', 60.0,
                                                      min_val=10.0, max_val=300.0)

        self.channel_health_threshold = self._get_float('PROXY_HUNTER_CHANNEL_HEALTH_THRESHOLD', 30.0,
                                                        min_val=0.0, max_val=100.0)
        self.channel_min_configs = self._get_int('PROXY_HUNTER_CHANNEL_MIN_CONFIGS', 3, min_val=1, max_val=100)
        self.channel_min_valid_ratio = self._get_float('PROXY_HUNTER_CHANNEL_MIN_VALID_RATIO', 0.05,
                                                       min_val=0.0, max_val=1.0)
        self.channel_min_protocols = self._get_int('PROXY_HUNTER_CHANNEL_MIN_PROTOCOLS', 1, min_val=1, max_val=10)
        self.channel_history_days = self._get_int('PROXY_HUNTER_CHANNEL_HISTORY_DAYS', 7, min_val=3, max_val=30)
        self.channel_recovering_trend_threshold = self._get_float('PROXY_HUNTER_RECOVERING_TREND_THRESHOLD',
                                                                  0.1, min_val=0.01, max_val=0.5)
        self.channel_min_recent_days_for_trend = self._get_int('PROXY_HUNTER_MIN_RECENT_DAYS_FOR_TREND',
                                                               2, min_val=1, max_val=7)

        whitelist_raw = os.getenv('PROXY_HUNTER_CHANNEL_WHITELIST', '')
        self.channel_whitelist = [url.strip() for url in whitelist_raw.split(',') if url.strip()]

        self.score_weights = {
            'stability': self._get_float('PROXY_HUNTER_WEIGHT_STABILITY', 0.3, min_val=0, max_val=1),
            'success_rate': self._get_float('PROXY_HUNTER_WEIGHT_SUCCESS_RATE', 0.25, min_val=0, max_val=1),
            'reputation': self._get_float('PROXY_HUNTER_WEIGHT_REPUTATION', 0.2, min_val=0, max_val=1),
            'lifetime': self._get_float('PROXY_HUNTER_WEIGHT_LIFETIME', 0.15, min_val=0, max_val=1),
            'config_quality': self._get_float('PROXY_HUNTER_WEIGHT_CONFIG_QUALITY', 0.1, min_val=0, max_val=1),
        }
        total = sum(self.score_weights.values())
        if total > 0:
            for k in self.score_weights:
                self.score_weights[k] /= total

        self.decay_period_hours = self._get_float('PROXY_HUNTER_DECAY_PERIOD', 24.0, min_val=1, max_val=720)
        self.min_runs_for_adaptive_thresholds = self._get_int('PROXY_HUNTER_MIN_RUNS_ADAPTIVE', 9, min_val=3, max_val=50)
        self.anomaly_z_score_threshold = self._get_float('PROXY_HUNTER_ANOMALY_Z_SCORE', 2.5, min_val=1.0, max_val=5.0)
        self.anomaly_iqr_multiplier = self._get_float('PROXY_HUNTER_ANOMALY_IQR', 1.5, min_val=0.5, max_val=3.0)
        self.anomaly_drop_threshold = self._get_float('PROXY_HUNTER_ANOMALY_DROP', 0.5, min_val=0.1, max_val=0.9)
        self.max_history_runs = self._get_int('PROXY_HUNTER_MAX_HISTORY_RUNS', 100, min_val=10, max_val=1000)
        self.save_interval_seconds = self._get_int('PROXY_HUNTER_SAVE_INTERVAL', 30, min_val=5, max_val=300)
        self.encrypt_ips = self._get_bool('PROXY_HUNTER_ENCRYPT_IPS', True)
        self.encryption_salt = os.getenv('PROXY_HUNTER_ENCRYPTION_SALT', 'proxy_hunter_salt_2026')

        logger.info("Settings loaded and validated.")

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

    def generate_env_example(self):
        lines = []
        for attr in dir(self):
            if attr.startswith('_') or attr in ('generate_env_example', 'reload', 'write_env_example'):
                continue
            value = getattr(self, attr)
            if isinstance(value, (bool, int, float, str)):
                description = attr.replace('_', ' ').capitalize()
                lines.append(f"# {description}")
                lines.append(f"{attr.upper()}={value}")
                lines.append("")
        return "\n".join(lines)

    def write_env_example(self, path=".env.example"):
        with open(path, 'w') as f:
            f.write(self.generate_env_example())
        logger.info(f".env.example written to {path}")

    def reload(self):
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


_settings = Settings()

SOURCE_URLS = _settings.source_urls
USE_MAXIMUM_POWER = _settings.use_maximum_power
SPECIFIC_CONFIG_COUNT = _settings.specific_config_count
MAX_CONFIG_AGE_DAYS = _settings.max_config_age_days
ENABLED_PROTOCOLS = _settings.enabled_protocols
TCP_TIMEOUT = _settings.tcp_timeout
HTTP_TIMEOUT = _settings.http_timeout
MAX_LATENCY_MS = _settings.max_latency_ms
ACTIVE_CHECKER_WORKERS = _settings.active_checker_workers
PER_HOST_LIMIT = _settings.per_host_limit
TELEGRAM_CALLS_PER_SECOND = _settings.telegram_calls_per_second
MAX_RESPONSE_SIZE_BYTES = _settings.max_response_size_bytes
CHANNEL_RETRY_ATTEMPTS = _settings.channel_retry_attempts
CHANNEL_RETRY_BASE_DELAY = _settings.channel_retry_base_delay
CHANNEL_RETRY_MAX_DELAY = _settings.channel_retry_max_delay
CHANNEL_RETRY_DEADLINE = _settings.channel_retry_deadline
CHANNEL_HEALTH_THRESHOLD = _settings.channel_health_threshold
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


def reload_settings():
    _settings.reload()
    global SOURCE_URLS, USE_MAXIMUM_POWER, SPECIFIC_CONFIG_COUNT, MAX_CONFIG_AGE_DAYS
    global ENABLED_PROTOCOLS, TCP_TIMEOUT, HTTP_TIMEOUT, MAX_LATENCY_MS, ACTIVE_CHECKER_WORKERS
    global PER_HOST_LIMIT, TELEGRAM_CALLS_PER_SECOND, MAX_RESPONSE_SIZE_BYTES
    global CHANNEL_RETRY_ATTEMPTS, CHANNEL_RETRY_BASE_DELAY, CHANNEL_RETRY_MAX_DELAY, CHANNEL_RETRY_DEADLINE
    global CHANNEL_HEALTH_THRESHOLD, CHANNEL_MIN_CONFIGS, CHANNEL_MIN_VALID_RATIO, CHANNEL_MIN_PROTOCOLS
    global CHANNEL_HISTORY_DAYS, CHANNEL_RECOVERING_TREND_THRESHOLD, CHANNEL_MIN_RECENT_DAYS_FOR_TREND
    global CHANNEL_WHITELIST, SCORE_WEIGHTS, DECAY_PERIOD_HOURS, MIN_RUNS_FOR_ADAPTIVE_THRESHOLDS
    global ANOMALY_Z_SCORE_THRESHOLD, ANOMALY_IQR_MULTIPLIER, ANOMALY_DROP_THRESHOLD, MAX_HISTORY_RUNS
    global SAVE_INTERVAL_SECONDS, ENCRYPT_IPS, ENCRYPTION_SALT

    SOURCE_URLS = _settings.source_urls
    USE_MAXIMUM_POWER = _settings.use_maximum_power
    SPECIFIC_CONFIG_COUNT = _settings.specific_config_count
    MAX_CONFIG_AGE_DAYS = _settings.max_config_age_days
    ENABLED_PROTOCOLS = _settings.enabled_protocols
    TCP_TIMEOUT = _settings.tcp_timeout
    HTTP_TIMEOUT = _settings.http_timeout
    MAX_LATENCY_MS = _settings.max_latency_ms
    ACTIVE_CHECKER_WORKERS = _settings.active_checker_workers
    PER_HOST_LIMIT = _settings.per_host_limit
    TELEGRAM_CALLS_PER_SECOND = _settings.telegram_calls_per_second
    MAX_RESPONSE_SIZE_BYTES = _settings.max_response_size_bytes
    CHANNEL_RETRY_ATTEMPTS = _settings.channel_retry_attempts
    CHANNEL_RETRY_BASE_DELAY = _settings.channel_retry_base_delay
    CHANNEL_RETRY_MAX_DELAY = _settings.channel_retry_max_delay
    CHANNEL_RETRY_DEADLINE = _settings.channel_retry_deadline
    CHANNEL_HEALTH_THRESHOLD = _settings.channel_health_threshold
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


def generate_env_example():
    _settings.write_env_example()
