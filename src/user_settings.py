# ============================================================================
# Файл: src/user_settings.py (полностью обновлён с Pydantic и валидацией)
# ============================================================================
#!/usr/bin/env python3

"""
Файл пользовательских настроек для Proxy-Hunter с валидацией через Pydantic.
Все параметры сгруппированы по блокам и снабжены комментариями и дефолтными значениями.
"""

import os
import logging
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field, validator, root_validator
from pathlib import Path

logger = logging.getLogger(__name__)


# ============================================================================
# БЛОК: МОДЕЛИ НАСТРОЕК (Pydantic)
# ============================================================================

class NetworkSettings(BaseModel):
    """Сетевые параметры."""
    tcp_timeout: float = Field(3.0, ge=0.5, le=30.0, description="Таймаут TCP-соединения (секунды)")
    http_timeout: float = Field(3.0, ge=0.5, le=30.0, description="Таймаут HTTP-запроса (секунды)")
    max_latency_ms: float = Field(5000.0, ge=100.0, le=60000.0, description="Максимальная задержка (мс)")
    active_checker_workers: int = Field(80, ge=1, le=500, description="Количество воркеров для активной проверки")
    per_host_limit: int = Field(10, ge=1, le=50, description="Лимит соединений на хост")
    telegram_calls_per_second: float = Field(5.0, ge=0.1, le=10.0, description="Количество запросов к Telegram в секунду")
    max_response_size_bytes: int = Field(9_048_576, ge=65536, le=10485760, description="Максимальный размер ответа (байт)")


class RetrySettings(BaseModel):
    """Настройки повторных попыток."""
    channel_retry_attempts: int = Field(3, ge=1, le=10, description="Количество попыток загрузки канала")
    channel_retry_base_delay: float = Field(0.5, ge=0.1, le=10.0, description="Начальная задержка между попытками (секунды)")
    channel_retry_max_delay: float = Field(10.0, ge=1.0, le=60.0, description="Максимальная задержка между попытками (секунды)")
    channel_retry_deadline: float = Field(5.0, ge=1.0, le=300.0, description="Общее время на все попытки (секунды)")


class ScoringSettings(BaseModel):
    """Настройки скоринга."""
    score_min_threshold: float = Field(30.0, ge=0.0, le=100.0, description="Минимальный балл для финального вывода")
    score_weights: Dict[str, float] = Field(
        default={
            "stability": 0.30,
            "success_rate": 0.25,
            "reputation": 0.20,
            "lifetime": 0.15,
            "config_quality": 0.10,
        },
        description="Веса для расчёта итогового балла"
    )
    decay_period_hours: float = Field(24.0, ge=1.0, le=720.0, description="Период полураспада для истории (часы)")


class ChannelSettings(BaseModel):
    """Настройки каналов."""
    source_urls: List[str] = Field(
        default=[
            "https://t.me/s/SOSkeyNET",
            "https://t.me/s/GozargahAzad",
            "https://t.me/s/generalconfiig",
            "https://t.me/s/kurdconfig",
            "https://t.me/s/MiTiVPN",
            "https://t.me/s/WangCai2",
        ],
        description="Список URL Telegram-каналов"
    )
    custom_channels_file: str = Field("custom_channels.txt", description="Файл с пользовательскими каналами")
    use_maximum_power: bool = Field(True, description="Собирать максимум конфигов")
    specific_config_count: int = Field(5000, ge=1, le=50000, description="Целевое количество конфигов")
    channel_health_threshold: float = Field(30.0, ge=0.0, le=100.0, description="Порог здоровья канала")
    channel_min_configs: int = Field(3, ge=1, le=100, description="Минимальное число конфигов для канала")
    channel_min_valid_ratio: float = Field(0.05, ge=0.0, le=1.0, description="Минимальная доля валидных конфигов")
    channel_min_protocols: int = Field(1, ge=1, le=10, description="Минимальное число протоколов в канале")
    channel_history_days: int = Field(7, ge=3, le=30, description="Количество дней истории для анализа канала")
    channel_recovering_trend_threshold: float = Field(0.1, ge=0.01, le=0.5, description="Порог тренда для восстановления канала")
    channel_min_recent_days_for_trend: int = Field(2, ge=1, le=7, description="Минимальное число дней для расчёта тренда")
    channel_whitelist: List[str] = Field(default=[], description="Белый список каналов")
    max_config_age_days: int = Field(14, ge=1, le=90, description="Максимальный возраст конфигурации (дни)")
    archive_max_age_days: int = Field(14, ge=1, le=90, description="Максимальный возраст для архива (дни)")
    simple_max_age_days: int = Field(3, ge=1, le=30, description="Максимальный возраст для простого вывода (дни)")


class DatabaseSettings(BaseModel):
    """Настройки базы данных."""
    db_path: str = Field("configs/history.db", description="Путь к базе данных")
    max_history_runs: int = Field(100, ge=10, le=1000, description="Максимальное число записей в истории")
    save_interval_seconds: int = Field(30, ge=5, le=300, description="Интервал автосохранения (секунды)")
    encrypt_ips: bool = Field(True, description="Шифровать IP-адреса в истории")
    encryption_salt: str = Field("proxy_hunter_salt_2026", description="Соль для шифрования IP")
    auto_cleanup_days: int = Field(30, ge=7, le=365, description="Автоматическая очистка данных старше (дни)")


class DatacenterSettings(BaseModel):
    """Настройки детекции датацентров."""
    geolite2_asn_path: str = Field("configs/GeoLite2-ASN.mmdb", description="Путь к базе MaxMind GeoLite2 ASN")
    builtin_datacenter_asns: Dict[str, str] = Field(
        default={
            "AS16509": "AWS",
            "AS14618": "AWS",
            "AS15169": "Google",
            "AS396982": "Google",
            "AS8075": "Microsoft",
            "AS8068": "Microsoft",
            "AS13335": "Cloudflare",
            "AS14061": "DigitalOcean",
            "AS24940": "Hetzner",
            "AS16276": "OVH",
            "AS45102": "Alibaba",
            "AS31898": "Oracle",
            "AS54113": "Fastly",
            "AS20940": "Akamai",
            "AS63949": "Linode",
            "AS133752": "Leaseweb",
            "AS20473": "Vultr",
        },
        description="Встроенный список ASN датацентров"
    )


class ProtocolSettings(BaseModel):
    """Настройки протоколов."""
    enabled_protocols: Dict[str, bool] = Field(
        default={
            "wireguard://": False,
            "hysteria2://": True,
            "vless://": True,
            "vmess://": True,
            "ss://": True,
            "trojan://": True,
            "tuic://": False,
        },
        description="Включённые протоколы"
    )


class AdvancedSettings(BaseModel):
    """Расширенные настройки."""
    min_runs_for_adaptive_thresholds: int = Field(9, ge=3, le=50, description="Минимальное число запусков для адаптивных порогов")
    anomaly_z_score_threshold: float = Field(2.5, ge=1.0, le=5.0, description="Порог Z-скора для аномалий")
    anomaly_iqr_multiplier: float = Field(1.5, ge=0.5, le=3.0, description="Множитель IQR для аномалий")
    anomaly_drop_threshold: float = Field(0.5, ge=0.1, le=0.9, description="Порог падения скора для аномалий")
    grace_period_runs: int = Field(5, ge=1, le=20, description="Количество запусков для карантина канала")
    adaptive_threshold_percentile: int = Field(20, ge=5, le=50, description="Процентиль для адаптивного порога")
    min_records_for_adaptive: int = Field(10, ge=3, le=50, description="Минимальное число записей для адаптивного порога")


class Settings(BaseModel):
    """Основная модель настроек Proxy-Hunter."""
    network: NetworkSettings = Field(default_factory=NetworkSettings)
    retry: RetrySettings = Field(default_factory=RetrySettings)
    scoring: ScoringSettings = Field(default_factory=ScoringSettings)
    channels: ChannelSettings = Field(default_factory=ChannelSettings)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    datacenter: DatacenterSettings = Field(default_factory=DatacenterSettings)
    protocols: ProtocolSettings = Field(default_factory=ProtocolSettings)
    advanced: AdvancedSettings = Field(default_factory=AdvancedSettings)

    @validator("score_weights")
    def validate_score_weights(cls, v: Dict[str, float]) -> Dict[str, float]:
        total = sum(v.values())
        if not (0.99 <= total <= 1.01):
            raise ValueError(f"Сумма весов должна быть равна 1.0, текущая: {total}")
        return v

    @root_validator
    def validate_all(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        if values.get("network").active_checker_workers > 200:
            logger.warning("ACTIVE_CHECKER_WORKERS > 200 может вызвать перегрузку сети")
        return values


# ============================================================================
# ЗАГРУЗКА НАСТРОЕК ИЗ ПЕРЕМЕННЫХ ОКРУЖЕНИЯ
# ============================================================================

def _load_channels_from_file(file_path: str) -> List[str]:
    """Загружает каналы из файла."""
    channels: List[str] = []
    if Path(file_path).exists():
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        channels.append(line)
        except Exception as e:
            logger.warning(f"Не удалось загрузить каналы из {file_path}: {e}")
    return channels


def _get_env_value(key: str, default: Any, field_type: type) -> Any:
    """Получает значение из переменной окружения с валидацией."""
    env_value = os.getenv(key)
    if env_value is None:
        return default
    try:
        if field_type == bool:
            return env_value.lower() in ("true", "1", "yes", "on")
        elif field_type == int:
            return int(env_value)
        elif field_type == float:
            return float(env_value)
        else:
            return env_value
    except (ValueError, TypeError):
        logger.warning(f"Некорректное значение для {key}: {env_value}. Используется дефолт: {default}")
        return default


def load_settings() -> Settings:
    """Загружает настройки из переменных окружения и файлов."""
    # Загружаем каналы из файла
    custom_channels = _load_channels_from_file("custom_channels.txt")
    default_channels = [
        "https://t.me/s/SOSkeyNET",
        "https://t.me/s/GozargahAzad",
        "https://t.me/s/generalconfiig",
        "https://t.me/s/kurdconfig",
        "https://t.me/s/MiTiVPN",
        "https://t.me/s/WangCai2",
    ]
    source_urls = custom_channels if custom_channels else default_channels

    # Создаём базовые настройки
    settings = Settings(
        channels=ChannelSettings(source_urls=source_urls),
    )

    # Переопределяем настройки из переменных окружения
    # Сетевые настройки
    settings.network.tcp_timeout = _get_env_value(
        "PROXY_CHECK_TCP_TIMEOUT", settings.network.tcp_timeout, float
    )
    settings.network.http_timeout = _get_env_value(
        "PROXY_CHECK_HTTP_TIMEOUT", settings.network.http_timeout, float
    )
    settings.network.max_latency_ms = _get_env_value(
        "PROXY_MAX_LATENCY_MS", settings.network.max_latency_ms, float
    )
    settings.network.active_checker_workers = _get_env_value(
        "PROXY_ACTIVE_CHECKER_WORKERS", settings.network.active_checker_workers, int
    )
    settings.network.per_host_limit = _get_env_value(
        "PROXY_PER_HOST_LIMIT", settings.network.per_host_limit, int
    )
    settings.network.telegram_calls_per_second = _get_env_value(
        "PROXY_TELEGRAM_CALLS_PER_SECOND", settings.network.telegram_calls_per_second, float
    )
    settings.network.max_response_size_bytes = _get_env_value(
        "PROXY_MAX_RESPONSE_SIZE_BYTES", settings.network.max_response_size_bytes, int
    )

    # Настройки повторных попыток
    settings.retry.channel_retry_attempts = _get_env_value(
        "PROXY_CHANNEL_RETRY_ATTEMPTS", settings.retry.channel_retry_attempts, int
    )
    settings.retry.channel_retry_base_delay = _get_env_value(
        "PROXY_CHANNEL_RETRY_BASE_DELAY", settings.retry.channel_retry_base_delay, float
    )
    settings.retry.channel_retry_max_delay = _get_env_value(
        "PROXY_CHANNEL_RETRY_MAX_DELAY", settings.retry.channel_retry_max_delay, float
    )
    settings.retry.channel_retry_deadline = _get_env_value(
        "PROXY_CHANNEL_RETRY_DEADLINE", settings.retry.channel_retry_deadline, float
    )

    # Настройки скоринга
    settings.scoring.score_min_threshold = _get_env_value(
        "PROXY_SCORE_MIN_THRESHOLD", settings.scoring.score_min_threshold, float
    )
    settings.scoring.decay_period_hours = _get_env_value(
        "PROXY_DECAY_PERIOD_HOURS", settings.scoring.decay_period_hours, float
    )

    # Настройки каналов
    settings.channels.use_maximum_power = _get_env_value(
        "PROXY_USE_MAXIMUM_POWER", settings.channels.use_maximum_power, bool
    )
    settings.channels.specific_config_count = _get_env_value(
        "PROXY_SPECIFIC_CONFIG_COUNT", settings.channels.specific_config_count, int
    )
    settings.channels.channel_health_threshold = _get_env_value(
        "PROXY_CHANNEL_HEALTH_THRESHOLD", settings.channels.channel_health_threshold, float
    )
    settings.channels.max_config_age_days = _get_env_value(
        "PROXY_MAX_CONFIG_AGE_DAYS", settings.channels.max_config_age_days, int
    )
    settings.channels.archive_max_age_days = _get_env_value(
        "PROXY_ARCHIVE_MAX_AGE_DAYS", settings.channels.archive_max_age_days, int
    )
    settings.channels.simple_max_age_days = _get_env_value(
        "PROXY_SIMPLE_MAX_AGE_DAYS", settings.channels.simple_max_age_days, int
    )

    # Настройки БД
    settings.database.db_path = _get_env_value(
        "PROXY_DB_PATH", settings.database.db_path, str
    )
    settings.database.max_history_runs = _get_env_value(
        "PROXY_MAX_HISTORY_RUNS", settings.database.max_history_runs, int
    )
    settings.database.save_interval_seconds = _get_env_value(
        "PROXY_SAVE_INTERVAL_SECONDS", settings.database.save_interval_seconds, int
    )
    settings.database.encrypt_ips = _get_env_value(
        "PROXY_ENCRYPT_IPS", settings.database.encrypt_ips, bool
    )
    settings.database.encryption_salt = _get_env_value(
        "PROXY_ENCRYPTION_SALT", settings.database.encryption_salt, str
    )
    settings.database.auto_cleanup_days = _get_env_value(
        "PROXY_AUTO_CLEANUP_DAYS", settings.database.auto_cleanup_days, int
    )

    # Настройки датацентров
    settings.datacenter.geolite2_asn_path = _get_env_value(
        "PROXY_GEOLITE2_ASN_PATH", settings.datacenter.geolite2_asn_path, str
    )

    # Расширенные настройки
    settings.advanced.min_runs_for_adaptive_thresholds = _get_env_value(
        "PROXY_MIN_RUNS_FOR_ADAPTIVE_THRESHOLDS", settings.advanced.min_runs_for_adaptive_thresholds, int
    )
    settings.advanced.grace_period_runs = _get_env_value(
        "PROXY_GRACE_PERIOD_RUNS", settings.advanced.grace_period_runs, int
    )

    # Валидируем настройки
    settings.validate()
    return settings


# Глобальный экземпляр настроек
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Возвращает глобальный экземпляр настроек."""
    global _settings
    if _settings is None:
        _settings = load_settings()
    return _settings


def reload_settings() -> Settings:
    """Перезагружает настройки из переменных окружения и файлов."""
    global _settings
    _settings = load_settings()
    return _settings


# ============================================================================
# СОВМЕСТИМОСТЬ С СТАРЫМ КОДОМ (переменные для обратной совместимости)
# ============================================================================

settings = get_settings()

# Сетевые параметры
TCP_TIMEOUT = settings.network.tcp_timeout
HTTP_TIMEOUT = settings.network.http_timeout
MAX_LATENCY_MS = settings.network.max_latency_ms
ACTIVE_CHECKER_WORKERS = settings.network.active_checker_workers
PER_HOST_LIMIT = settings.network.per_host_limit
TELEGRAM_CALLS_PER_SECOND = settings.network.telegram_calls_per_second
MAX_RESPONSE_SIZE_BYTES = settings.network.max_response_size_bytes

# Настройки повторных попыток
CHANNEL_RETRY_ATTEMPTS = settings.retry.channel_retry_attempts
CHANNEL_RETRY_BASE_DELAY = settings.retry.channel_retry_base_delay
CHANNEL_RETRY_MAX_DELAY = settings.retry.channel_retry_max_delay
CHANNEL_RETRY_DEADLINE = settings.retry.channel_retry_deadline

# Настройки скоринга
SCORE_MIN_THRESHOLD = settings.scoring.score_min_threshold
SCORE_WEIGHTS = settings.scoring.score_weights
DECAY_PERIOD_HOURS = settings.scoring.decay_period_hours

# Настройки каналов
SOURCE_URLS = settings.channels.source_urls
USE_MAXIMUM_POWER = settings.channels.use_maximum_power
SPECIFIC_CONFIG_COUNT = settings.channels.specific_config_count
CHANNEL_HEALTH_THRESHOLD = settings.channels.channel_health_threshold
CHANNEL_MIN_CONFIGS = settings.channels.channel_min_configs
CHANNEL_MIN_VALID_RATIO = settings.channels.channel_min_valid_ratio
CHANNEL_MIN_PROTOCOLS = settings.channels.channel_min_protocols
CHANNEL_HISTORY_DAYS = settings.channels.channel_history_days
CHANNEL_RECOVERING_TREND_THRESHOLD = settings.channels.channel_recovering_trend_threshold
CHANNEL_MIN_RECENT_DAYS_FOR_TREND = settings.channels.channel_min_recent_days_for_trend
CHANNEL_WHITELIST = settings.channels.channel_whitelist
MAX_CONFIG_AGE_DAYS = settings.channels.max_config_age_days
ARCHIVE_MAX_AGE_DAYS = settings.channels.archive_max_age_days
SIMPLE_MAX_AGE_DAYS = settings.channels.simple_max_age_days

# Настройки БД
DB_PATH = settings.database.db_path
MAX_HISTORY_RUNS = settings.database.max_history_runs
SAVE_INTERVAL_SECONDS = settings.database.save_interval_seconds
ENCRYPT_IPS = settings.database.encrypt_ips
ENCRYPTION_SALT = settings.database.encryption_salt
AUTO_CLEANUP_DAYS = settings.database.auto_cleanup_days

# Настройки датацентров
GEOLITE2_ASN_PATH = settings.datacenter.geolite2_asn_path
BUILTIN_DATACENTER_ASNS = settings.datacenter.builtin_datacenter_asns

# Настройки протоколов
ENABLED_PROTOCOLS = settings.protocols.enabled_protocols

# Расширенные настройки
MIN_RUNS_FOR_ADAPTIVE_THRESHOLDS = settings.advanced.min_runs_for_adaptive_thresholds
ANOMALY_Z_SCORE_THRESHOLD = settings.advanced.anomaly_z_score_threshold
ANOMALY_IQR_MULTIPLIER = settings.advanced.anomaly_iqr_multiplier
ANOMALY_DROP_THRESHOLD = settings.advanced.anomaly_drop_threshold
GRACE_PERIOD_RUNS = settings.advanced.grace_period_runs
ADAPTIVE_THRESHOLD_PERCENTILE = settings.advanced.adaptive_threshold_percentile
MIN_RECORDS_FOR_ADAPTIVE = settings.advanced.min_records_for_adaptive
