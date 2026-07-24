# ============================================================================
# Файл: src/user_settings.py (исправлен, единый стиль нижнего регистра)
# ============================================================================

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from typing import Dict, List, Optional, Set, Tuple
from datetime import datetime, timedelta
import re
from urllib.parse import urlparse
from dataclasses import dataclass, field
import logging
from pathlib import Path
from functools import lru_cache

logger = logging.getLogger(__name__)

# ============================================================================
# КОНСТАНТЫ (используются в других модулях)
# ============================================================================

# Ретри-параметры для каналов
CHANNEL_RETRY_ATTEMPTS = 3
CHANNEL_RETRY_BASE_DELAY = 0.2
CHANNEL_RETRY_MAX_DELAY = 5.0
CHANNEL_RETRY_DEADLINE = 30.0

# Ограничения Telegram
TELEGRAM_CALLS_PER_SECOND = 3.0
MAX_RESPONSE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB

# Возраст конфигов для архивов
ARCHIVE_MAX_AGE_DAYS = 14
SIMPLE_MAX_AGE_DAYS = 7

# Пороги скоринга
SCORE_MIN_THRESHOLD = 30.0

# Настройки активной проверки
ACTIVE_CHECKER_WORKERS = 50
TCP_TIMEOUT = 5.0
HTTP_TIMEOUT = 8.0
MAX_LATENCY_MS = 2000.0
PER_HOST_LIMIT = 4

# Протоколы (включены по умолчанию)
ENABLED_PROTOCOLS = {
    "wireguard://": False,
    "hysteria2://": True,
    "vless://": True,
    "vmess://": True,
    "ss://": True,
    "trojan://": True,
    "tuic://": False,
}

# Режимы сбора
USE_MAXIMUM_POWER = True
SPECIFIC_CONFIG_COUNT = 5000

# Порог здоровья каналов
CHANNEL_HEALTH_THRESHOLD = 30.0

# Путь к базе MaxMind (если есть)
GEOLITE2_ASN_PATH = os.getenv('GEOLITE2_ASN_PATH', 'configs/GeoLite2-ASN.mmdb')

# Встроенный список ASN дата-центров (для детекции)
BUILTIN_DATACENTER_ASNS = {
    'AS13335', 'AS15169', 'AS16509', 'AS14618', 'AS54113',
    'AS20473', 'AS16276', 'AS14061', 'AS63949', 'AS15003',
    'AS23033', 'AS26347', 'AS8100', 'AS8075', 'AS396982',
    'AS701', 'AS7132', 'AS1299', 'AS2914', 'AS12389',
    'AS2119', 'AS3303', 'AS3320', 'AS3491', 'AS8551',
    'AS9009', 'AS11139', 'AS20115', 'AS24724', 'AS31898'
}

# Веса для скоринга
SCORE_WEIGHTS = {
    'stability': 0.25,
    'success_rate': 0.30,
    'reputation': 0.15,
    'lifetime': 0.10,
    'config_quality': 0.20,
}

# ============================================================================
# КЛАССЫ НАСТРОЕК (все поля в нижнем регистре)
# ============================================================================

def _load_default_source_urls() -> List[str]:
    """
    Восстановлено поведение из коммитов 2600be4/08efd05 (2026-07-22),
    когда пул каналов брался из custom_channels.txt (~16-26 каналов),
    а не из жёстко вшитых 6 URL.
    """
    base_default = [
        "https://t.me/s/SOSkeyNET",
        "https://t.me/s/GozargahAzad",
        "https://t.me/s/generalconfiig",
        "https://t.me/s/kurdconfig",
        "https://t.me/s/MiTiVPN",
        "https://t.me/s/WangCai2",
    ]
    try:
        candidates = [
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "custom_channels.txt"),
            os.path.join(os.getcwd(), "custom_channels.txt"),
            "custom_channels.txt",
        ]
        for path in candidates:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    extra = [
                        line.strip()
                        for line in f.read().splitlines()
                        if line.strip() and not line.startswith("#") and line.startswith(("http://", "https://"))
                    ]
                # Объединяем встроенные + custom, дедуплицируем с сохранением порядка
                seen = set()
                merged = []
                for url in base_default + extra:
                    if url and url not in seen:
                        seen.add(url)
                        merged.append(url)
                if len(merged) >= len(base_default):
                    return merged
                break
    except Exception:
        pass
    return base_default


@dataclass
class ChannelSettings:
    source_urls: List[str] = field(default_factory=_load_default_source_urls)
    use_maximum_power: bool = USE_MAXIMUM_POWER
    specific_config_count: int = SPECIFIC_CONFIG_COUNT
    max_config_age_days: int = 14
    channel_health_threshold: float = CHANNEL_HEALTH_THRESHOLD
    channel_min_configs: int = 1
    channel_min_valid_ratio: float = 0.05
    channel_min_protocols: int = 1
    channel_history_days: int = 14
    channel_whitelist: List[str] = field(default_factory=list)
    channel_recovering_trend_threshold: float = 0.05  # было 0.1 (мягче — больше recovering)
    channel_min_recent_days_for_trend: int = 2


@dataclass
class ProtocolSettings:
    enabled_protocols: Dict[str, bool] = field(default_factory=lambda: ENABLED_PROTOCOLS)


@dataclass
class AdvancedSettings:
    grace_period_runs: int = 3
    adaptive_threshold_percentile: int = 20
    min_records_for_adaptive: int = 10


@dataclass
class Settings:
    channels: ChannelSettings = field(default_factory=ChannelSettings)
    protocols: ProtocolSettings = field(default_factory=ProtocolSettings)
    advanced: AdvancedSettings = field(default_factory=AdvancedSettings)
    db_path: str = "configs/history.db"
    max_history_runs: int = 100
    save_interval_seconds: int = 30
    encrypt_ips: bool = True
    encryption_salt: str = "proxy_hunter_salt_2026"
    auto_cleanup_days: int = 30
    # Дублируем для обратной совместимости, если где-то используется settings.source_urls
    source_urls: List[str] = field(default_factory=lambda: ChannelSettings().source_urls)


# ============================================================================
# ГЛОБАЛЬНЫЙ ЭКЗЕМПЛЯР НАСТРОЕК (синглтон)
# ============================================================================

_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Возвращает глобальный объект настроек (создаёт при первом вызове)."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


# Для обратной совместимости
def get_settings_safe() -> Settings:
    return get_settings()
