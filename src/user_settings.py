"""
Настройки Proxy-Hunter.
ИСПРАВЛЕНО: property-доступ через get_settings() вместо глобальных переменных.
НОВОЕ: добавлены test_domain, target_region, xray_path, region_test_top_n.
"""

import os
import json
import logging
from typing import List, Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logger = logging.getLogger(__name__)

# Региональные тестовые домены (дублируются из region_tester.py для автономности)
_DEFAULT_TEST_DOMAINS = {
    'RU': 'rutracker.org',
    'CN': 'google.com',
    'IR': 'twitter.com',
    'GENERIC': 'google.com',
}


class Settings:
    """Централизованные настройки проекта."""

    def __init__(self):
        self.reload()

    def reload(self) -> None:
        """Перечитывает все настройки из переменных окружения."""
        # Основные
        self.source_urls: List[str] = self._parse_list(
            os.getenv('SOURCE_URLS', ''), separator=','
        )
        self.custom_channels_file: str = os.getenv(
            'CUSTOM_CHANNELS_FILE', 'custom_channels.txt'
        )
        self.output_archive: str = os.getenv(
            'OUTPUT_ARCHIVE', 'configs/output_archive.txt'
        )
        self.output_simple: str = os.getenv(
            'OUTPUT_SIMPLE', 'configs/output_simple.txt'
        )
        self.db_path: str = os.getenv('DB_PATH', 'configs/history.db')
        self.parsed_cache_path: str = os.getenv(
            'PARSED_CACHE_PATH', 'configs/parsed_cache.json'
        )
        self.bloom_shards_dir: str = os.getenv(
            'BLOOM_SHARDS_DIR', 'bloom_shards'
        )

        # Сеть
        self.fetch_timeout: float = float(os.getenv('FETCH_TIMEOUT', '30'))
        self.fetch_concurrency: int = int(os.getenv('FETCH_CONCURRENCY', '50'))
        self.rate_limit_per_sec: float = float(os.getenv('RATE_LIMIT_PER_SEC', '1.5'))
        self.max_retries: int = int(os.getenv('MAX_RETRIES', '3'))

        # Верификация
        self.check_timeout: float = float(os.getenv('CHECK_TIMEOUT', '5'))
        self.check_concurrency: int = int(os.getenv('CHECK_CONCURRENCY', '100'))
        self.max_latency_ms: float = float(os.getenv('MAX_LATENCY_MS', '10000'))

        # Скоринг
        self.min_score: float = float(os.getenv('MIN_SCORE', '30'))
        self.min_score_fallback: float = float(os.getenv('MIN_SCORE_FALLBACK', '10'))

        # НОВОЕ: Региональное тестирование
        self.target_region: str = os.getenv('TARGET_REGION', 'RU').upper()
        self.test_domain: str = os.getenv(
            'TEST_DOMAIN',
            _DEFAULT_TEST_DOMAINS.get(self.target_region, 'google.com')
        )
        self.xray_path: str = os.getenv('XRAY_PATH', 'xray')
        self.region_test_top_n: int = int(os.getenv('REGION_TEST_TOP_N', '50'))
        self.region_test_timeout: float = float(os.getenv('REGION_TEST_TIMEOUT', '15'))
        self.region_test_concurrency: int = int(os.getenv('REGION_TEST_CONCURRENCY', '3'))
        self.skip_verification: bool = os.getenv(
            'SKIP_VERIFICATION', 'false'
        ).lower() in ('true', '1', 'yes')

        # НОВОЕ: Модель выживания
        self.survival_states_path: str = os.getenv(
            'SURVIVAL_STATES_PATH', 'configs/survival_states.json'
        )
        self.survival_death_threshold: float = float(
            os.getenv('SURVIVAL_DEATH_THRESHOLD', '5.0')
        )

        # НОВОЕ: Оценка цензуры
        self.censorship_stats_path: str = os.getenv(
            'CENSORSHIP_STATS_PATH', 'configs/censorship_stats.json'
        )

        # НОВОЕ: Статистика верификации
        self.verification_stats_path: str = os.getenv(
            'VERIFICATION_STATS_PATH', 'configs/verification_stats.json'
        )

        # Bloom
        self.bloom_hmac_key: str = os.getenv(
            'BLOOM_HMAC_KEY', 'fallback-dev-key-change-me'
        )

        # ML
        self.model_path: str = os.getenv('MODEL_PATH', 'configs/model.cbm')
        self.feature_importance_path: str = os.getenv(
            'FEATURE_IMPORTANCE_PATH', 'configs/feature_importance.json'
        )

        logger.info(
            f"Settings loaded: region={self.target_region}, "
            f"test_domain={self.test_domain}, "
            f"skip_verification={self.skip_verification}"
        )

    @staticmethod
    def _parse_list(value: str, separator: str = ',') -> List[str]:
        if not value:
            return []
        return [item.strip() for item in value.split(separator) if item.strip()]

    def to_dict(self) -> dict:
        """Экспорт настроек в dict (для логирования/отладки)."""
        return {
            'target_region': self.target_region,
            'test_domain': self.test_domain,
            'xray_path': self.xray_path,
            'region_test_top_n': self.region_test_top_n,
            'skip_verification': self.skip_verification,
            'fetch_concurrency': self.fetch_concurrency,
            'check_concurrency': self.check_concurrency,
            'min_score': self.min_score,
            'min_score_fallback': self.min_score_fallback,
            'rate_limit_per_sec': self.rate_limit_per_sec,
        }


# Синглтон
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Возвращает синглтон настроек. Создаёт при первом вызове."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reload_settings() -> Settings:
    """Перечитывает настройки из окружения. Обновляет синглтон."""
    global _settings
    if _settings is None:
        _settings = Settings()
    else:
        _settings.reload()
    return _settings


# Обратная совместимость: модульные переменные для существующего кода.
# ВНИМАНИЕ: используйте get_settings() для доступа к актуальным значениям.
# Эти переменные обновляются при reload_settings().
SOURCE_URLS: List[str] = []
CUSTOM_CHANNELS_FILE: str = 'custom_channels.txt'
OUTPUT_ARCHIVE: str = 'configs/output_archive.txt'
OUTPUT_SIMPLE: str = 'configs/output_simple.txt'
DB_PATH: str = 'configs/history.db'
TARGET_REGION: str = 'RU'
TEST_DOMAIN: str = 'rutracker.org'
XRAY_PATH: str = 'xray'


def _sync_module_vars() -> None:
    """Синхронизирует модульные переменные с синглтоном."""
    s = get_settings()
    global SOURCE_URLS, CUSTOM_CHANNELS_FILE, OUTPUT_ARCHIVE, OUTPUT_SIMPLE
    global DB_PATH, TARGET_REGION, TEST_DOMAIN, XRAY_PATH
    SOURCE_URLS = s.source_urls
    CUSTOM_CHANNELS_FILE = s.custom_channels_file
    OUTPUT_ARCHIVE = s.output_archive
    OUTPUT_SIMPLE = s.output_simple
    DB_PATH = s.db_path
    TARGET_REGION = s.target_region
    TEST_DOMAIN = s.test_domain
    XRAY_PATH = s.xray_path


# Инициализация при импорте
_sync_module_vars()
