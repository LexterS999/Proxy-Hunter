"""
config.py - Конфигурация приложения
"""

import os
import logging
from typing import List, Dict, Optional

# [CHANGE] убран logging.basicConfig — логирование настраивается только в точке входа
logger = logging.getLogger(__name__)


class Config:
    """Основная конфигурация"""

    # Telegram каналы для парсинга
    DEFAULT_SOURCE_URLS = [
        'https://t.me/s/proxy_channel',
        'https://t.me/s/free_proxies',
        'https://t.me/s/vmess_configs',
        'https://t.me/s/vless_configs',
        'https://t.me/s/trojan_configs',
        'https://t.me/s/shadowsocks_configs',
    ]

    # Настройки парсинга
    PARSE_TIMEOUT = 30
    MAX_RETRIES = 3
    RETRY_DELAY = 2

    # Настройки валидации
    MIN_SCORE_THRESHOLD = 0.5
    MAX_LATENCY = 5000  # мс

    # Настройки дедупликации
    DEDUP_SHARD_DIR = 'configs/bloom_shards'
    DEDUP_NUM_SHARDS = 10
    DEDUP_CAPACITY = 1000000

    # Настройки архивации
    ARCHIVE_DIR = 'configs'
    ARCHIVE_FILE = 'configs/output_archive.txt'
    SIMPLE_FILE = 'configs/output_simple.txt'

    # Настройки БД
    DB_PATH = 'configs/history.db'

    # Настройки логирования
    LOG_LEVEL = logging.INFO
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

    def __init__(self):
        self.source_urls = self.DEFAULT_SOURCE_URLS.copy()
        self._load_custom_channels()

    def _load_custom_channels(self):
        """Загружает пользовательские каналы из custom_channels.txt"""
        try:
            custom_file = 'custom_channels.txt'
            if os.path.exists(custom_file):
                with open(custom_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            if not line.startswith('http'):
                                line = f'https://t.me/s/{line}'
                            if line not in self.source_urls:
                                self.source_urls.append(line)
                logger.info(f"📋 Загружено каналов: {len(self.source_urls)}")
        except Exception as e:
            logger.warning(f"⚠️ Не удалось загрузить custom_channels.txt: {e}")

    def get_enabled_channels(self) -> List[str]:
        """Возвращает список активных каналов с учётом их здоровья"""
        return self._apply_channel_health_filter(self.source_urls)

    def _apply_channel_health_filter(self, urls: List[str]) -> List[str]:
        """Фильтрует каналы по их здоровью (success rate)"""
        try:
            from channel_quality_analyzer import ChannelQualityAnalyzer
            analyzer = ChannelQualityAnalyzer()
            # [CHANGE] теперь реально обновляет метрики в БД (ранее pass)
            analyzer.update_health(urls)
            healthy = analyzer.get_healthy_channels(urls)
            if healthy:
                return healthy
            return urls
        except Exception as e:
            logger.debug(f"⚠️ Фильтр здоровья каналов недоступен: {e}")
            return urls
