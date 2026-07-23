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

from db import get_db
from user_settings import (
    SOURCE_URLS, USE_MAXIMUM_POWER, SPECIFIC_CONFIG_COUNT, ENABLED_PROTOCOLS,
    MAX_CONFIG_AGE_DAYS, CHANNEL_HEALTH_THRESHOLD, get_settings
)
from channel_quality_analyzer import ChannelQualityAnalyzer

# Получаем настройки
settings = get_settings()
REGION = os.getenv('PROXY_HUNTER_REGION', 'RU')

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


# ============================================================================
# DATACLASSES ДЛЯ КОНФИГУРАЦИЙ
# ============================================================================

@dataclass
class ChannelMetrics:
    """Метрики канала."""
    total_configs: int = 0
    valid_configs: int = 0
    unique_configs: int = 0
    avg_response_time: float = 0.0
    last_success_time: Optional[datetime] = None
    fail_count: int = 0
    success_count: int = 0
    overall_score: float = 0.0
    protocol_counts: Dict[str, int] = field(default_factory=dict)


@dataclass
class ChannelConfig:
    """Конфигурация канала."""
    url: str
    enabled: bool = True
    metrics: ChannelMetrics = field(default_factory=ChannelMetrics)
    is_telegram: bool = False
    error_count: int = 0
    last_check_time: Optional[datetime] = None
    region_bonus: float = 0.0

    def __post_init__(self):
        self.url = self._validate_url(self.url)
        self.is_telegram = bool(re.match(r'^https://t\.me/s/', self.url))

    def _validate_url(self, url: str) -> str:
        """Валидирует URL канала."""
        if not url or not isinstance(url, str):
            raise ValueError("Invalid URL: empty or not a string")
        url = url.strip()
        if not url.startswith(('http://', 'https://', 'ssconf://')):
            raise ValueError(f"Invalid URL protocol: {url}")
        
        # Проверяем на потенциально опасные протоколы
        dangerous_protocols = ['javascript:', 'data:', 'file:']
        if any(url.lower().startswith(proto) for proto in dangerous_protocols):
            raise ValueError(f"Dangerous URL protocol: {url}")
        
        return url

    def calculate_overall_score(self) -> None:
        """Рассчитывает общий score канала."""
        try:
            total_attempts = max(1, self.metrics.success_count + self.metrics.fail_count)
            reliability_score = (self.metrics.success_count / total_attempts) * 35

            total_configs = max(1, self.metrics.total_configs)
            quality_score = (self.metrics.valid_configs / total_configs) * 25

            valid_configs = max(1, self.metrics.valid_configs)
            uniqueness_score = (self.metrics.unique_configs / valid_configs) * 25

            response_score = 15.0
            if self.metrics.avg_response_time > 0:
                response_score = max(0.0, min(15.0, 15.0 * (1 - (self.metrics.avg_response_time / 10))))

            region_bonus = getattr(self, 'region_bonus', 0.0)

            self.metrics.overall_score = round(
                reliability_score + quality_score + uniqueness_score + response_score + region_bonus, 2
            )
        except Exception as e:
            logger.error(f"Error calculating score for {self.url}: {str(e)}")
            self.metrics.overall_score = 0.0


@dataclass
class ProxyConfig:
    """Основная конфигурация прокси."""
    use_maximum_power: bool = USE_MAXIMUM_POWER
    specific_config_count: int = SPECIFIC_CONFIG_COUNT
    MAX_CONFIG_AGE_DAYS: int = MAX_CONFIG_AGE_DAYS
    region: str = REGION
    SOURCE_URLS: List[ChannelConfig] = field(default_factory=list)
    SUPPORTED_PROTOCOLS: Dict[str, Dict] = field(default_factory=dict)
    CHANNEL_RETRY_LIMIT: int = 10
    CHANNEL_ERROR_THRESHOLD: float = 0.7
    OUTPUT_FILE: str = 'configs/proxy_configs.txt'
    STATS_FILE: str = 'configs/channel_stats.json'
    MAX_RETRIES: int = 5
    RETRY_DELAY: int = 15
    REQUEST_TIMEOUT: int = 60
    HEADERS: Dict[str, str] = field(default_factory=dict)
    MIN_CONFIGS_PER_CHANNEL: int = 1
    MAX_CONFIGS_PER_CHANNEL: int = 20000

    def __post_init__(self):
        """Инициализирует конфигурацию."""
        self.SUPPORTED_PROTOCOLS = self._initialize_protocols()
        initial_urls: List[ChannelConfig] = [ChannelConfig(url=url) for url in SOURCE_URLS]
        self.SOURCE_URLS = self._remove_duplicate_urls(initial_urls)
        self._initialize_settings()
        self._set_smart_limits()
        self._analyzer: Optional[ChannelQualityAnalyzer] = None
        self._apply_region_bonus()

    def _initialize_protocols(self) -> Dict[str, Dict]:
        """Инициализирует поддерживаемые протоколы."""
        return {
            "wireguard://": {"priority": 1, "aliases": [], "enabled": ENABLED_PROTOCOLS.get("wireguard://", False)},
            "hysteria2://": {"priority": 2, "aliases": ["hy2://"], "enabled": ENABLED_PROTOCOLS.get("hysteria2://", False)},
            "vless://": {"priority": 2, "aliases": [], "enabled": ENABLED_PROTOCOLS.get("vless://", False)},
            "vmess://": {"priority": 1, "aliases": [], "enabled": ENABLED_PROTOCOLS.get("vmess://", False)},
            "ss://": {"priority": 2, "aliases": [], "enabled": ENABLED_PROTOCOLS.get("ss://", False)},
            "trojan://": {"priority": 2, "aliases": [], "enabled": ENABLED_PROTOCOLS.get("trojan://", False)},
            "tuic://": {"priority": 1, "aliases": [], "enabled": ENABLED_PROTOCOLS.get("tuic://", False)}
        }

    def _initialize_settings(self) -> None:
        """Инициализирует настройки по умолчанию."""
        self.CHANNEL_RETRY_LIMIT = min(10, max(1, 5))
        self.CHANNEL_ERROR_THRESHOLD = min(0.9, max(0.1, 0.7))
        self.OUTPUT_FILE = 'configs/proxy_configs.txt'
        self.STATS_FILE = 'configs/channel_stats.json'
        self.MAX_RETRIES = min(10, max(1, 5))
        self.RETRY_DELAY = min(60, max(5, 15))
        self.REQUEST_TIMEOUT = min(120, max(10, 60))
        self.HEADERS = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }

    @lru_cache(maxsize=1000)
    def _normalize_url(self, url: str) -> str:
        """Нормализует URL (кешируется)."""
        try:
            if not url:
                raise ValueError("Empty URL")
            url = url.strip()
            if url.startswith('ssconf://'):
                url = url.replace('ssconf://', 'https://', 1)
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError("Invalid URL format")
            path = parsed.path.rstrip('/')
            if parsed.netloc.startswith('t.me/s/'):
                channel_name = parsed.path.strip('/').lower()
                return f"telegram:{channel_name}"
            return f"{parsed.scheme}://{parsed.netloc}{path}"
        except Exception as e:
            logger.error(f"URL normalization error: {str(e)}")
            raise

    def _remove_duplicate_urls(self, channel_configs: List[ChannelConfig]) -> List[ChannelConfig]:
        """Удаляет дубликаты URL (учитывает протокол)."""
        try:
            seen_urls: Dict[str, bool] = {}
            unique_configs: List[ChannelConfig] = []
            for config in channel_configs:
                if not isinstance(config, ChannelConfig):
                    logger.warning(f"Invalid config skipped: {config}")
                    continue
                try:
                    # Учитываем протокол, сервер и порт для дедупликации
                    normalized_url = self._normalize_url(config.url)
                    if normalized_url not in seen_urls:
                        seen_urls[normalized_url] = True
                        unique_configs.append(config)
                except Exception:
                    continue
            if not unique_configs:
                self.save_empty_config_file()
                logger.error("No valid sources found. Empty config file created.")
                return []
            return unique_configs
        except Exception as e:
            logger.error(f"Error removing duplicate URLs: {str(e)}")
            self.save_empty_config_file()
            return []

    def is_protocol_enabled(self, protocol: str) -> bool:
        """Проверяет, включён ли протокол."""
        try:
            if not protocol:
                return False
            protocol = protocol.lower().strip()
            if protocol in self.SUPPORTED_PROTOCOLS:
                return self.SUPPORTED_PROTOCOLS[protocol].get("enabled", False)
            for main_protocol, info in self.SUPPORTED_PROTOCOLS.items():
                if protocol in info.get("aliases", []):
                    return info.get("enabled", False)
            return False
        except Exception:
            return False

    def _apply_region_bonus(self) -> None:
        """Применяет региональный бонус к каналам."""
        for ch in self.SOURCE_URLS:
            url_lower = ch.url.lower()
            if any(region in url_lower for region in ['ir', 'iran', 'ru', 'russia']):
                ch.region_bonus = 8.0
                logger.debug(f"Applied region bonus to {ch.url}")
            else:
                ch.region_bonus = 0.0

    def _prune_dead_channels(self) -> None:
        """Удаляет неработающие каналы (без конфигов за последние 24 часа)."""
        db = get_db()
        cutoff = datetime.now() - timedelta(days=1)  # последние 24 часа
        for ch in self.SOURCE_URLS:
            history = db.get_channel_history(ch.url, limit=5)
            recent_success = False
            for h in history:
                last_success = h.get('last_success')
                if last_success:
                    try:
                        if datetime.fromisoformat(last_success) > cutoff:
                            recent_success = True
                            break
                    except:
                        pass
            total = sum(h.get('total_configs', 0) for h in history)
            if not recent_success and total == 0:
                ch.enabled = False
                logger.info(f"Channel {ch.url} disabled (no configs in last 24h and total=0).")
            elif not recent_success and total > 0:
                logger.debug(f"Channel {ch.url} has old configs but no recent success, keeping enabled.")
            else:
                if not ch.enabled:
                    ch.enabled = True
                    logger.info(f"Channel {ch.url} re-enabled (found recent success).")

    def get_enabled_channels(self) -> List[ChannelConfig]:
        """Возвращает список включённых каналов."""
        self._prune_dead_channels()
        self._apply_channel_health_filter()
        channels = [channel for channel in self.SOURCE_URLS if channel.enabled]
        if not channels:
            self.save_empty_config_file()
            logger.error("No enabled channels found after health filter. Empty config file created.")
        channels.sort(key=lambda c: c.metrics.overall_score, reverse=True)
        return channels

    def _apply_channel_health_filter(self) -> None:
        """Применяет фильтр здоровья к каналам."""
        if not self.SOURCE_URLS:
            return
        if self._analyzer is None:
            self._analyzer = ChannelQualityAnalyzer()
        urls = [ch.url for ch in self.SOURCE_URLS]
        self._analyzer.update_health(urls)
        states: Dict[str, str] = {}
        for ch in self.SOURCE_URLS:
            state = self._analyzer.get_channel_state(ch.url)
            states[ch.url] = state
            if state == 'inactive':
                ch.enabled = False
                logger.info(f"Channel {ch.url} disabled (state: inactive).")
            else:
                ch.enabled = True
                logger.debug(f"Channel {ch.url} enabled (state: {state}).")
        active_count = sum(1 for s in states.values() if s == 'active')
        recovering_count = sum(1 for s in states.values() if s == 'recovering')
        inactive_count = sum(1 for s in states.values() if s == 'inactive')
        logger.info(f"Channel health summary: active={active_count}, recovering={recovering_count}, inactive={inactive_count}")

    def update_channel_stats(
        self,
        channel: ChannelConfig,
        success: bool,
        response_time: float = 0.0
    ) -> None:
        """Обновляет статистику канала."""
        if success:
            channel.metrics.success_count += 1
            channel.metrics.last_success_time = datetime.now()
        else:
            channel.metrics.fail_count += 1

        if response_time > 0:
            if channel.metrics.avg_response_time == 0:
                channel.metrics.avg_response_time = response_time
            else:
                channel.metrics.avg_response_time = (
                    channel.metrics.avg_response_time * 0.7
                ) + (response_time * 0.3)

        channel.calculate_overall_score()

        if channel.metrics.overall_score < 25:
            channel.enabled = False
            if not any(c.enabled for c in self.SOURCE_URLS):
                self.save_empty_config_file()
                logger.error("All channels are disabled. Empty config file created.")

    def adjust_protocol_limits(self, channel: ChannelConfig) -> None:
        """Корректирует лимиты протоколов на основе статистики канала."""
        if self.use_maximum_power:
            return
        for protocol in channel.metrics.protocol_counts:
            if protocol in self.SUPPORTED_PROTOCOLS:
                current_count = channel.metrics.protocol_counts[protocol]
                if current_count > 0:
                    self.SUPPORTED_PROTOCOLS[protocol]["min_configs"] = min(
                        self.SUPPORTED_PROTOCOLS[protocol]["min_configs"],
                        current_count
                    )

    def save_empty_config_file(self) -> bool:
        """Создаёт пустой файл конфигураций."""
        try:
            Path(self.OUTPUT_FILE).parent.mkdir(parents=True, exist_ok=True)
            with open(self.OUTPUT_FILE, 'w', encoding='utf-8') as f:
                f.write("")
            return True
        except Exception:
            return False

    def _set_smart_limits(self) -> None:
        """Устанавливает умные лимиты в зависимости от режима."""
        if self.use_maximum_power:
            self._set_maximum_power_mode()
        else:
            self._set_specific_count_mode()

    def _set_maximum_power_mode(self) -> None:
        """Устанавливает лимиты для режима максимальной производительности."""
        max_configs = 20000
        for protocol in self.SUPPORTED_PROTOCOLS:
            self.SUPPORTED_PROTOCOLS[protocol].update({
                "min_configs": 1,
                "max_configs": max_configs,
                "flexible_max": True
            })
        self.MIN_CONFIGS_PER_CHANNEL = 1
        self.MAX_CONFIGS_PER_CHANNEL = max_configs
        self.MAX_RETRIES = min(10, max(1, 10))
        self.CHANNEL_RETRY_LIMIT = min(10, max(1, 10))
        self.REQUEST_TIMEOUT = min(120, max(30, 90))

    def _set_specific_count_mode(self) -> None:
        """Устанавливает лимиты для режима ограниченного сбора."""
        if self.specific_config_count <= 0:
            self.specific_config_count = 50
        protocols_count = len(self.SUPPORTED_PROTOCOLS)
        base_per_protocol = max(1, self.specific_config_count // protocols_count)
        for protocol in self.SUPPORTED_PROTOCOLS:
            self.SUPPORTED_PROTOCOLS[protocol].update({
                "min_configs": 1,
                "max_configs": min(base_per_protocol * 2, 1000),
                "flexible_max": True
            })
        self.MIN_CONFIGS_PER_CHANNEL = 1
        self.MAX_CONFIGS_PER_CHANNEL = min(max(5, self.specific_config_count // 2), 1000)
