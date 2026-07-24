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

# Импортируем настройки безопасно, чтобы избежать циклических импортов
_settings = None

def get_settings_safe():
    """Безопасная загрузка настроек для избежания циклических импортов."""
    global _settings
    if _settings is None:
        try:
            from user_settings import get_settings
            _settings = get_settings()
        except ImportError as e:
            logger.warning(f"Failed to import settings: {e}. Using defaults.")
            class ChannelSettings:
                SOURCE_URLS = [
                    "https://t.me/s/SOSkeyNET",
                    "https://t.me/s/GozargahAzad",
                    "https://t.me/s/generalconfiig",
                    "https://t.me/s/kurdconfig",
                    "https://t.me/s/MiTiVPN",
                    "https://t.me/s/WangCai2",
                ]
                USE_MAXIMUM_POWER = True
                SPECIFIC_CONFIG_COUNT = 5000
                MAX_CONFIG_AGE_DAYS = 14
                CHANNEL_HEALTH_THRESHOLD = 30.0

            class ProtocolSettings:
                ENABLED_PROTOCOLS = {
                    "wireguard://": False,
                    "hysteria2://": True,
                    "vless://": True,
                    "vmess://": True,
                    "ss://": True,
                    "trojan://": True,
                    "tuic://": False,
                }

            class Settings:
                channels = ChannelSettings()
                protocols = ProtocolSettings()

            _settings = Settings()
    return _settings

settings = get_settings_safe()
REGION = os.getenv('PROXY_HUNTER_REGION', 'RU')

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

_db = None

def get_db_safe():
    global _db
    if _db is None:
        try:
            from db import get_db
            _db = get_db()
        except ImportError as e:
            logger.warning(f"Failed to import db: {e}")
            class _FakeDB:
                def get_channel_history(self, *args, **kwargs):
                    return []
                def get_profile_last_seen(self, *args, **kwargs):
                    return None
                def get_profile(self, *args, **kwargs):
                    return None
            _db = _FakeDB()
    return _db

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
    avg_config_score: float = 0.0  # новое поле – средний скор конфигов

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
        if not url or not isinstance(url, str):
            raise ValueError("Invalid URL: empty or not a string")
        url = url.strip()
        if not url.startswith(('http://', 'https://', 'ssconf://')):
            raise ValueError(f"Invalid URL protocol: {url}")
        dangerous_protocols = ['javascript:', 'data:', 'file:']
        if any(url.lower().startswith(proto) for proto in dangerous_protocols):
            raise ValueError(f"Dangerous URL protocol: {url}")
        return url

    def calculate_overall_score(self) -> None:
        """Рассчитывает общий score канала с учётом качества конфигов."""
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

            # Учитываем средний скор конфигов (если есть)
            avg_cfg_score = self.metrics.avg_config_score
            if avg_cfg_score > 0:
                quality_bonus = (avg_cfg_score / 100) * 10  # до +10 баллов
            else:
                quality_bonus = 0.0

            self.metrics.overall_score = round(
                reliability_score + quality_score + uniqueness_score + response_score + region_bonus + quality_bonus, 2
            )
        except Exception as e:
            logger.error(f"Error calculating score for {self.url}: {str(e)}")
            self.metrics.overall_score = 0.0

@dataclass
class ProxyConfig:
    """Основная конфигурация прокси."""
    use_maximum_power: bool = True
    specific_config_count: int = 5000
    MAX_CONFIG_AGE_DAYS: int = 14
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
        settings = get_settings_safe()
        self.use_maximum_power = settings.channels.use_maximum_power
        self.specific_config_count = settings.channels.specific_config_count
        self.MAX_CONFIG_AGE_DAYS = settings.channels.max_config_age_days

        self.SUPPORTED_PROTOCOLS = self._initialize_protocols(settings)
        initial_urls: List[ChannelConfig] = [ChannelConfig(url=url) for url in settings.channels.source_urls]
        self.SOURCE_URLS = self._remove_duplicate_urls(initial_urls)
        self._initialize_settings()
        self._set_smart_limits()
        self._analyzer = None
        self._apply_region_bonus()

        logger.info(f"Loaded {len(self.SOURCE_URLS)} channels from settings")
        for ch in self.SOURCE_URLS[:5]:
            logger.debug(f"  - {ch.url} (enabled: {ch.enabled})")
        if len(self.SOURCE_URLS) > 5:
            logger.debug(f"  ... and {len(self.SOURCE_URLS) - 5} more channels")

    def _initialize_protocols(self, settings) -> Dict[str, Dict]:
        enabled_protocols = settings.protocols.enabled_protocols
        return {
            "wireguard://": {"priority": 1, "aliases": [], "enabled": enabled_protocols.get("wireguard://", False)},
            "hysteria2://": {"priority": 2, "aliases": ["hy2://"], "enabled": enabled_protocols.get("hysteria2://", False)},
            "vless://": {"priority": 2, "aliases": [], "enabled": enabled_protocols.get("vless://", False)},
            "vmess://": {"priority": 1, "aliases": [], "enabled": enabled_protocols.get("vmess://", False)},
            "ss://": {"priority": 2, "aliases": [], "enabled": enabled_protocols.get("ss://", False)},
            "trojan://": {"priority": 2, "aliases": [], "enabled": enabled_protocols.get("trojan://", False)},
            "tuic://": {"priority": 1, "aliases": [], "enabled": enabled_protocols.get("tuic://", False)}
        }

    def _initialize_settings(self) -> None:
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
        try:
            seen_urls: Dict[str, bool] = {}
            unique_configs: List[ChannelConfig] = []
            for config in channel_configs:
                if not isinstance(config, ChannelConfig):
                    logger.warning(f"Invalid config skipped: {config}")
                    continue
                try:
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
            logger.info(f"Removed duplicates: {len(channel_configs)} -> {len(unique_configs)} channels")
            return unique_configs
        except Exception as e:
            logger.error(f"Error removing duplicate URLs: {str(e)}")
            self.save_empty_config_file()
            return []

    def is_protocol_enabled(self, protocol: str) -> bool:
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
        for ch in self.SOURCE_URLS:
            url_lower = ch.url.lower()
            if any(region in url_lower for region in ['ir', 'iran', 'ru', 'russia']):
                ch.region_bonus = 8.0
                logger.debug(f"Applied region bonus to {ch.url}")
            else:
                ch.region_bonus = 0.0

    def _prune_dead_channels(self) -> None:
        """Удаляет неработающие каналы с учётом реабилитации и более долгого окна (7 дней)."""
        db = get_db_safe()
        cutoff = datetime.now() - timedelta(days=7)   # было 1
        enabled_count = 0
        disabled_count = 0
        rehabilitated_count = 0

        for ch in self.SOURCE_URLS:
            try:
                history = db.get_channel_history(ch.url, limit=5)  # последние 5 запусков
                recent_success = False
                total = 0
                for h in history:
                    total += h.get('total_configs', 0)
                    last_success = h.get('last_success')
                    if last_success:
                        try:
                            if datetime.fromisoformat(last_success) > cutoff:
                                recent_success = True
                                break
                        except:
                            pass

                # Если канал выключен, но за последние 3 запуска были конфиги – реабилитируем
                if not ch.enabled:
                    recent_configs = sum(1 for h in history[-3:] if h.get('total_configs', 0) > 0)
                    if recent_configs >= 1:   # хотя бы один запуск с конфигами
                        ch.enabled = True
                        rehabilitated_count += 1
                        logger.info(f"Channel {ch.url} rehabilitated (found configs in last 3 runs).")
                        # Сбрасываем счётчик ошибок
                        ch.metrics.fail_count = 0
                        continue

                if not history:
                    ch.enabled = True
                    enabled_count += 1
                    logger.debug(f"Channel {ch.url} has no history, keeping enabled (new channel)")
                    continue

                if not recent_success and total == 0:
                    ch.enabled = False
                    disabled_count += 1
                    logger.info(f"Channel {ch.url} disabled (no configs in last 7 days and total=0).")
                elif not recent_success and total > 0:
                    ch.enabled = True
                    enabled_count += 1
                    logger.debug(f"Channel {ch.url} has old configs but no recent success, keeping enabled.")
                else:
                    if not ch.enabled:
                        ch.enabled = True
                        enabled_count += 1
                        logger.info(f"Channel {ch.url} re-enabled (found recent success).")
                    else:
                        enabled_count += 1
            except Exception as e:
                logger.error(f"Error checking channel {ch.url}: {e}")
                ch.enabled = True
                enabled_count += 1

        logger.info(f"Channel pruning: {enabled_count} enabled, {disabled_count} disabled, {rehabilitated_count} rehabilitated")

    def get_enabled_channels(self) -> List[ChannelConfig]:
        logger.info("Getting enabled channels...")

        self._apply_channel_health_filter()
        self._prune_dead_channels()

        channels = [channel for channel in self.SOURCE_URLS if channel.enabled]

        if not channels:
            self.save_empty_config_file()
            logger.error("No enabled channels found after health filter. Empty config file created.")
            logger.info("Attempting to reset channel health states...")
            self._reset_channel_health()
            channels = self.SOURCE_URLS.copy()
            logger.info(f"Reset health states. Trying with all {len(channels)} channels.")

        channels.sort(key=lambda c: c.metrics.overall_score, reverse=True)
        logger.info(f"✅ Enabled channels: {len(channels)}")
        return channels

    def _reset_channel_health(self) -> None:
        try:
            from channel_quality_analyzer import ChannelQualityAnalyzer
            analyzer = ChannelQualityAnalyzer()
            urls = [ch.url for ch in self.SOURCE_URLS]
            analyzer.reset_channel_states(urls)
            logger.info(f"Reset health states for {len(urls)} channels")
        except Exception as e:
            logger.error(f"Failed to reset channel health: {e}")

    def _apply_channel_health_filter(self) -> None:
        if not self.SOURCE_URLS:
            return
        try:
            from channel_quality_analyzer import ChannelQualityAnalyzer
            self._analyzer = ChannelQualityAnalyzer()
        except ImportError as e:
            logger.warning(f"Failed to import ChannelQualityAnalyzer: {e}")
            return

        urls = [ch.url for ch in self.SOURCE_URLS]
        self._analyzer.update_health(urls)
        states: Dict[str, str] = {}
        active_count = 0
        recovering_count = 0
        inactive_count = 0

        for ch in self.SOURCE_URLS:
            state = self._analyzer.get_channel_state(ch.url)
            states[ch.url] = state

            if state in ('active', 'recovering'):
                ch.enabled = True
                if state == 'active':
                    active_count += 1
                else:
                    recovering_count += 1
            else:
                db = get_db_safe()
                history = db.get_channel_history(ch.url, limit=1)

                if not history:
                    ch.enabled = True
                    active_count += 1
                    logger.debug(f"New channel {ch.url} with no history, keeping enabled")
                else:
                    ch.enabled = False
                    inactive_count += 1
                    logger.debug(f"Channel {ch.url} disabled (state: inactive)")

        logger.info(f"Channel health summary: active={active_count}, recovering={recovering_count}, inactive={inactive_count}")

    def update_channel_stats(
        self,
        channel: ChannelConfig,
        success: bool,
        response_time: float = 0.0
    ) -> None:
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
        try:
            Path(self.OUTPUT_FILE).parent.mkdir(parents=True, exist_ok=True)
            with open(self.OUTPUT_FILE, 'w', encoding='utf-8') as f:
                f.write("")
            return True
        except Exception:
            return False

    def _set_smart_limits(self) -> None:
        if self.use_maximum_power:
            self._set_maximum_power_mode()
        else:
            self._set_specific_count_mode()

    def _set_maximum_power_mode(self) -> None:
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
