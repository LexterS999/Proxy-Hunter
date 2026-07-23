#!/usr/bin/env python3

"""
Оптимизированный пайплайн Proxy-Hunter с:
- Улучшенной оценкой
- Асинхронной активной проверкой
- Кешированием
- Graceful shutdown
- Autoclose для всех асинхронных ресурсов
- Transient error handling
- Использованием aiofiles для всех файловых операций

Добавлены:
- SNI Probe для тестирования с несколькими SNI
- Региональный скоринг с бонусами/штрафами
- Сбор статистики локальных проверок
- Интеграция RealitySNIHunter
- Автоматическое обновление весов
- Детекция датацентров (штраф/бонус)
- Фильтрация по возрасту профилей
- Красивый итоговый вывод статистики
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import logging
import time
import traceback
import json
import hashlib
import asyncio
import shutil
import signal
from pathlib import Path
from typing import List, Dict, Optional, Set, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from functools import lru_cache

import aiofiles
from tqdm import tqdm

# Импортируем модули с обработкой возможных ошибок
try:
    from config import ProxyConfig
    from fetch_configs import AsyncConfigFetcher
    from config_validator import ConfigValidator
    from deep_deduplicate import DeepDeduplicator
    from config_quality import ConfigQualityChecker
    from profile_scorer import ProfileScorer
    from active_checker import ActiveChecker
    from parse_fallback import FallbackParser
    from session_pool import SessionPool
    from channel_quality_analyzer import ChannelQualityAnalyzer
    from db import get_db
    from sni_probe import SNIProbe
    from reality_sni_hunter import RealitySNIHunter
    from regional_scorer import RegionalScorer
    from regional_stats import RegionalStats
    from sni_filter import SNIFilter
    from weight_updater import WeightUpdater
    from datacenter_detector import is_datacenter_ip
    from logger_utils import print_summary
    from user_settings import get_settings, get_settings as user_get_settings
    
    # Получаем настройки
    settings = user_get_settings()
    
    # Импортируем переменные для обратной совместимости
    from user_settings import (
        ARCHIVE_MAX_AGE_DAYS,
        SIMPLE_MAX_AGE_DAYS,
        SCORE_MIN_THRESHOLD,
        ACTIVE_CHECKER_WORKERS,
        TCP_TIMEOUT,
        HTTP_TIMEOUT,
        MAX_LATENCY_MS,
        PER_HOST_LIMIT,
        ENABLED_PROTOCOLS,
        USE_MAXIMUM_POWER,
        SPECIFIC_CONFIG_COUNT,
        CHANNEL_HEALTH_THRESHOLD,
    )
except ImportError as e:
    # Фоллбек, если какие-то модули недоступны
    logger = logging.getLogger(__name__)
    logger.error(f"Failed to import modules: {e}")
    sys.exit(1)

# Настройка логирования
log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
logging.basicConfig(
    level=logging.DEBUG if log_level == 'DEBUG' else logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)


@dataclass
class ParsedConfig:
    """Распарсенная конфигурация."""
    raw: str
    protocol: str
    server: str
    port: int
    credential: str
    parsed_data: Dict = field(default_factory=dict)
    parse_method: str = 'unknown'
    fingerprint: str = ''
    is_valid: bool = False
    score: float = 0.0
    stability: float = 0.5
    lifetime: float = 24.0
    latency: float = -1.0
    is_active: bool = False

    @property
    def cache_key(self) -> str:
        return hashlib.md5(self.raw.encode()).hexdigest()

    @property
    def dedup_key(self) -> str:
        """Ключ для дедупликации (учитывает протокол)."""
        return f"{self.server}:{self.port}:{self.protocol}:{self.credential}"

    @property
    def prefix_key(self) -> str:
        parts = self.server.split('.')
        if len(parts) >= 3:
            prefix = '.'.join(parts[:3])
        else:
            prefix = self.server
        return f"{self.protocol}:{prefix}"


@lru_cache(maxsize=10000)
def parse_config_once(raw: str) -> Optional[ParsedConfig]:
    """Парсит конфиг один раз (кешируется)."""
    try:
        data, method = FallbackParser.parse_with_stats(raw)
        if not data:
            return None
        protocol = raw.split('://')[0].lower()
        if protocol == 'vmess':
            server = data.get('add', '')
            port = int(data.get('port', 0))
            credential = data.get('id', '')
        elif protocol == 'vless':
            server = data.get('address', '')
            port = int(data.get('port', 0))
            credential = data.get('uuid', '')
        elif protocol == 'trojan':
            server = data.get('address', '')
            port = int(data.get('port', 0))
            credential = data.get('password', '')
        elif protocol == 'ss':
            server = data.get('address', '')
            port = int(data.get('port', 0))
            credential = f"{data.get('method', '')}:{data.get('password', '')}"
        elif protocol in ('hysteria2', 'hy2'):
            server = data.get('address', '')
            port = int(data.get('port', 0))
            credential = data.get('password', '')
        elif protocol == 'tuic':
            server = data.get('address', '')
            port = int(data.get('port', 0))
            credential = f"{data.get('uuid', '')}:{data.get('password', '')}"
        else:
            server = data.get('address') or data.get('add') or data.get('host') or ''
            port = int(data.get('port', 0))
            credential = ''
        if not server or port <= 0:
            return None
        return ParsedConfig(
            raw=raw,
            protocol=protocol,
            server=server,
            port=port,
            credential=credential,
            parsed_data=data,
            parse_method=method,
            is_valid=True
        )
    except Exception as e:
        logger.debug(f"parse_config_once failed for {raw[:50]}...: {e}")
        return None


class OptimizedPipeline:
    """Оптимизированный пайплайн с autoclose и обработкой ошибок."""
    def __init__(self) -> None:
        self.config = ProxyConfig()
        self.region = self.config.region
        self.validator = ConfigValidator()
        self.deduplicator = DeepDeduplicator()
        self.quality_checker = ConfigQualityChecker(timeout=0, max_workers=1)
        self.scorer = ProfileScorer(region=self.region)
        self.output_file = 'configs/output_archive.txt'
        self.simple_file = 'configs/output_simple.txt'
        self.parsed_cache_file = 'configs/parsed_cache.json'
        self.name_mapping_file = 'configs/name_mapping.json'
        self.channel_stats_file = 'configs/channel_stats.json'
        self.channel_analyzer: Optional[ChannelQualityAnalyzer] = None
        self._shutdown_requested = False
        self._state: Dict = {}
        self.db = get_db()
        self.ARCHIVE_RETENTION_DAYS = 7
        self.checker_cache: Optional[ActiveChecker] = None
        self._parsed_cache: Dict[str, ParsedConfig] = {}
        self._session_pool = SessionPool()
        
        # Новые компоненты
        self.sni_probe = SNIProbe(timeout=5.0)
        self.reality_hunter = RealitySNIHunter(xray_core_path="xray", timeout=5.0)
        self.regional_scorer = RegionalScorer(region=self.region)
        self.regional_stats = RegionalStats()
        self.sni_filter = SNIFilter(allowed_snis=['cloudflare.com', 'www.cloudflare.com'])
        self.weight_updater = WeightUpdater(region=self.region)

        self._check_dependencies()
        self._setup_signal_handlers()

    def _check_dependencies(self) -> None:
        """Проверяет наличие зависимостей."""
        missing: List[str] = []
        try:
            import aiohttp
        except ImportError:
            missing.append("aiohttp")
        try:
            import bs4
        except ImportError:
            missing.append("beautifulsoup4")
        try:
            import numpy
        except ImportError:
            missing.append("numpy")
        try:
            import scipy
        except ImportError:
            missing.append("scipy")
        try:
            import tqdm
        except ImportError:
            missing.append("tqdm")
        try:
            import aiofiles
        except ImportError:
            missing.append("aiofiles")
        try:
            import maxminddb
        except ImportError:
            missing.append("maxminddb")
        if missing:
            logger.error(f"Missing required dependencies: {', '.join(missing)}")
            logger.error("Please install: pip install -r requirements.txt")
            sys.exit(1)

    def _setup_signal_handlers(self) -> None:
        """Настраивает обработчики сигналов для graceful shutdown."""
        def handler(sig: int, frame) -> None:
            logger.info(f"Received signal {sig}, initiating graceful shutdown...")
            self._shutdown_requested = True
        signal.signal(signal.SIGINT, handler)
        signal.signal(signal.SIGTERM, handler)

    def _get_cache_key(self, config: str) -> str:
        """Возвращает кеш-ключ для конфига."""
        return hashlib.md5(config.encode()).hexdigest()

    def _get_or_parse_config(self, raw: str) -> Optional[ParsedConfig]:
        """Возвращает распарсенный конфиг из кеша или парсит заново."""
        cache_key = self._get_cache_key(raw)
        if cache_key in self._parsed_cache:
            return self._parsed_cache[cache_key]
        parsed = parse_config_once(raw)
        if parsed:
            self._parsed_cache[cache_key] = parsed
        return parsed

    async def _load_parsed_cache_async(self) -> Dict:
        """Загружает кеш парсинга асинхронно."""
        if os.path.exists(self.parsed_cache_file):
            try:
                async with aiofiles.open(self.parsed_cache_file, 'r') as f:
                    content = await f.read()
                    if content:
                        return json.loads(content)
            except Exception as e:
                logger.warning(f"Failed to load parsed cache: {e}")
        return {}

    async def _save_parsed_cache_async(self, cache: Dict) -> None:
        """Сохраняет кеш парсинга асинхронно."""
        try:
            Path(self.parsed_cache_file).parent.mkdir(parents=True, exist_ok=True)
            async with aiofiles.open(self.parsed_cache_file, 'w') as f:
                await f.write(json.dumps(cache, indent=2))
        except Exception as e:
            logger.warning(f"Failed to save parsed cache: {e}")

    async def _load_name_mapping_async(self) -> Dict[str, str]:
        """Загружает маппинг имён асинхронно."""
        if os.path.exists(self.name_mapping_file):
            try:
                async with aiofiles.open(self.name_mapping_file, 'r', encoding='utf-8') as f:
                    content = await f.read()
                    return json.loads(content)
            except Exception:
                pass
        return {}

    async def _save_name_mapping_async(self, mapping: Dict[str, str]) -> None:
        """Сохраняет маппинг имён асинхронно."""
        try:
            Path(self.name_mapping_file).parent.mkdir(parents=True, exist_ok=True)
            async with aiofiles.open(self.name_mapping_file, 'w', encoding='utf-8') as f:
                await f.write(json.dumps(mapping, indent=2, ensure_ascii=False))
        except Exception as e:
            logger.error(f"Failed to save name mapping: {e}")

    def _get_config_key(self, config: str) -> str:
        """Возвращает ключ для конфига (учитывает протокол)."""
        parsed = self._get_or_parse_config(config)
        if parsed:
            return hashlib.md5(parsed.dedup_key.encode()).hexdigest()
        return hashlib.md5(config.encode()).hexdigest()

    def _generate_name(self, config: str) -> str:
        """Генерирует имя для конфига."""
        try:
            protocol = config.split('://')[0].upper()
            key = self._get_config_key(config)
            return f"{protocol}-{key[:8]}"
        except Exception:
            return f"config-{hashlib.md5(config.encode()).hexdigest()[:8]}"

    async def _load_archive_async(self) -> List[str]:
        """Загружает архив конфигов асинхронно."""
        if not os.path.exists(self.output_file):
            return []
        try:
            async with aiofiles.open(self.output_file, 'r', encoding='utf-8') as f:
                content = await f.read()
                return [line.strip() for line in content.splitlines() if line.strip() and not line.startswith('//')]
        except Exception as e:
            logger.warning(f"Failed to load archive: {e}")
            return []

    async def _save_archive_with_names_async(self, configs: List[str], mapping: Dict[str, str]) -> None:
        """Сохраняет архив с именами асинхронно."""
        for cfg in configs:
            key = self._get_config_key(cfg)
            if key not in mapping:
                mapping[key] = self._generate_name(cfg)
        lines = []
        for cfg in configs:
            key = self._get_config_key(cfg)
            name = mapping.get(key, '')
            if name:
                if '#' in cfg:
                    base = cfg.split('#')[0]
                    lines.append(f"{base}#{name}")
                else:
                    lines.append(f"{cfg}#{name}")
            else:
                lines.append(cfg)
        try:
            Path(self.output_file).parent.mkdir(parents=True, exist_ok=True)
            async with aiofiles.open(self.output_file, 'w', encoding='utf-8') as f:
                await f.write('\n'.join(lines) + '\n')
            await self._save_name_mapping_async(mapping)
        except Exception as e:
            logger.error(f"Failed to save archive: {e}")

    async def _save_simple_async(self, configs: List[str], mapping: Dict[str, str]) -> None:
        """Сохраняет простой вывод асинхронно."""
        lines = []
        for cfg in configs:
            key = self._get_config_key(cfg)
            name = mapping.get(key, '')
            if name:
                if '#' in cfg:
                    base = cfg.split('#')[0]
                    lines.append(f"{base}#{name}")
                else:
                    lines.append(f"{cfg}#{name}")
            else:
                lines.append(cfg)
        try:
            Path(self.simple_file).parent.mkdir(parents=True, exist_ok=True)
            async with aiofiles.open(self.simple_file, 'w', encoding='utf-8') as f:
                await f.write('\n'.join(lines) + '\n')
        except Exception as e:
            logger.error(f"Failed to save simple output: {e}")

    def _save_channel_stats(self, run_id: int) -> None:
        """Сохраняет статистику каналов."""
        try:
            for ch in self.config.SOURCE_URLS:
                m = ch.metrics
                metrics = {
                    'total_configs': m.total_configs,
                    'valid_configs': m.valid_configs,
                    'unique_configs': m.unique_configs,
                    'avg_response_time': m.avg_response_time,
                    'last_success': m.last_success_time.isoformat() if m.last_success_time else None,
                    'fail_count': m.fail_count,
                    'success_count': m.success_count,
                    'overall_score': m.overall_score,
                    'protocol_counts': m.protocol_counts or {}
                }
                self.db.update_channel(ch.url, metrics, enabled=ch.enabled)
                self.db.add_channel_history(ch.url, run_id, metrics)
            logger.info(f"✅ Channel stats saved to SQLite: {len(self.config.SOURCE_URLS)} channels")
        except Exception as e:
            logger.error(f"Failed to save channel stats: {e}")

    def _refresh_channel_health(self) -> None:
        """Обновляет состояние здоровья каналов."""
        try:
            self.channel_analyzer = ChannelQualityAnalyzer()
            urls = [ch.url for ch in self.config.SOURCE_URLS]
            for ch in self.config.SOURCE_URLS:
                state = self.channel_analyzer.get_channel_state(ch.url)
                if state == 'inactive':
                    ch.enabled = False
                    logger.info(f"Channel {ch.url} disabled (state: inactive).")
                else:
                    ch.enabled = True
            report = self.channel_analyzer.get_health_report()
            summary = report.get('summary', {})
            logger.info(
                f"📈 Channel health: active={summary.get('active', 0)}, "
                f"recovering={summary.get('recovering', 0)}, "
                f"inactive={summary.get('inactive', 0)} (total {summary.get('total', 0)})"
            )
        except Exception as e:
            logger.warning(f"Failed to refresh channel health: {e}")

    def _filter_by_age_with_score(self, configs: List[str], max_age_days: int, score_threshold: int = 80) -> List[str]:
        """Фильтрует конфиги по возрасту и скора."""
        if max_age_days <= 0:
            return []
        cutoff = datetime.now() - timedelta(days=max_age_days)
        filtered = []
        for cfg in configs:
            key = self._get_config_key(cfg)
            last_seen = self.db.get_profile_last_seen(key)
            if last_seen:
                try:
                    last_dt = datetime.fromisoformat(last_seen)
                    if last_dt >= cutoff:
                        filtered.append(cfg)
                        continue
                    profile = self.db.get_profile(key)
                    if profile and profile.get('overall_score', 0) > score_threshold:
                        filtered.append(cfg)
                        continue
                except:
                    pass
            filtered.append(cfg)
        return filtered

    def _build_probe_shortlist(self, configs: List[str], quality_scores: Dict[str, float]) -> List[str]:
        """Создаёт короткий список для проверки."""
        if not configs:
            return []
        probe_budget = max(250, ACTIVE_CHECKER_WORKERS * 6)
        if not USE_MAXIMUM_POWER:
            probe_budget = min(probe_budget, max(100, SPECIFIC_CONFIG_COUNT // 5))
        probe_budget = min(len(configs), probe_budget)

        server_caps: Dict[str, int] = {}
        shortlist: List[str] = []
        for cfg in sorted(configs, key=lambda c: quality_scores.get(c, 0.0), reverse=True):
            parsed = self._get_or_parse_config(cfg)
            if not parsed:
                continue
            server = parsed.server or 'unknown'
            used = server_caps.get(server, 0)
            if used >= 2 and len(shortlist) < probe_budget // 2:
                continue
            server_caps[server] = used + 1
            shortlist.append(cfg)
            if len(shortlist) >= probe_budget:
                break

        if len(shortlist) < probe_budget:
            seen = set(shortlist)
            for cfg in sorted(configs, key=lambda c: quality_scores.get(c, 0.0), reverse=True):
                if cfg not in seen:
                    shortlist.append(cfg)
                    seen.add(cfg)
                    if len(shortlist) >= probe_budget:
                        break
        return shortlist

    async def save_state(self) -> None:
        """Сохраняет состояние перед выключением."""
        logger.info("Saving state before shutdown...")
        try:
            if hasattr(self.deduplicator, '_bloom'):
                try:
                    await self.deduplicator._bloom.save()
                except Exception as e:
                    logger.warning(f"Failed to save bloom filter state: {e}")
            await self._session_pool.close_all()
        except Exception as e:
            logger.error(f"Error saving state: {e}")
        logger.info("State saved.")

    async def run(self) -> bool:
        """Запускает пайплайн."""
        start_time = time.time()
        fetcher = None
        try:
            logger.info("=" * 60)
            logger.info("🚀 Starting Proxy-Hunter Pipeline (optimized, async, SQLite)")
            logger.info("=" * 60)

            # Шаг 1: Сбор
            logger.info("📡 Fetching configurations...")
            fetcher = AsyncConfigFetcher(self.config)
            try:
                raw_configs = await fetcher.fetch_all()
            except Exception as e:
                logger.error(f"Failed to fetch configs: {e}")
                await fetcher.close()
                return False
            
            if self._shutdown_requested:
                await self.save_state()
                await fetcher.close()
                return False

            run_stats = {
                'timestamp': datetime.now().isoformat(),
                'total_raw': len(raw_configs),
                'total_valid': 0,
                'total_final': 0,
                'avg_score': 0.0,
                'p50_latency': 0.0,
                'p95_latency': 0.0,
                'p99_latency': 0.0,
                'success_rate': 0.0,
                'protocols': {},
                'geo_distribution': {},
                'anomalies': []
            }
            run_id = self.db.add_run(run_stats)
            self._save_channel_stats(run_id)
            self._refresh_channel_health()

            if not raw_configs:
                logger.error("No configs fetched.")
                await fetcher.close()
                return False
            logger.info(f"✅ Raw configs: {len(raw_configs)}")

            # Шаг 2: Парсинг и валидация
            logger.info("🔍 Validating and extracting server info...")
            parsed_cache = await self._load_parsed_cache_async()
            valid_configs = []
            parse_stats = {'strict': 0, 'heuristic': 0, 'failed': 0}
            with tqdm(total=len(raw_configs), desc="Parsing configs",
                      file=sys.stderr, mininterval=0.5, ncols=80, leave=False) as pbar:
                for cfg in raw_configs:
                    if self._shutdown_requested:
                        break
                    try:
                        parsed = self._get_or_parse_config(cfg)
                        if parsed and parsed.is_valid:
                            valid_configs.append(cfg)
                            if parsed.parse_method == 'strict':
                                parse_stats['strict'] += 1
                            else:
                                parse_stats['heuristic'] += 1
                            cache_key = self._get_cache_key(cfg)
                            parsed_cache[cache_key] = parsed.parsed_data
                        else:
                            parse_stats['failed'] += 1
                    except Exception as e:
                        logger.warning(f"Validation error for config: {cfg[:50]}... {e}")
                    pbar.update(1)

            if self._shutdown_requested:
                await self.save_state()
                await fetcher.close()
                return False

            await self._save_parsed_cache_async(parsed_cache)
            logger.info(f"✅ Valid configs: {len(valid_configs)}")
            logger.info(f"   Parse stats: strict={parse_stats['strict']}, heuristic={parse_stats['heuristic']}, failed={parse_stats['failed']}")

            if not valid_configs:
                logger.error("No valid configs found.")
                await fetcher.close()
                return False

            # Шаг 2.1: SNI-фильтрация
            logger.info("🔍 Applying SNI filtering (Buildcage emulation)...")
            filtered_by_sni = []
            for cfg in valid_configs:
                parsed = self._get_or_parse_config(cfg)
                if parsed and self.sni_filter.filter_config(cfg, parsed.parsed_data):
                    filtered_by_sni.append(cfg)
            logger.info(f"After SNI filtering: {len(filtered_by_sni)} configs (removed {len(valid_configs) - len(filtered_by_sni)})")
            if not filtered_by_sni:
                logger.warning("No configs passed SNI filter, using all valid configs")
                filtered_by_sni = valid_configs

            # Шаг 3: Пассивная оценка
            logger.info("⚡ Passive scoring profiles...")
            scored_configs = []
            with tqdm(total=len(filtered_by_sni), desc="Scoring configs",
                      file=sys.stderr, mininterval=0.5, ncols=80, leave=False) as pbar:
                for idx, cfg in enumerate(filtered_by_sni):
                    if self._shutdown_requested:
                        break
                    try:
                        parsed = self._get_or_parse_config(cfg)
                        if parsed and parsed.parsed_data:
                            score_info = self.scorer.preview_score(cfg, parsed.parsed_data)
                            base_score = score_info['score']
                            server = parsed.server
                            dc = is_datacenter_ip(server)
                            base_score *= 0.95 if dc else 1.05
                            base_score = max(0, min(100, base_score))
                            scored_configs.append({
                                'config': cfg,
                                'score': round(base_score, 2),
                                'stability': score_info['stability'],
                                'lifetime': score_info['lifetime'],
                                'is_datacenter': dc,
                                'server_type': 'datacenter' if dc else 'vps',
                                'parsed': parsed.parsed_data,
                            })
                    except Exception as e:
                        logger.error(f"Scoring error for config {idx}: {e}")
                    pbar.update(1)

            if self._shutdown_requested:
                await self.save_state()
                await fetcher.close()
                return False
            logger.info(f"✅ Passively scored {len(scored_configs)} configs")

            if not scored_configs:
                logger.error("No configs scored.")
                await fetcher.close()
                return False

            filtered = [item for item in scored_configs if item['score'] >= SCORE_MIN_THRESHOLD]
            logger.info(f"✅ After min_score filter: {len(filtered)}")
            if not filtered:
                logger.warning("No configs passed min_score filter, lowering threshold...")
                filtered = list(scored_configs)
                logger.info(f"✅ After lowered filter: {len(filtered)}")
            if self._shutdown_requested or not filtered:
                await self.save_state()
                await fetcher.close()
                return False

            # Шаг 4: Дедупликация до активной проверки
            logger.info("🧹 Deep deduplication before active probing...")
            quality_scores = {item['config']: item['score'] for item in filtered}
            deduped_candidates = await self.deduplicator.deduplicate_configs_async(
                [item['config'] for item in filtered],
                quality_scores,
            )
            logger.info(f"✅ After pre-probe dedup: {len(deduped_candidates)}")

            if self._shutdown_requested or not deduped_candidates:
                if self._shutdown_requested:
                    await self.save_state()
                await fetcher.close()
                return False

            # Шаг 5: Активная проверка
            logger.info("🔌 Active checking on top passive candidates...")
            if self.checker_cache is None:
                self.checker_cache = ActiveChecker(timeout=TCP_TIMEOUT, max_workers=ACTIVE_CHECKER_WORKERS)
            probe_shortlist = self._build_probe_shortlist(deduped_candidates, quality_scores)
            logger.info(f"   Probe shortlist: {len(probe_shortlist)} / {len(deduped_candidates)}")
            try:
                probe_results = await self.checker_cache.check_batch(probe_shortlist)
            except Exception as e:
                logger.error(f"Active checking failed: {e}")
                await self.save_state()
                await fetcher.close()
                return False
            
            probe_map = {item['config']: item for item in probe_results}

            probe_records = []
            good_configs = []
            strict_passive_floor = max(60.0, SCORE_MIN_THRESHOLD + 20.0)
            for cfg in deduped_candidates:
                parsed = self._get_or_parse_config(cfg)
                if not parsed or not parsed.parsed_data:
                    continue
                base_score = quality_scores.get(cfg, 0.0)
                probe = probe_map.get(cfg)
                if probe is None:
                    if base_score >= strict_passive_floor:
                        good_configs.append(cfg)
                    continue

                success = bool(probe.get('success'))
                latency = max(0.0, float(probe.get('latency', 0.0) or 0.0))
                committed = self.scorer.score_profile(
                    cfg,
                    parsed.parsed_data,
                    success=success,
                    latency=latency,
                    sni_used=probe.get('sni_override') or parsed.parsed_data.get('sni'),
                    host_used=parsed.parsed_data.get('host'),
                )
                self.scorer.record_local_result(cfg, parsed.parsed_data, success, latency)

                final_score = committed['score']
                if success:
                    latency_factor = max(0.90, min(1.12, 1200.0 / max(latency, 150.0))) if latency > 0 else 1.0
                    final_score = max(final_score, min(100.0, final_score * latency_factor))
                    good_configs.append(cfg)
                else:
                    final_score = min(final_score, base_score * 0.65)
                quality_scores[cfg] = round(max(0.0, min(100.0, final_score)), 2)

                profile_key = self.scorer.get_profile_key(cfg, parsed.parsed_data)
                probe_records.append({
                    'profile_key': profile_key,
                    'timestamp': datetime.now().isoformat(),
                    'success': success,
                    'latency': latency,
                    'protocol': parsed.protocol,
                    'transport': parsed.parsed_data.get('type', parsed.parsed_data.get('net', 'tcp')),
                    'sni_used': probe.get('sni_override') or parsed.parsed_data.get('sni'),
                    'host_used': parsed.parsed_data.get('host'),
                    'path_used': parsed.parsed_data.get('path'),
                    'attempt_number': probe.get('attempt_number', 1),
                    'total_attempts': probe.get('total_attempts', 1),
                    'error': probe.get('error'),
                })

            if probe_records:
                try:
                    self.db.add_probe_results_batch(probe_records)
                except Exception as e:
                    logger.error(f"Failed to save probe records: {e}")

            deduped = list(dict.fromkeys(good_configs))
            logger.info(f"✅ Selected after hybrid validation: {len(deduped)}")
            if not deduped:
                logger.warning("No configs confirmed by active checks; using strongest passive fallbacks.")
                deduped = sorted(deduped_candidates, key=lambda c: quality_scores.get(c, 0.0), reverse=True)[:100]

            # Шаг 6: Фильтрация по возрасту
            logger.info(f"⏳ Filtering configs by age (archive: {ARCHIVE_MAX_AGE_DAYS} days, simple: {SIMPLE_MAX_AGE_DAYS} days)")
            archive_configs = self._filter_by_age_with_score(deduped, ARCHIVE_MAX_AGE_DAYS)
            simple_configs = self._filter_by_age_with_score(deduped, SIMPLE_MAX_AGE_DAYS)
            logger.info(f"   Archive configs: {len(archive_configs)}")
            logger.info(f"   Simple configs: {len(simple_configs)}")

            old_archive = await self._load_archive_async()
            old_archive_filtered = self._filter_by_age_with_score(old_archive, ARCHIVE_MAX_AGE_DAYS)
            logger.info(f"   Old archive filtered: {len(old_archive)} -> {len(old_archive_filtered)}")

            sorted_by_score = sorted(simple_configs, key=lambda c: quality_scores.get(c, 0), reverse=True)
            simple_top = [c for c in sorted_by_score if quality_scores.get(c, 0) > 50][:100]
            logger.info(f"   Simple output (top-100, score>50): {len(simple_top)} configs")

            archive_sorted = sorted(archive_configs, key=lambda c: (quality_scores.get(c, 0), self._get_config_key(c)), reverse=True)
            archive_all = [c for c in archive_sorted if quality_scores.get(c, 0) > 0]
            logger.info(f"   Archive output (score>0): {len(archive_all)} configs")

            # Шаг 7: Архивация с именами
            logger.info("💾 Archiving logic (with name mapping)...")
            name_mapping = await self._load_name_mapping_async()
            for cfg in archive_all:
                key = self._get_config_key(cfg)
                if key not in name_mapping:
                    name_mapping[key] = self._generate_name(cfg)

            merged_archive = []
            seen_keys = set()
            for cfg in old_archive_filtered:
                key = self._get_config_key(cfg)
                if key not in seen_keys:
                    merged_archive.append(cfg)
                    seen_keys.add(key)
            for cfg in archive_all:
                key = self._get_config_key(cfg)
                if key not in seen_keys:
                    merged_archive.append(cfg)
                    seen_keys.add(key)

            # Сохраняем результаты
            await self._save_archive_with_names_async(merged_archive, name_mapping)
            await self._save_simple_async(simple_top, name_mapping)

            # Обновляем веса
            self.weight_updater.update_weights(quality_scores)

            # Выводим статистику
            run_stats['total_valid'] = len(valid_configs)
            run_stats['total_final'] = len(deduped)
            run_stats['avg_score'] = sum(quality_scores.values()) / len(quality_scores) if quality_scores else 0.0
            run_stats['success_rate'] = sum(1 for r in probe_results if r.get('success')) / len(probe_results) if probe_results else 0.0
            
            # Рассчитываем перцентили задержки
            latencies = [r.get('latency', -1) for r in probe_results if r.get('latency', -1) > 0]
            if latencies:
                import numpy as np
                run_stats['p50_latency'] = float(np.percentile(latencies, 50))
                run_stats['p95_latency'] = float(np.percentile(latencies, 95))
                run_stats['p99_latency'] = float(np.percentile(latencies, 99))
            
            # Сохраняем статистику запуска
            self.db.add_run(run_stats)
            
            # Очищаем старые данные
            self.db.cleanup_old_data()
            
            # Выводим итоговую статистику
            print_summary(run_stats, len(merged_archive), len(simple_top))
            
            logger.info(f"✅ Pipeline completed in {time.time() - start_time:.2f} seconds")
            return True

        except Exception as e:
            logger.error(f"Pipeline failed: {e}")
            logger.error(traceback.format_exc())
            return False
        finally:
            # Autoclose для всех ресурсов
            try:
                if fetcher:
                    await fetcher.close()
                if self.checker_cache:
                    await self.checker_cache.close()
                await self.save_state()
            except Exception as e:
                logger.error(f"Error during cleanup: {e}")


if __name__ == "__main__":
    pipeline = OptimizedPipeline()
    success = asyncio.run(pipeline.run())
    sys.exit(0 if success else 1)
