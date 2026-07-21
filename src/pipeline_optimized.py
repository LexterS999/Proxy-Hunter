#!/usr/bin/env python3
"""
Оптимизированный пайплайн Proxy-Hunter с улучшенной оценкой,
активной проверкой (асинхронной), кешированием, graceful shutdown,
и использованием aiofiles для всех файловых операций.

Добавлены:
- SNI Probe для тестирования с несколькими SNI
- Региональный скоринг с бонусами/штрафами
- Сбор статистики локальных проверок
- Интеграция RealitySNIHunter
- Автоматическое обновление весов
"""

import sys
import os
from db import HistoryDB, _compress, _decompress
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
from typing import List, Dict, Optional, Set
from datetime import datetime, timedelta
from dataclasses import dataclass, field

import aiofiles
from tqdm import tqdm

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
from db import HistoryDB

# Новые импорты
from sni_probe import SNIProbe
from reality_sni_hunter import RealitySNIHunter
from regional_scorer import RegionalScorer
from regional_stats import RegionalStats
from sni_filter import SNIFilter
from weight_updater import WeightUpdater

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


@dataclass
class ParsedConfig:
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
        return f"{self.server}:{self.port}:{self.protocol}:{self.credential}"

    @property
    def prefix_key(self) -> str:
        parts = self.server.split('.')
        if len(parts) >= 3:
            prefix = '.'.join(parts[:3])
        else:
            prefix = self.server
        return f"{self.protocol}:{prefix}"


def parse_config_once(raw: str) -> Optional[ParsedConfig]:
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
        self.db = HistoryDB()
        self.ARCHIVE_RETENTION_DAYS = 7
        self.checker_cache: Optional[ActiveChecker] = None
        self._parsed_cache: Dict[str, ParsedConfig] = {}
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
        if missing:
            logger.error(f"Missing required dependencies: {', '.join(missing)}")
            logger.error("Please install: pip install -r requirements.txt")
            sys.exit(1)

    def _setup_signal_handlers(self) -> None:
        def handler(sig: int, frame) -> None:
            logger.info(f"Received signal {sig}, initiating graceful shutdown...")
            self._shutdown_requested = True
        signal.signal(signal.SIGINT, handler)
        signal.signal(signal.SIGTERM, handler)

    def _get_cache_key(self, config: str) -> str:
        return hashlib.md5(config.encode()).hexdigest()

    def _get_or_parse_config(self, raw: str) -> Optional[ParsedConfig]:
        cache_key = self._get_cache_key(raw)
        if cache_key in self._parsed_cache:
            return self._parsed_cache[cache_key]
        parsed = parse_config_once(raw)
        if parsed:
            self._parsed_cache[cache_key] = parsed
        return parsed

    async def _load_parsed_cache_async(self) -> Dict:
        if os.path.exists(self.parsed_cache_file):
            try:
                async with aiofiles.open(self.parsed_cache_file, 'r') as f:
                    content = await f.read()
                    if content:
                        return json.loads(content)
            except:
                pass
        return {}

    async def _save_parsed_cache_async(self, cache: Dict) -> None:
        try:
            Path(self.parsed_cache_file).parent.mkdir(parents=True, exist_ok=True)
            async with aiofiles.open(self.parsed_cache_file, 'w') as f:
                await f.write(json.dumps(cache, indent=2))
        except Exception as e:
            logger.warning(f"Failed to save parsed cache: {e}")

    async def _load_name_mapping_async(self) -> Dict[str, str]:
        if os.path.exists(self.name_mapping_file):
            try:
                async with aiofiles.open(self.name_mapping_file, 'r', encoding='utf-8') as f:
                    content = await f.read()
                    return json.loads(content)
            except:
                pass
        return {}

    async def _save_name_mapping_async(self, mapping: Dict[str, str]) -> None:
        try:
            Path(self.name_mapping_file).parent.mkdir(parents=True, exist_ok=True)
            async with aiofiles.open(self.name_mapping_file, 'w', encoding='utf-8') as f:
                await f.write(json.dumps(mapping, indent=2, ensure_ascii=False))
        except Exception as e:
            logger.error(f"Failed to save name mapping: {e}")

    def _get_config_key(self, config: str) -> str:
        parsed = self._get_or_parse_config(config)
        if parsed:
            return hashlib.md5(parsed.dedup_key.encode()).hexdigest()
        return hashlib.md5(config.encode()).hexdigest()

    def _generate_name(self, config: str) -> str:
        try:
            protocol = config.split('://')[0].upper()
            key = self._get_config_key(config)
            return f"{protocol}-{key[:8]}"
        except Exception:
            return f"config-{hashlib.md5(config.encode()).hexdigest()[:8]}"

    async def _load_archive_async(self) -> List[str]:
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

    def _safe_load_history(self) -> Dict:
        return {}

    def _save_channel_stats(self, run_id: int) -> None:
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

    async def save_state(self) -> None:
        logger.info("Saving state before shutdown...")
        if hasattr(self.deduplicator, '_bloom'):
            try:
                await self.deduplicator._bloom.save()
            except Exception as e:
                logger.warning(f"Failed to save bloom filter state: {e}")
        logger.info("State saved.")

    async def run(self) -> bool:
        try:
            start_time = time.time()
            logger.info("=" * 60)
            logger.info("🚀 Starting Proxy-Hunter Pipeline (optimized, async, SQLite, no GeoIP)")
            logger.info("=" * 60)

            # Шаг 1: Сбор
            logger.info("📡 Fetching configurations...")
            fetcher = AsyncConfigFetcher(self.config)
            raw_configs = await fetcher.fetch_all()
            if self._shutdown_requested:
                await self.save_state()
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
                return False
            logger.info(f"✅ Raw configs: {len(raw_configs)}")

            # Шаг 2: Парсинг и валидация
            logger.info("🔍 Validating and extracting server info...")
            parsed_cache = await self._load_parsed_cache_async()
            valid_configs = []
            parse_stats = {'strict': 0, 'heuristic': 0, 'failed': 0}
            with tqdm(total=len(raw_configs), desc="Parsing configs") as pbar:
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
                return False
            await self._save_parsed_cache_async(parsed_cache)
            logger.info(f"✅ Valid configs: {len(valid_configs)}")
            logger.info(f"   Parse stats: strict={parse_stats['strict']}, heuristic={parse_stats['heuristic']}, failed={parse_stats['failed']}")

            if not valid_configs:
                logger.error("No valid configs found.")
                return False

            # Шаг 2.1: SNI-фильтрация (эмуляция блокировок)
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

            # Шаг 3: Оценка
            logger.info("⚡ Scoring profiles...")
            scored_configs = []
            with tqdm(total=len(filtered_by_sni), desc="Scoring configs") as pbar:
                for idx, cfg in enumerate(filtered_by_sni):
                    if self._shutdown_requested:
                        break
                    try:
                        parsed = self._get_or_parse_config(cfg)
                        if parsed and parsed.parsed_data:
                            score_info = self.scorer.score_profile(cfg, parsed.parsed_data, success=True)
                            parsed.score = score_info['score']
                            parsed.stability = score_info['stability']
                            parsed.lifetime = score_info['lifetime']
                            scored_configs.append({
                                'config': cfg,
                                'score': score_info['score'],
                                'stability': score_info['stability'],
                                'lifetime': score_info['lifetime'],
                                'is_datacenter': False,
                                'server_type': 'UNK',
                                'parsed': parsed.parsed_data
                            })
                    except Exception as e:
                        logger.error(f"Scoring error for config {idx}: {e}")
                    pbar.update(1)

            if self._shutdown_requested:
                await self.save_state()
                return False
            logger.info(f"✅ Scored {len(scored_configs)} configs")

            if not scored_configs:
                logger.error("No configs scored.")
                return False

            # Шаг 4: Фильтр по скору
            min_score = 0.0
            filtered = [item for item in scored_configs if item['score'] >= min_score]
            logger.info(f"✅ After min_score filter: {len(filtered)}")
            if not filtered:
                logger.warning("No configs passed min_score filter, lowering threshold...")
                min_score = 0.0
                filtered = [item for item in scored_configs if item['score'] >= min_score]
                logger.info(f"✅ After lowered filter: {len(filtered)}")
            if self._shutdown_requested or not filtered:
                await self.save_state()
                return False

            # Шаг 5: Активная проверка (с кешированием)
            logger.info("🔌 Active checking (TCP, HTTP HEAD, async, cached)...")
            history = self._safe_load_history()
            if self.checker_cache is None:
                self.checker_cache = ActiveChecker(
                    timeout=5.0,
                    max_workers=None,
                    max_latency=10000.0,
                    history=history,
                    cache_ttl=3600
                )
            checker = self.checker_cache

            configs_to_check = [item['config'] for item in filtered]
            check_results = await checker.check_batch(configs_to_check)

            if self._shutdown_requested:
                await self.save_state()
                return False

            await SessionPool().close()

            # Сохраняем локальную статистику
            for result in check_results:
                if result.get('valid', False):
                    config = result['config']
                    parsed = self._get_or_parse_config(config)
                    if parsed:
                        self.scorer.record_local_result(
                            config, parsed.parsed_data,
                            success=result.get('success', False),
                            latency=result.get('latency', -1)
                        )

            good_configs = [
                r['config'] for r in check_results
                if r.get('valid', False) and r.get('latency', -1) > 0
            ]
            logger.info(f"✅ Active check: {len(good_configs)} configs passed")

            if not good_configs:
                error_counts = {}
                for r in check_results:
                    err = r.get('error', 'unknown')
                    error_counts[err] = error_counts.get(err, 0) + 1
                logger.error("❌ No configs passed active check!")
                logger.error(f"   Error breakdown: {error_counts}")
                return False

            # Обновляем скоры
            for result in check_results:
                if result.get('valid', False) and result.get('latency', -1) > 0:
                    latency_ms = result['latency']
                    latency_bonus = max(0, min(20, 20 * (1 - latency_ms / 3000)))
                    for item in filtered:
                        if item['config'] == result['config']:
                            item['score'] = min(100, item['score'] + latency_bonus)
                            break

            # Шаг 5.1: SNI-тестирование для топ-10 конфигов
            logger.info("🔬 SNI multi-test for top 10 configs...")
            top_configs = filtered[:10]
            sni_list = ['cloudflare.com', 'google.com', 'youtube.com', 'speedtest.net', 'dl.google.com']
            for item in top_configs:
                cfg = item['config']
                try:
                    sni_results = await checker.test_with_multiple_sni(cfg, sni_list)
                    if sni_results and 'error' not in sni_results:
                        working_snis = [s for s, res in sni_results.items() if res.get('success')]
                        if working_snis:
                            item['score'] += 10 * len(working_snis) / len(sni_list)
                except Exception as e:
                    logger.debug(f"SNI test failed for {cfg[:50]}: {e}")

            # Шаг 5.2: Интеграция RealitySNIHunter (сканирование SNI)
            logger.info("🔍 Scanning for working SNIs via RealitySNIHunter...")
            try:
                ip_range = "104.16.0.0/16"  # Cloudflare IP range
                found_snis = await self.reality_hunter.hunt(ip_range, top_n=10)
                if found_snis:
                    logger.info(f"Found {len(found_snis)} working SNIs: {[s['sni'] for s in found_snis]}")
                    for item in filtered:
                        server = item.get('parsed', {}).get('address') or item.get('parsed', {}).get('add')
                        if server:
                            for entry in found_snis:
                                if entry['ip'] == server:
                                    item['score'] *= 1.2
                                    break
            except Exception as e:
                logger.warning(f"RealitySNIHunter scan failed: {e}")

            # Шаг 6: Дедупликация
            logger.info("🧹 Deep deduplication (new configs)...")
            quality_scores = {item['config']: item['score'] for item in filtered if item['config'] in good_configs}
            deduped = await self.deduplicator.deduplicate_configs_async(good_configs, quality_scores)
            logger.info(f"✅ After dedup: {len(deduped)}")

            if self._shutdown_requested or not deduped:
                if self._shutdown_requested:
                    await self.save_state()
                return False

            # Шаг 7: Архивация с именами
            logger.info("💾 Archiving logic (with name mapping)...")
            name_mapping = await self._load_name_mapping_async()
            new_configs_with_names = []
            for cfg in deduped:
                key = self._get_config_key(cfg)
                if key not in name_mapping:
                    name_mapping[key] = self._generate_name(cfg)
                new_configs_with_names.append(cfg)
            archive_configs = await self._load_archive_async()
            seen_keys = set()
            merged_configs = []
            for cfg in archive_configs + new_configs_with_names:
                key = self._get_config_key(cfg)
                if key not in seen_keys:
                    seen_keys.add(key)
                    merged_configs.append(cfg)
            logger.info(f"🔄 Merged archive: {len(archive_configs)} old + {len(new_configs_with_names)} new → {len(merged_configs)} unique")

            await self._save_archive_with_names_async(merged_configs, name_mapping)
            await self._save_simple_async(new_configs_with_names, name_mapping)

            logger.info(f"✅ Archive saved: {len(merged_configs)} configs in {self.output_file}")
            logger.info(f"✅ Simple output saved: {len(new_configs_with_names)} configs in {self.simple_file}")

            # Шаг 8: Xray конфиг
            logger.info("📦 Generating Xray balanced config...")
            try:
                from xray_balancer import ConfigToXray
                converter = ConfigToXray(self.output_file, 'configs/xray_loadbalanced_config.json')
                converter.process_configs()
            except Exception as e:
                logger.warning(f"Xray balancer failed: {e}")

            # Шаг 9: Обновление статистики
            logger.info("📊 Updating run statistics in SQLite...")
            final_stats = {
                'total_raw': len(raw_configs),
                'total_valid': len(valid_configs),
                'total_final': len(merged_configs),
                'avg_score': sum(item['score'] for item in filtered) / len(filtered) if filtered else 0,
                'protocols': {},
                'geo_distribution': {},
                'anomalies': [],
                'p50_latency': 0,
                'p95_latency': 0,
                'p99_latency': 0,
                'success_rate': len(good_configs) / len(filtered) if filtered else 0
            }
            with self.db._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE runs SET
                        total_raw = ?,
                        total_valid = ?,
                        total_final = ?,
                        avg_score = ?,
                        p50_latency = ?,
                        p95_latency = ?,
                        p99_latency = ?,
                        success_rate = ?,
                        protocols = ?,
                        geo_distribution = ?,
                        anomalies = ?
                    WHERE id = ?
                ''', (
                    final_stats['total_raw'],
                    final_stats['total_valid'],
                    final_stats['total_final'],
                    final_stats['avg_score'],
                    final_stats.get('p50_latency', 0),
                    final_stats.get('p95_latency', 0),
                    final_stats.get('p99_latency', 0),
                    final_stats['success_rate'],
                    _compress(final_stats.get('protocols', {})),
                    _compress(final_stats.get('geo_distribution', {})),
                    _compress(final_stats.get('anomalies', [])),
                    run_id
                ))
                conn.commit()
            logger.info("✅ Run statistics updated.")

            # Шаг 10: Периодическое обновление весов
            logger.info("⚖️ Updating regional weights...")
            try:
                self.weight_updater.update()
            except Exception as e:
                logger.warning(f"Weight update failed: {e}")

            elapsed = time.time() - start_time
            logger.info("=" * 60)
            logger.info(f"✅ Pipeline completed in {elapsed:.2f}s")
            logger.info(f"📊 Final configs in archive: {len(merged_configs)}")
            logger.info("=" * 60)
            return True

        except KeyboardInterrupt:
            logger.warning("⚠️ Pipeline interrupted by user.")
            await self.save_state()
            return False
        except Exception as e:
            logger.error(f"❌ Pipeline failed: {e}\n{traceback.format_exc()}")
            return False
        finally:
            try:
                await SessionPool().close()
            except Exception as e:
                logger.warning(f"Error closing session pool: {e}")


def main() -> None:
    pipeline = OptimizedPipeline()
    success = asyncio.run(pipeline.run())
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
