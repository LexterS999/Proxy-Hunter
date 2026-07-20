#!/usr/bin/env python3
"""
Оптимизированный пайплайн Proxy-Hunter с улучшенной оценкой,
интеллектуальным зондированием, ML-фильтрацией и кешированием.
"""

import sys
import os
import asyncio
import uvloop
asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

from db import get_db, _compress, _decompress
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import logging
import time
import traceback
import json
import hashlib
import shutil
import signal
from pathlib import Path
from typing import List, Dict, Optional, Set
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from logging.handlers import RotatingFileHandler

import aiofiles
import numpy as np
import pandas as pd
import joblib
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
from config_identity import ConfigIdentity

# Новые модули
from feature_extractor import FeatureExtractor
from probe_engine import IntelligentProbe
from anomaly_detector import AnomalyDetector
from channel_selector import ChannelSelector

logger = logging.getLogger(__name__)

class OptimizedPipeline:
    def __init__(self, config: Optional[ProxyConfig] = None):
        self.config = config or ProxyConfig()
        self.validator = ConfigValidator()
        self.deduplicator = DeepDeduplicator()
        self.quality_checker = ConfigQualityChecker(timeout=0, max_workers=1)
        self.scorer = ProfileScorer()
        self.output_file = 'configs/output_archive.txt'
        self.simple_file = 'configs/output_simple.txt'
        self.parsed_cache_file = 'configs/parsed_cache.json'
        self.name_mapping_file = 'configs/name_mapping.json'
        self.channel_stats_file = 'configs/channel_stats.json'
        self.channel_analyzer = None
        self._shutdown_requested = False
        self._state = {}
        self.db = get_db()
        self.ARCHIVE_RETENTION_DAYS = 7
        self._executor = ThreadPoolExecutor(max_workers=4)
        self.checker_cache = None
        self._health_applied = False

        # Новые компоненты
        self.feature_extractor = FeatureExtractor()
        self.probe_engine = IntelligentProbe(timeout=5.0, max_attempts=3)
        self.anomaly_detector = AnomalyDetector()
        self.channel_selector = ChannelSelector()
        self.model = None
        self.feature_cols = []
        self.cat_cols = []
        self._load_model()

        self._setup_logging()
        self._check_dependencies()
        self._setup_signal_handlers()

    def _load_model(self):
        """Загружает ML-модель, если она есть."""
        try:
            data = joblib.load('configs/quality_model.cbm')
            self.model = data['model']
            self.feature_cols = data['features']
            self.cat_cols = data['categorical']
            logger.info("✅ Quality model loaded successfully")
        except Exception as e:
            self.model = None
            logger.warning(f"Could not load quality model: {e}. Using fallback scoring.")

    def _setup_logging(self):
        log_dir = Path('logs')
        log_dir.mkdir(exist_ok=True)
        log_file = log_dir / 'pipeline.log'
        handler = RotatingFileHandler(
            str(log_file),
            maxBytes=10*1024*1024,
            backupCount=5,
            encoding='utf-8'
        )
        handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        logger.addHandler(handler)
        console = logging.StreamHandler()
        console.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        logger.addHandler(console)
        logger.setLevel(logging.INFO)

    def _check_dependencies(self):
        missing = []
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
            import catboost
        except ImportError:
            missing.append("catboost")
        if missing:
            logger.error(f"Missing required dependencies: {', '.join(missing)}")
            logger.error("Please install: pip install -r requirements.txt")
            sys.exit(1)

    def _setup_signal_handlers(self):
        def handler(sig, frame):
            logger.info(f"Received signal {sig}, initiating graceful shutdown...")
            self._shutdown_requested = True
        signal.signal(signal.SIGINT, handler)
        signal.signal(signal.SIGTERM, handler)

    def _get_cache_key(self, config: str) -> str:
        return hashlib.md5(config.encode()).hexdigest()

    async def _load_parsed_cache_async(self) -> Dict:
        if os.path.exists(self.parsed_cache_file):
            try:
                async with aiofiles.open(self.parsed_cache_file, 'r') as f:
                    content = await f.read()
                    if content:
                        return json.loads(content)
                    else:
                        logger.warning(f"Parsed cache file {self.parsed_cache_file} is empty, starting fresh.")
            except (json.JSONDecodeError, ValueError, OSError) as e:
                logger.warning(f"Failed to load parsed cache: {e}, starting fresh.")
        return {}

    async def _save_parsed_cache_async(self, cache: Dict):
        try:
            Path(self.parsed_cache_file).parent.mkdir(parents=True, exist_ok=True)
            import portalocker
            async with aiofiles.open(self.parsed_cache_file, 'w') as f:
                with open(self.parsed_cache_file, 'w') as sync_f:
                    portalocker.lock(sync_f, portalocker.LOCK_EX)
                    json.dump(cache, sync_f, indent=2)
                    portalocker.unlock(sync_f)
        except Exception as e:
            logger.warning(f"Failed to save parsed cache: {e}")

    async def _load_name_mapping_async(self) -> Dict[str, str]:
        if os.path.exists(self.name_mapping_file):
            try:
                async with aiofiles.open(self.name_mapping_file, 'r', encoding='utf-8') as f:
                    content = await f.read()
                    return json.loads(content)
            except Exception as e:
                logger.warning(f"Failed to load name mapping: {e}")
        return {}

    async def _save_name_mapping_async(self, mapping: Dict[str, str]):
        try:
            Path(self.name_mapping_file).parent.mkdir(parents=True, exist_ok=True)
            async with aiofiles.open(self.name_mapping_file, 'w', encoding='utf-8') as f:
                await f.write(json.dumps(mapping, indent=2, ensure_ascii=False))
        except Exception as e:
            logger.error(f"Failed to save name mapping: {e}")

    def _get_config_key(self, config: str) -> str:
        return ConfigIdentity.get_key(config)

    def _generate_name(self, config: str) -> str:
        try:
            protocol = config.split('://')[0].upper()
            key = self._get_config_key(config)
            return f"{protocol}-{key[:8]}"
        except:
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

    async def _save_archive_with_names_async(self, configs: List[str], mapping: Dict[str, str]):
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

    async def _save_simple_async(self, configs: List[str], mapping: Dict[str, str]):
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

    def _save_channel_stats(self, run_id: int):
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

    def _refresh_channel_health(self):
        if self._health_applied:
            return
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
                    logger.debug(f"Channel {ch.url} enabled (state: {state}).")
            report = self.channel_analyzer.get_health_report()
            summary = report.get('summary', {})
            logger.info(
                f"📈 Channel health: active={summary.get('active', 0)}, "
                f"recovering={summary.get('recovering', 0)}, "
                f"inactive={summary.get('inactive', 0)} (total {summary.get('total', 0)})"
            )
            self._health_applied = True
        except Exception as e:
            logger.warning(f"Failed to refresh channel health: {e}")

    async def save_state(self):
        logger.info("Saving state before shutdown...")
        if hasattr(self.deduplicator, '_bloom'):
            try:
                await self.deduplicator._bloom.save()
            except Exception as e:
                logger.warning(f"Failed to save bloom filter state: {e}")
        logger.info("State saved.")

    def _parse_config(self, config: str) -> Optional[Dict]:
        """Парсит конфигурацию и возвращает словарь с данными."""
        from parse_fallback import FallbackParser
        parsed, method = FallbackParser.parse_with_stats(config)
        if parsed:
            parsed['protocol'] = config.split('://')[0].lower()
        return parsed

    async def run(self) -> bool:
        saga_state = {
            'step': 'start',
            'timestamp': datetime.now().isoformat(),
            'raw_configs': None,
            'valid_configs': None,
            'scored_configs': None,
            'filtered_configs': None,
            'good_configs': None,
            'deduped_configs': None,
            'merged_configs': None
        }
        try:
            start_time = time.time()
            logger.info("=" * 60)
            logger.info("🚀 Starting Proxy-Hunter Pipeline (optimized, async, with ML)")
            logger.info("=" * 60)

            # Шаг 1: Сбор
            logger.info("📡 Fetching configurations...")
            fetcher = AsyncConfigFetcher(self.config)
            raw_configs = await fetcher.fetch_all()
            saga_state['step'] = 'fetched'
            saga_state['raw_configs'] = len(raw_configs)
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

            def parse_one(cfg):
                try:
                    if self.validator.is_valid_config(cfg):
                        cache_key = self._get_cache_key(cfg)
                        if cache_key in parsed_cache:
                            data = parsed_cache[cache_key]
                            if data:
                                return (cfg, 'strict' if data.get('method') == 'strict' else 'heuristic')
                            else:
                                return (None, 'failed')
                        else:
                            data, method = FallbackParser.parse_with_stats(cfg)
                            if data is None:
                                return (None, 'failed')
                            parsed_cache[cache_key] = data
                            if data:
                                return (cfg, method if method in ('strict', 'heuristic') else 'heuristic')
                            else:
                                return (None, 'failed')
                except Exception:
                    return (None, 'failed')

            loop = asyncio.get_event_loop()
            batch_size = 1000
            for i in range(0, len(raw_configs), batch_size):
                batch = raw_configs[i:i+batch_size]
                futures = [loop.run_in_executor(self._executor, parse_one, cfg) for cfg in batch]
                for future in asyncio.as_completed(futures):
                    cfg, method = await future
                    if cfg:
                        valid_configs.append(cfg)
                        parse_stats[method] = parse_stats.get(method, 0) + 1
                    else:
                        parse_stats['failed'] += 1

            if self._shutdown_requested:
                await self.save_state()
                return False
            await self._save_parsed_cache_async(parsed_cache)
            saga_state['step'] = 'validated'
            saga_state['valid_configs'] = len(valid_configs)
            logger.info(f"✅ Valid configs: {len(valid_configs)}")
            logger.info(f"   Parse stats: strict={parse_stats['strict']}, heuristic={parse_stats['heuristic']}, failed={parse_stats['failed']}")

            if not valid_configs:
                logger.error("No valid configs found.")
                return False

            # Шаг 3: Оценка и извлечение признаков
            logger.info("⚡ Scoring profiles and extracting features...")
            scored_configs = []
            features_list = []
            scored_lock = asyncio.Lock()

            def score_and_extract(cfg):
                try:
                    parsed = self._parse_config(cfg)
                    if not parsed:
                        return None
                    info = self.quality_checker.extract_server_info(cfg)
                    if info and info.get('parsed'):
                        score_info = self.scorer.score_profile(cfg, info['parsed'], success=True)
                        # Извлекаем признаки
                        key = self.feature_extractor.get_profile_key(cfg)
                        if key:
                            feats = self.feature_extractor.extract_features(key, cfg, parsed)
                            self.feature_extractor.update_features_db(feats)
                            return {
                                'config': cfg,
                                'score': score_info['score'],
                                'stability': score_info['stability'],
                                'lifetime': score_info['lifetime'],
                                'is_datacenter': False,
                                'server_type': 'UNK',
                                'parsed': parsed,
                                'features': feats,
                                'profile_key': key
                            }
                except Exception as e:
                    logger.debug(f"Score/extract failed: {e}")
                return None

            with tqdm(total=len(valid_configs), desc="Scoring & extracting") as pbar:
                for i in range(0, len(valid_configs), batch_size):
                    batch = valid_configs[i:i+batch_size]
                    futures = [loop.run_in_executor(self._executor, score_and_extract, cfg) for cfg in batch]
                    for future in asyncio.as_completed(futures):
                        result = await future
                        if result:
                            async with scored_lock:
                                scored_configs.append(result)
                                features_list.append(result['features'])
                        pbar.update(1)

            if self._shutdown_requested:
                await self.save_state()
                return False
            saga_state['step'] = 'scored'
            saga_state['scored_configs'] = len(scored_configs)
            logger.info(f"✅ Scored {len(scored_configs)} configs")

            if not scored_configs:
                logger.error("No configs scored.")
                return False

            # Шаг 4: ML-фильтрация (если модель доступна)
            if self.model is not None and len(features_list) > 10:
                try:
                    df = pd.DataFrame(features_list)
                    for col in self.cat_cols:
                        if col in df.columns:
                            df[col] = df[col].astype(str)
                    X = df[self.feature_cols + self.cat_cols]
                    predictions = self.model.predict(X)
                    for i, item in enumerate(scored_configs):
                        item['ml_score'] = predictions[i] if i < len(predictions) else 50.0
                except Exception as e:
                    logger.warning(f"ML prediction failed: {e}, using fallback")
                    for item in scored_configs:
                        item['ml_score'] = item['score']

                # Фильтрация по ML-скору
                min_ml_score = 30.0
                filtered_by_ml = [item for item in scored_configs if item.get('ml_score', 0) >= min_ml_score]
                logger.info(f"✅ ML filter (>{min_ml_score}): {len(scored_configs)} → {len(filtered_by_ml)}")
                scored_configs = filtered_by_ml
                if not scored_configs:
                    logger.error("No configs passed ML filter.")
                    return False
            else:
                for item in scored_configs:
                    item['ml_score'] = item['score']

            # Шаг 5: Аномалии
            anomaly_features = [f for f in features_list if self.anomaly_detector.predict(f)]
            logger.info(f"🔍 Detected {len(anomaly_features)} anomalous profiles")

            # Шаг 6: Интеллектуальная активная проверка
            logger.info("🔌 Intelligent probing (multi-attempt, protocol-aware)...")
            probe_results = []
            valid_configs_to_probe = [item['config'] for item in scored_configs]

            sem = asyncio.Semaphore(50)  # ограничение параллелизма

            async def probe_one(item):
                async with sem:
                    cfg = item['config']
                    parsed = item.get('parsed')
                    if not parsed:
                        parsed = self._parse_config(cfg)
                    if parsed:
                        result = await self.probe_engine.probe(cfg, parsed)
                        result['profile_key'] = item.get('profile_key', self.feature_extractor.get_profile_key(cfg))
                        return result
                    return {'success': False, 'error': 'parse_failed'}

            probe_tasks = [probe_one(item) for item in scored_configs]
            probe_results = await asyncio.gather(*probe_tasks, return_exceptions=True)

            # Обработка результатов
            good_configs = []
            for idx, res in enumerate(probe_results):
                if isinstance(res, Exception):
                    logger.debug(f"Probe exception: {res}")
                    continue
                if res.get('success'):
                    good_configs.append(scored_configs[idx]['config'])
                # Сохраняем историю зонда
                self.db.add_probe_history(res)

            logger.info(f"✅ Active check: {len(good_configs)} configs passed")
            saga_state['step'] = 'checked'
            saga_state['good_configs'] = len(good_configs)

            if not good_configs:
                error_counts = {}
                for res in probe_results:
                    if isinstance(res, dict):
                        err = res.get('error', 'unknown')
                        error_counts[err] = error_counts.get(err, 0) + 1
                logger.error("❌ No configs passed active check!")
                logger.error(f"   Error breakdown: {error_counts}")
                return False

            # Шаг 7: Дедупликация
            logger.info("🧹 Deep deduplication...")
            quality_scores = {item['config']: item.get('ml_score', item['score']) for item in scored_configs if item['config'] in good_configs}
            deduped = await self.deduplicator.deduplicate_configs_async(good_configs, quality_scores)
            logger.info(f"✅ After dedup: {len(deduped)}")
            saga_state['step'] = 'deduped'
            saga_state['deduped_configs'] = len(deduped)

            if self._shutdown_requested or not deduped:
                if self._shutdown_requested:
                    await self.save_state()
                return False

            # Шаг 8: Архивация с именами
            logger.info("💾 Archiving logic...")
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
            saga_state['step'] = 'archived'
            saga_state['merged_configs'] = len(merged_configs)

            await self._save_archive_with_names_async(merged_configs, name_mapping)
            await self._save_simple_async(new_configs_with_names, name_mapping)

            logger.info(f"✅ Archive saved: {len(merged_configs)} configs in {self.output_file}")
            logger.info(f"✅ Simple output saved: {len(new_configs_with_names)} configs in {self.simple_file}")

            # Шаг 9: Xray конфиг
            logger.info("📦 Generating Xray balanced config...")
            try:
                from xray_balancer import ConfigToXray
                converter = ConfigToXray(self.output_file, 'configs/xray_loadbalanced_config.json')
                converter.process_configs()
            except Exception as e:
                logger.warning(f"Xray balancer failed: {e}")

            # Шаг 10: Обновление статистики
            logger.info("📊 Updating run statistics in SQLite...")
            final_stats = {
                'total_raw': len(raw_configs),
                'total_valid': len(valid_configs),
                'total_final': len(merged_configs),
                'avg_score': sum(item.get('ml_score', item['score']) for item in scored_configs) / len(scored_configs) if scored_configs else 0,
                'protocols': {},
                'geo_distribution': {},
                'anomalies': [],
                'p50_latency': 0,
                'p95_latency': 0,
                'p99_latency': 0,
                'success_rate': len(good_configs) / len(scored_configs) if scored_configs else 0
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
                if hasattr(self.deduplicator, '_bloom'):
                    await self.deduplicator._bloom.save()
            except Exception as e:
                logger.warning(f"Error closing session pool or saving bloom: {e}")
            self._executor.shutdown(wait=False)


def main():
    pipeline = OptimizedPipeline()
    success = asyncio.run(pipeline.run())
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
