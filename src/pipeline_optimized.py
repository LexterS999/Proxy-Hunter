#!/usr/bin/env python3
"""
Оптимизированный пайплайн Proxy-Hunter с улучшенной оценкой,
активной проверкой (асинхронной), кешированием и прогресс-баром.
Добавлены: graceful shutdown (сигналы), инъекция зависимости для history,
проверка зависимостей, закрытие сессий, интеллектуальный анализ каналов.
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
from typing import List, Dict
from datetime import datetime

from tqdm import tqdm

from config import ProxyConfig
from fetch_configs import AsyncConfigFetcher
from config_validator import ConfigValidator
from deep_deduplicate import DeepDeduplicator
from config_quality import ConfigQualityChecker
from quality_analyzer_enhanced import EnhancedQualityAnalyzer
from profile_scorer import ProfileScorer
from rename_configs import ConfigRenamer
from enrich_configs import ConfigEnricher
from active_checker import ActiveChecker
from parse_fallback import FallbackParser
from session_pool import SessionPool
from channel_quality_analyzer import ChannelQualityAnalyzer
from protocol_registry import registry

# Настройка логирования с ротацией
from logging.handlers import RotatingFileHandler

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

root_logger = logging.getLogger()
for handler in root_logger.handlers[:]:
    root_logger.removeHandler(handler)

file_handler = RotatingFileHandler(
    'pipeline_debug.log',
    maxBytes=10*1024*1024,
    backupCount=3
)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
root_logger.addHandler(file_handler)

stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
root_logger.addHandler(stream_handler)


class OptimizedPipeline:
    def __init__(self):
        self.config = ProxyConfig()
        self.validator = ConfigValidator()
        self.deduplicator = DeepDeduplicator()
        self.quality_checker = ConfigQualityChecker(timeout=0, max_workers=1)
        self.analyzer = EnhancedQualityAnalyzer()
        self.scorer = ProfileScorer()
        self.output_file = 'configs/output.txt'
        self.location_cache_file = 'configs/location_cache.json'
        self.parsed_cache_file = 'configs/parsed_cache.json'
        self.channel_stats_file = 'configs/channel_stats.json'
        self.channel_analyzer = None
        self._shutdown_requested = False
        self._state = {}

        self._check_dependencies()

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
            import maxminddb
        except ImportError:
            missing.append("maxminddb")
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
        if missing:
            logger.error(f"Missing required dependencies: {', '.join(missing)}")
            logger.error("Please install: pip install -r requirements.txt")
            sys.exit(1)

    def _get_cache_key(self, config: str) -> str:
        return hashlib.md5(config.encode()).hexdigest()

    def _load_parsed_cache(self) -> Dict:
        if os.path.exists(self.parsed_cache_file):
            try:
                if os.path.getsize(self.parsed_cache_file) > 0:
                    with open(self.parsed_cache_file, 'r') as f:
                        return json.load(f)
                else:
                    logger.warning(f"Parsed cache file {self.parsed_cache_file} is empty, starting fresh.")
            except (json.JSONDecodeError, ValueError) as e:
                logger.warning(f"Failed to load parsed cache: {e}, starting fresh.")
        return {}

    def _save_parsed_cache(self, cache: Dict):
        try:
            Path(self.parsed_cache_file).parent.mkdir(parents=True, exist_ok=True)
            with open(self.parsed_cache_file, 'w') as f:
                json.dump(cache, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save parsed cache: {e}")

    def _safe_load_history(self) -> Dict:
        return self.analyzer.history

    def _save_channel_stats(self):
        try:
            channels_data = []
            for ch in self.config.SOURCE_URLS:
                m = ch.metrics
                last_success = m.last_success_time.isoformat() if m.last_success_time else None
                channels_data.append({
                    'url': ch.url,
                    'enabled': ch.enabled,
                    'metrics': {
                        'total_configs': m.total_configs,
                        'valid_configs': m.valid_configs,
                        'unique_configs': m.unique_configs,
                        'avg_response_time': m.avg_response_time,
                        'last_success': last_success,
                        'fail_count': m.fail_count,
                        'success_count': m.success_count,
                        'overall_score': m.overall_score,
                        'protocol_counts': m.protocol_counts or {}
                    }
                })
            payload = {
                'channels': channels_data,
                'last_updated': datetime.now().isoformat()
            }
            Path(self.channel_stats_file).parent.mkdir(parents=True, exist_ok=True)
            with open(self.channel_stats_file, 'w', encoding='utf-8') as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
            logger.info(f"✅ Channel stats saved: {len(channels_data)} channels")
        except Exception as e:
            logger.error(f"Failed to save channel stats: {e}")

    def _refresh_channel_health(self, history_data: Dict):
        """Обновляет здоровье каналов, используя переданные данные вместо повторного чтения с диска."""
        try:
            self.channel_analyzer = ChannelQualityAnalyzer()
            # Передаём уже загруженные данные
            self.channel_analyzer.update_health([ch.url for ch in self.config.SOURCE_URLS], history_data=history_data)
            report = self.channel_analyzer.get_health_report()
            summary = report.get('summary', {})
            logger.info(
                f"📈 Channel health: {summary.get('healthy', 0)} healthy / "
                f"{summary.get('unhealthy', 0)} unhealthy (total {summary.get('total', 0)})"
            )
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

    def _setup_signal_handlers(self):
        def handler(sig, frame):
            logger.info(f"Received signal {sig}, initiating graceful shutdown...")
            self._shutdown_requested = True
        signal.signal(signal.SIGINT, handler)
        signal.signal(signal.SIGTERM, handler)

    async def run(self) -> bool:
        try:
            self._setup_signal_handlers()

            start_time = time.time()
            logger.info("="*60)
            logger.info("🚀 Starting Proxy-Hunter Pipeline (optimized, async)")
            logger.info("="*60)

            # Шаг 1: Сбор конфигураций (асинхронный)
            logger.info("📡 Fetching configurations...")
            fetcher = AsyncConfigFetcher(self.config)
            raw_configs = await fetcher.fetch_all()
            if self._shutdown_requested:
                await self.save_state()
                return False

            # Шаг 1.5: Сохранение статистики каналов и интеллектуальный анализ
            logger.info("📊 Saving channel statistics...")
            self._save_channel_stats()
            # Загружаем свежую историю для анализа
            with open(self.channel_stats_file, 'r') as f:
                history_data = json.load(f)
            self._refresh_channel_health(history_data)

            if not raw_configs:
                logger.error("No configs fetched.")
                return False
            logger.info(f"✅ Raw configs: {len(raw_configs)}")

            # Шаг 2: Валидация и извлечение данных с кешированием
            logger.info("🔍 Validating and extracting server info...")
            parsed_cache = self._load_parsed_cache()
            valid_configs = []
            parse_stats = {'strict': 0, 'heuristic': 0, 'failed': 0}

            with tqdm(total=len(raw_configs), desc="Parsing configs") as pbar:
                for cfg in raw_configs:
                    if self._shutdown_requested:
                        break
                    try:
                        if self.validator.is_valid_config(cfg):
                            cache_key = self._get_cache_key(cfg)
                            if cache_key in parsed_cache:
                                parsed_data = parsed_cache[cache_key]
                                if parsed_data:
                                    valid_configs.append(cfg)
                                    parse_stats['strict' if parsed_data.get('method') == 'strict' else 'heuristic'] += 1
                                else:
                                    parse_stats['failed'] += 1
                            else:
                                data, method = FallbackParser.parse_with_stats(cfg)
                                if data:
                                    valid_configs.append(cfg)
                                    parse_stats[method if method in parse_stats else 'heuristic'] += 1
                                else:
                                    parse_stats['failed'] += 1
                                parsed_cache[cache_key] = data
                    except Exception as e:
                        logger.warning(f"Validation error for config: {cfg[:50]}... {e}")
                    pbar.update(1)

            if self._shutdown_requested:
                await self.save_state()
                return False
            self._save_parsed_cache(parsed_cache)
            logger.info(f"✅ Valid configs: {len(valid_configs)}")
            logger.info(f"   Parse stats: strict={parse_stats['strict']}, heuristic={parse_stats['heuristic']}, failed={parse_stats['failed']}")

            if not valid_configs:
                logger.error("No valid configs found.")
                return False

            # Шаг 3: Оценка каждого профиля
            logger.info("⚡ Scoring profiles...")
            scored_configs = []
            with tqdm(total=len(valid_configs), desc="Scoring configs") as pbar:
                for idx, cfg in enumerate(valid_configs):
                    if self._shutdown_requested:
                        break
                    try:
                        parsed = registry.parse(cfg)
                        if parsed:
                            score_info = self.scorer.score_profile(cfg, parsed, success=True)
                            scored_configs.append({
                                'config': cfg,
                                'score': score_info['score'],
                                'stability': score_info['stability'],
                                'lifetime': score_info['lifetime'],
                                'is_datacenter': score_info['is_datacenter'],
                                'server_type': score_info['server_type'],
                                'parsed': parsed
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

            # Шаг 4: Фильтрация по композитному скору
            min_score = 0.0
            filtered = [item for item in scored_configs if item['score'] >= min_score]
            logger.info(f"✅ After min_score filter: {len(filtered)}")

            if not filtered:
                logger.warning("No configs passed min_score filter, lowering threshold...")
                min_score = 0.0
                filtered = [item for item in scored_configs if item['score'] >= min_score]
                logger.info(f"✅ After lowered filter: {len(filtered)}")

            if self._shutdown_requested:
                await self.save_state()
                return False
            if not filtered:
                return False

            # Шаг 5: Активная проверка (асинхронная, с кешированием и фильтрацией)
            logger.info("🔌 Active checking (TCP SYN, cached, async)...")

            history = self._safe_load_history()
            checker = ActiveChecker(
                timeout=1.0,
                max_workers=None,
                max_latency=6000.0,
                history=history
            )

            configs_to_check = [item['config'] for item in filtered]
            check_results = await checker.check_batch(configs_to_check)

            if self._shutdown_requested:
                await self.save_state()
                return False

            await SessionPool().close()

            good_configs = [
                r['config'] for r in check_results
                if r.get('valid', False) and 0 <= r.get('latency', -1)
            ]
            logger.info(f"✅ Active check: {len(good_configs)} configs passed")

            if not good_configs:
                error_counts = {}
                for r in check_results:
                    err = r.get('error', 'unknown')
                    error_counts[err] = error_counts.get(err, 0) + 1
                logger.error("❌ No configs passed active check!")
                logger.error(f"   Error breakdown: {error_counts}")
                for i, r in enumerate(check_results[:5]):
                    logger.error(f"   Sample {i+1}: error={r.get('error')}, config={r.get('config', '')[:80]}")
                return False

            # Обновляем скоры на основе реальной задержки
            for result in check_results:
                if result.get('valid', False) and result.get('latency', -1) > 0:
                    latency_ms = result['latency']
                    latency_bonus = max(0, min(20, 20 * (1 - latency_ms / 3000)))
                    for item in filtered:
                        if item['config'] == result['config']:
                            item['score'] = min(100, item['score'] + latency_bonus)
                            break

            # Шаг 6: Дедупликация
            logger.info("🧹 Deep deduplication...")
            quality_scores = {item['config']: item['score'] for item in filtered if item['config'] in good_configs}
            deduped = await self.deduplicator.deduplicate_configs_async(good_configs, quality_scores)
            logger.info(f"✅ After dedup: {len(deduped)}")

            if self._shutdown_requested or not deduped:
                if self._shutdown_requested:
                    await self.save_state()
                return False

            # Шаг 7: Обогащение геоданными
            logger.info("🌍 Enriching configs with geolocation...")

            cache_exists = os.path.exists(self.location_cache_file)
            cache_empty = True
            if cache_exists:
                try:
                    if os.path.getsize(self.location_cache_file) > 0:
                        with open(self.location_cache_file, 'r') as f:
                            data = json.load(f)
                            if data:
                                cache_empty = False
                    else:
                        logger.warning(f"Location cache file {self.location_cache_file} is empty, treating as empty cache.")
                except (json.JSONDecodeError, ValueError) as e:
                    logger.warning(f"Location cache file {self.location_cache_file} is corrupted: {e}, treating as empty cache.")
                    cache_empty = True

            if cache_empty:
                logger.info("Location cache missing or empty, running enrich_configs...")
                enricher = ConfigEnricher()
                temp_file = 'configs/temp_for_enrich.txt'
                try:
                    with open(temp_file, 'w') as f:
                        for cfg in deduped:
                            f.write(cfg + '\n')
                    enricher.process_configs(temp_file, self.location_cache_file)
                except Exception as e:
                    logger.error(f"Error during enrich_configs: {e}")
                finally:
                    if os.path.exists(temp_file):
                        os.remove(temp_file)
            else:
                logger.info("Location cache found, skipping enrich_configs.")

            # Шаг 8: Сохранение результатов
            logger.info("💾 Saving output with new naming...")
            temp_file = 'configs/temp_for_rename.txt'
            try:
                with open(temp_file, 'w') as f:
                    for cfg in deduped:
                        f.write(cfg + '\n')
                renamer = ConfigRenamer(self.location_cache_file)
                renamer.process_configs(temp_file, self.output_file)
            except Exception as e:
                logger.error(f"Error during rename_configs: {e}")
            finally:
                if os.path.exists(temp_file):
                    os.remove(temp_file)

            # Шаг 9: Сохранение упрощённого списка
            logger.info("📄 Saving simple output...")
            simple_file = 'configs/output_simple.txt'
            try:
                with open(self.output_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
            except FileNotFoundError:
                logger.error(f"Output file {self.output_file} not found, cannot create simple output.")
                return False

            simple_configs = []
            for line in lines:
                line = line.strip()
                if line.startswith('//') or not line:
                    continue
                simple_configs.append(line)
            try:
                with open(simple_file, 'w', encoding='utf-8') as f:
                    for cfg in simple_configs:
                        f.write(cfg + '\n')
                logger.info(f"✅ Simple output saved: {len(simple_configs)} configs")
            except Exception as e:
                logger.error(f"Failed to write simple output: {e}")

            # Шаг 10: Обновление истории качества
            logger.info("📊 Updating quality history...")
            stats = {
                'raw': len(raw_configs),
                'valid': len(valid_configs),
                'final': len(deduped),
                'avg_score': sum(item['score'] for item in filtered) / len(filtered) if filtered else 0,
                'protocols': {},
                'geo_distribution': {}
            }
            self.analyzer.save_run_stats(stats)

            elapsed = time.time() - start_time
            logger.info("="*60)
            logger.info(f"✅ Pipeline completed in {elapsed:.2f}s")
            logger.info(f"📊 Final configs: {len(deduped)}")
            logger.info("="*60)
            return True

        except KeyboardInterrupt:
            logger.warning("⚠️ Pipeline interrupted by user.")
            await self.save_state()
            return False
        except Exception as e:
            logger.error(f"❌ Pipeline failed: {e}\n{traceback.format_exc()}")
            return False


def main():
    pipeline = OptimizedPipeline()
    success = asyncio.run(pipeline.run())
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
