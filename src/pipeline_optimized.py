#!/usr/bin/env python3
"""
Оптимизированный пайплайн Proxy-Hunter с улучшенной оценкой,
активной проверкой (асинхронной), кешированием и прогресс-баром.
Использует SQLite для долгосрочного хранения истории.
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
from db import HistoryDB

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


class OptimizedPipeline:
    def __init__(self):
        self.config = ProxyConfig()
        self.validator = ConfigValidator()
        self.deduplicator = DeepDeduplicator()
        self.quality_checker = ConfigQualityChecker(timeout=0, max_workers=1)
        self.scorer = ProfileScorer()
        self.output_file = 'configs/output_archive.txt'          # архивный файл
        self.simple_file = 'configs/output_simple.txt'          # свежие конфиги
        self.location_cache_file = 'configs/location_cache.json'
        self.parsed_cache_file = 'configs/parsed_cache.json'
        self.name_mapping_file = 'configs/name_mapping.json'   # новый файл для маппинга имён
        self.channel_stats_file = 'configs/channel_stats.json'
        self.channel_analyzer = None
        self._shutdown_requested = False
        self._state = {}
        self.db = HistoryDB()
        self.ARCHIVE_RETENTION_DAYS = 7

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

    def _load_name_mapping(self) -> Dict[str, str]:
        """Загружает маппинг конфиг -> имя из JSON."""
        if os.path.exists(self.name_mapping_file):
            try:
                with open(self.name_mapping_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load name mapping: {e}")
        return {}

    def _save_name_mapping(self, mapping: Dict[str, str]):
        """Сохраняет маппинг конфиг -> имя в JSON."""
        try:
            Path(self.name_mapping_file).parent.mkdir(parents=True, exist_ok=True)
            with open(self.name_mapping_file, 'w', encoding='utf-8') as f:
                json.dump(mapping, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Failed to save name mapping: {e}")

    def _get_config_key(self, config: str) -> str:
        """
        Генерирует уникальный ключ для конфига на основе server:port:protocol:credential.
        Используется для поиска в маппинге имён.
        """
        try:
            data, _ = FallbackParser.parse_with_stats(config)
            if not data:
                return hashlib.md5(config.encode()).hexdigest()
            protocol = config.split('://')[0].lower()
            if protocol == 'vmess':
                server = data.get('add', '')
                port = data.get('port', 0)
                credential = data.get('id', '')
            elif protocol == 'vless':
                server = data.get('address', '')
                port = data.get('port', 0)
                credential = data.get('uuid', '')
            elif protocol == 'trojan':
                server = data.get('address', '')
                port = data.get('port', 0)
                credential = data.get('password', '')
            elif protocol == 'ss':
                server = data.get('address', '')
                port = data.get('port', 0)
                credential = f"{data.get('method', '')}:{data.get('password', '')}"
            else:
                server = data.get('address') or data.get('add') or data.get('host') or ''
                port = data.get('port', 0)
                credential = ''
            key = f"{server}:{port}:{protocol}:{credential}"
            return hashlib.md5(key.encode()).hexdigest()
        except Exception as e:
            logger.debug(f"Failed to generate config key: {e}")
            return hashlib.md5(config.encode()).hexdigest()

    def _generate_name(self, config: str) -> str:
        """
        Генерирует имя для конфига, используя ConfigRenamer, но без обращения к GeoIP
        (использует кеш). Возвращает только имя (без перестроения URI).
        """
        try:
            # Используем существующий реймер, но только для генерации имени
            renamer = ConfigRenamer(self.location_cache_file)
            # Переименовываем конфиг, получаем полную строку с #имя
            renamed = renamer.rename_config(config, 0)
            if renamed and '#' in renamed:
                return renamed.split('#', 1)[1]
            return ''
        except Exception as e:
            logger.debug(f"Failed to generate name: {e}")
            return ''

    def _load_archive(self) -> List[str]:
        """Загружает все конфиги из архивного файла."""
        if not os.path.exists(self.output_file):
            return []
        try:
            with open(self.output_file, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('//')]
        except Exception as e:
            logger.warning(f"Failed to load archive: {e}")
            return []

    def _save_archive_with_names(self, configs: List[str], mapping: Dict[str, str]):
        """
        Сохраняет архив, подставляя имена из mapping.
        Для конфигов, которых нет в mapping, генерирует новое имя и добавляет.
        """
        # Убедимся, что все конфиги есть в mapping
        for cfg in configs:
            key = self._get_config_key(cfg)
            if key not in mapping:
                name = self._generate_name(cfg)
                if name:
                    mapping[key] = name
                else:
                    # Если имя не сгенерировалось, используем хеш
                    mapping[key] = f"config-{key[:8]}"

        # Строим строки для записи
        lines = []
        for cfg in configs:
            key = self._get_config_key(cfg)
            name = mapping.get(key, '')
            if name:
                # Вставляем имя в конфиг
                if '#' in cfg:
                    base = cfg.split('#')[0]
                    lines.append(f"{base}#{name}")
                else:
                    lines.append(f"{cfg}#{name}")
            else:
                lines.append(cfg)

        try:
            Path(self.output_file).parent.mkdir(parents=True, exist_ok=True)
            with open(self.output_file, 'w', encoding='utf-8') as f:
                for line in lines:
                    f.write(line + '\n')
            # Сохраняем обновлённый mapping
            self._save_name_mapping(mapping)
        except Exception as e:
            logger.error(f"Failed to save archive: {e}")

    def _save_simple(self, configs: List[str], mapping: Dict[str, str]):
        """Сохраняет только свежие конфиги (без архивации) с именами."""
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
            with open(self.simple_file, 'w', encoding='utf-8') as f:
                for line in lines:
                    f.write(line + '\n')
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
        try:
            self.channel_analyzer = ChannelQualityAnalyzer()
            urls = [ch.url for ch in self.config.SOURCE_URLS]
            for ch in self.config.SOURCE_URLS:
                if not self.channel_analyzer.is_channel_healthy(ch.url):
                    ch.enabled = False
                    logger.info(f"Channel {ch.url} disabled due to poor long-term health.")
                else:
                    ch.enabled = True
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
            logger.info("=" * 60)
            logger.info("🚀 Starting Proxy-Hunter Pipeline (optimized, async, SQLite)")
            logger.info("=" * 60)

            # Шаг 1: Сбор конфигураций
            logger.info("📡 Fetching configurations...")
            fetcher = AsyncConfigFetcher(self.config)
            raw_configs = await fetcher.fetch_all()
            if self._shutdown_requested:
                await self.save_state()
                return False

            # Шаг 1.5: Сохранение статистики каналов в SQLite
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
                        info = self.quality_checker.extract_server_info(cfg)
                        if info and info.get('parsed'):
                            score_info = self.scorer.score_profile(cfg, info['parsed'], success=True)
                            scored_configs.append({
                                'config': cfg,
                                'score': score_info['score'],
                                'stability': score_info['stability'],
                                'lifetime': score_info['lifetime'],
                                'is_datacenter': score_info['is_datacenter'],
                                'server_type': score_info['server_type'],
                                'parsed': info['parsed']
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

            # Шаг 5: Активная проверка
            logger.info("🔌 Active checking (TCP SYN, cached, async)...")
            history = self._safe_load_history()
            checker = ActiveChecker(
                timeout=2.0,
                max_workers=None,
                max_latency=10000.0,
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

            # Шаг 6: Дедупликация (только для новых конфигов)
            logger.info("🧹 Deep deduplication (new configs)...")
            quality_scores = {item['config']: item['score'] for item in filtered if item['config'] in good_configs}
            deduped = await self.deduplicator.deduplicate_configs_async(good_configs, quality_scores)
            logger.info(f"✅ After dedup: {len(deduped)}")

            if self._shutdown_requested or not deduped:
                if self._shutdown_requested:
                    await self.save_state()
                return False

            # Шаг 7: Обогащение геоданными (если нужно)
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
                except Exception:
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

            # ========== НОВАЯ ЛОГИКА АРХИВАЦИИ ==========
            logger.info("💾 Archiving logic (with name mapping)...")

            # Загружаем маппинг имён
            name_mapping = self._load_name_mapping()

            # Для новых конфигов генерируем имена только если их нет в mapping
            new_configs_with_names = []
            for cfg in deduped:
                key = self._get_config_key(cfg)
                if key not in name_mapping:
                    name = self._generate_name(cfg)
                    if name:
                        name_mapping[key] = name
                    else:
                        # fallback
                        name_mapping[key] = f"config-{key[:8]}"
                # Добавляем конфиг в список для архива (уже с именем, но мы применим его при записи)
                new_configs_with_names.append(cfg)

            # Загружаем существующий архив (старые конфиги)
            archive_configs = self._load_archive()

            # Объединяем: сначала старые, потом новые (удаляем дубликаты по ключу)
            seen_keys = set()
            merged_configs = []
            for cfg in archive_configs + new_configs_with_names:
                key = self._get_config_key(cfg)
                if key not in seen_keys:
                    seen_keys.add(key)
                    merged_configs.append(cfg)

            logger.info(f"🔄 Merged archive: {len(archive_configs)} old + {len(new_configs_with_names)} new → {len(merged_configs)} unique")

            # Сохраняем архив с именами из маппинга
            self._save_archive_with_names(merged_configs, name_mapping)

            # Сохраняем только новые конфиги (без архивации) с именами
            self._save_simple(new_configs_with_names, name_mapping)

            logger.info(f"✅ Archive saved: {len(merged_configs)} configs in {self.output_file}")
            logger.info(f"✅ Simple output saved: {len(new_configs_with_names)} configs in {self.simple_file}")

            # Шаг 8: Генерация Xray-конфига (опционально)
            logger.info("📦 Generating Xray balanced config...")
            try:
                from xray_balancer import ConfigToXray
                converter = ConfigToXray(self.output_file, 'configs/xray_loadbalanced_config.json')
                converter.process_configs()
            except Exception as e:
                logger.warning(f"Xray balancer failed: {e}")

            # Шаг 9: Обновление статистики запуска в SQLite
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


def main():
    pipeline = OptimizedPipeline()
    success = asyncio.run(pipeline.run())
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
