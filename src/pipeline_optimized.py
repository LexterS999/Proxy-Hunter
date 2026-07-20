#!/usr/bin/env python3
"""
Оптимизированный пайплайн Proxy-Hunter с улучшенной оценкой,
интеллектуальным зондированием, ML-фильтрацией и кешированием.
Рефакторинг: атомарные шаги, ProcessPoolExecutor, DI, Circuit Breaker.
"""

import sys
import os
import asyncio
import uvloop
asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

from db import get_db, _compress
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import logging
import time
import traceback
import json
import hashlib
import shutil
import signal
import socket
from pathlib import Path
from typing import List, Dict, Optional, Set, Any
from datetime import datetime, timezone
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
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

from feature_extractor import FeatureExtractor
from probe_engine import IntelligentProbe
from anomaly_detector import AnomalyDetector
from channel_selector import ChannelSelector
from async_db_writer import AsyncDBWriter
from handle_errors import handle_errors

logger = logging.getLogger(__name__)

# ============================
# Глобальная функция для парсинга в отдельном процессе
# ============================

def _parse_config_worker(cfg: str, cache_key: str, parsed_cache: Dict) -> tuple:
    """
    Вспомогательная функция для параллельной валидации и парсинга.
    Возвращает (cfg, method, data) или (None, 'failed', None).
    """
    if not ConfigValidator.is_valid_config(cfg):
        return (None, 'failed', None)
    if cache_key in parsed_cache:
        data = parsed_cache[cache_key]
        if data:
            method = 'strict' if data.get('method') == 'strict' else 'heuristic'
            return (cfg, method, None)
        else:
            return (None, 'failed', None)
    else:
        data, method = FallbackParser.parse_with_stats(cfg)
        if data is None:
            return (None, 'failed', None)
        else:
            if method not in ('strict', 'heuristic'):
                method = 'heuristic'
            return (cfg, method, data)

# ============================
# Вспомогательные классы
# ============================

class CircuitBreaker:
    """Предохранитель для защиты от массовых сбоев."""
    def __init__(self, failure_threshold=5, timeout=60):
        self.failure_count = 0
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.state = 'closed'  # closed, open, half-open
        self.last_failure = None

    def record_failure(self):
        self.failure_count += 1
        if self.failure_count >= self.failure_threshold:
            self.state = 'open'
            self.last_failure = time.time()

    def record_success(self):
        self.failure_count = 0
        self.state = 'closed'

    def is_open(self):
        if self.state == 'open' and time.time() - self.last_failure > self.timeout:
            self.state = 'half-open'
            return False
        return self.state == 'open'

class ErrorHandler:
    """Глобальный обработчик ошибок с подсчётом повторений."""
    def __init__(self):
        self.retry_count = {}

    def handle(self, error, context):
        key = f"{context}_{type(error).__name__}"
        self.retry_count[key] = self.retry_count.get(key, 0) + 1
        if self.retry_count[key] > 5:
            logger.critical(f"Too many errors in {context}: {error}")
            return False  # Прервать выполнение
        return True  # Продолжить с задержкой

class BatchWriter:
    """Пакетная запись в БД."""
    def __init__(self, db, batch_size=100):
        self.db = db
        self.batch_size = batch_size
        self.buffer = []

    async def add(self, item):
        self.buffer.append(item)
        if len(self.buffer) >= self.batch_size:
            await self.flush()

    async def flush(self):
        if self.buffer:
            # Здесь нужно реализовать вставку в зависимости от типа данных
            # Например, для профилей:
            # await self.db.update_profiles_batch(self.buffer)
            self.buffer = []

# ============================
# DI-контейнер
# ============================

class Container:
    def __init__(self):
        self.db = None  # будет инициализирован асинхронно
        self.config = ProxyConfig()
        self.fetcher = AsyncConfigFetcher(self.config)
        self.deduplicator = DeepDeduplicator()
        self.probe = IntelligentProbe()
        self.scorer = ProfileScorer()
        self.validator = ConfigValidator()
        self.quality_checker = ConfigQualityChecker(timeout=0, max_workers=1)
        self.feature_extractor = FeatureExtractor()
        self.anomaly_detector = AnomalyDetector()
        self.channel_analyzer = ChannelQualityAnalyzer()
        self.async_writer = AsyncDBWriter()

    async def init_db(self):
        self.db = await get_db()
        return self.db

    def get_pipeline(self):
        return OptimizedPipeline(
            fetcher=self.fetcher,
            deduplicator=self.deduplicator,
            probe=self.probe,
            scorer=self.scorer,
            validator=self.validator,
            quality_checker=self.quality_checker,
            feature_extractor=self.feature_extractor,
            anomaly_detector=self.anomaly_detector,
            channel_analyzer=self.channel_analyzer,
            async_writer=self.async_writer,
            db=self.db,
            config=self.config
        )

# ============================
# Основной пайплайн
# ============================

class OptimizedPipeline:
    def __init__(self,
                 fetcher: AsyncConfigFetcher,
                 deduplicator: DeepDeduplicator,
                 probe: IntelligentProbe,
                 scorer: ProfileScorer,
                 validator: ConfigValidator,
                 quality_checker: ConfigQualityChecker,
                 feature_extractor: FeatureExtractor,
                 anomaly_detector: AnomalyDetector,
                 channel_analyzer: ChannelQualityAnalyzer,
                 async_writer: AsyncDBWriter,
                 db,
                 config: ProxyConfig):
        self.fetcher = fetcher
        self.deduplicator = deduplicator
        self.probe = probe
        self.scorer = scorer
        self.validator = validator
        self.quality_checker = quality_checker
        self.feature_extractor = feature_extractor
        self.anomaly_detector = anomaly_detector
        self.channel_analyzer = channel_analyzer
        self.async_writer = async_writer
        self.db = db
        self.config = config

        self.output_file = 'configs/output_archive.txt'
        self.simple_file = 'configs/output_simple.txt'
        self.name_mapping_file = 'configs/name_mapping.json'
        self._shutdown_requested = False
        self._state = {}
        self._health_applied = False
        self.model = None
        self.model_path = 'configs/quality_model.cbm'
        self.model_mtime = None
        self.feature_cols = []
        self.cat_cols = []

        # ProcessPoolExecutor для CPU-bound задач
        self._process_executor = ProcessPoolExecutor(max_workers=os.cpu_count() or 4)
        self._executor = ThreadPoolExecutor(max_workers=4)  # для I/O задач

        # Circuit Breaker для каналов
        self.channel_circuit_breaker = CircuitBreaker(failure_threshold=5, timeout=60)

        # ErrorHandler
        self.error_handler = ErrorHandler()

        # BatchWriter
        self.batch_writer = BatchWriter(db, batch_size=100)

        self._setup_logging()
        self._check_dependencies()
        self._setup_signal_handlers()
        self._load_model()

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
            import lxml
        except ImportError:
            missing.append("lxml")
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
        try:
            import aiosqlite
        except ImportError:
            missing.append("aiosqlite")
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

    def _load_model(self):
        try:
            mtime = os.path.getmtime(self.model_path) if os.path.exists(self.model_path) else None
            if self.model is not None and mtime == self.model_mtime:
                return
            data = joblib.load(self.model_path)
            self.model = data['model']
            self.feature_cols = data['features']
            self.cat_cols = data['categorical']
            self.model_mtime = mtime
            logger.info(f"✅ Quality model loaded from {self.model_path}")
        except FileNotFoundError:
            logger.warning(f"Model file {self.model_path} not found, using fallback scoring.")
            self.model = None
            self.model_mtime = None
        except Exception as e:
            logger.warning(f"Could not load quality model: {e}. Using fallback scoring.")
            self.model = None
            self.model_mtime = None

    def _reload_model_if_changed(self):
        if os.path.exists(self.model_path):
            current_mtime = os.path.getmtime(self.model_path)
            if current_mtime != self.model_mtime:
                logger.info("Model file changed, reloading...")
                self._load_model()

    def _get_cache_key(self, config: str) -> str:
        return hashlib.md5(config.encode()).hexdigest()

    def _parse_config(self, config: str) -> Optional[Dict]:
        parsed, method = FallbackParser.parse_with_stats(config)
        if parsed:
            parsed['protocol'] = config.split('://')[0].lower()
        return parsed

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

    async def _load_name_mapping_async(self) -> Dict[str, str]:
        if not os.path.exists(self.name_mapping_file):
            return {}
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

    # ========== Атомарные шаги ==========

    async def _fetch(self) -> List[str]:
        """Шаг 1: Сбор конфигураций."""
        logger.info("📡 Fetching configurations...")
        raw = await self.fetcher.fetch_all()
        if self._shutdown_requested:
            return []
        logger.info(f"✅ Raw configs: {len(raw)}")
        return raw

    async def _validate(self, raw_configs: List[str]) -> List[str]:
        """Шаг 2: Парсинг и валидация с кешированием."""
        logger.info("🔍 Validating and extracting server info...")
        if not raw_configs:
            return []

        loop = asyncio.get_event_loop()
        batch_size = 1000
        valid = []
        parse_stats = {'strict': 0, 'heuristic': 0, 'failed': 0}

        cache_keys = [self._get_cache_key(cfg) for cfg in raw_configs]
        parsed_cache = await self.db.get_parsed_cache_batch(cache_keys)
        new_cache_items = {}

        # Используем глобальную функцию _parse_config_worker
        for i in range(0, len(raw_configs), batch_size):
            if self._shutdown_requested:
                return []
            batch = raw_configs[i:i+batch_size]
            batch_keys = cache_keys[i:i+batch_size]
            # Передаём копию parsed_cache (будет скопирована в каждый процесс)
            futures = [
                loop.run_in_executor(
                    self._process_executor,
                    _parse_config_worker,
                    cfg,
                    key,
                    parsed_cache
                )
                for cfg, key in zip(batch, batch_keys)
            ]
            for future in asyncio.as_completed(futures):
                cfg, method, data = await future
                if cfg:
                    valid.append(cfg)
                    parse_stats[method] = parse_stats.get(method, 0) + 1
                    if data is not None:
                        new_cache_items[self._get_cache_key(cfg)] = data
                else:
                    parse_stats['failed'] += 1

        if new_cache_items:
            await self.db.set_parsed_cache_batch(new_cache_items)

        logger.info(f"✅ Valid configs: {len(valid)}")
        logger.info(f"   Parse stats: strict={parse_stats['strict']}, heuristic={parse_stats['heuristic']}, failed={parse_stats['failed']}")
        return valid

    async def _score(self, valid_configs: List[str]) -> List[Dict]:
        """Шаг 3: Оценка и извлечение признаков."""
        logger.info("⚡ Scoring profiles and extracting features...")
        if not valid_configs:
            return []

        loop = asyncio.get_event_loop()
        batch_size = 1000
        scored = []
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
                    key = self.feature_extractor.get_profile_key(cfg)
                    if key:
                        feats = self.feature_extractor.extract_features(key, cfg, parsed)
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

        # ВАЖНО: score_and_extract — это вложенная функция (closure), которая
        # обращается к self (self._parse_config, self.quality_checker, self.scorer,
        # self.feature_extractor). Такие closures нельзя сериализовать (pickle),
        # поэтому передавать их в ProcessPoolExecutor нельзя — это и вызывало
        # "AttributeError: Can't get local object 'OptimizedPipeline._score.<locals>.score_and_extract'".
        # Выполняем задачу в ThreadPoolExecutor (self._executor): пиклинг не требуется,
        # т.к. поток работает в том же процессе и имеет доступ к self напрямую.
        with tqdm(total=len(valid_configs), desc="Scoring & extracting") as pbar:
            for i in range(0, len(valid_configs), batch_size):
                if self._shutdown_requested:
                    return []
                batch = valid_configs[i:i+batch_size]
                futures = [loop.run_in_executor(self._executor, score_and_extract, cfg) for cfg in batch]
                for future in asyncio.as_completed(futures):
                    result = await future
                    if result:
                        async with scored_lock:
                            scored.append(result)
                            features_list.append(result['features'])
                    pbar.update(1)

        logger.info(f"✅ Scored {len(scored)} configs")
        return scored

    async def _probe(self, scored_configs: List[Dict]) -> List[str]:
        """Шаг 4: Интеллектуальное зондирование."""
        logger.info("🔌 Intelligent probing...")
        if not scored_configs:
            return []

        hosts = set()
        for item in scored_configs:
            parsed = item.get('parsed')
            if not parsed:
                parsed = self._parse_config(item['config'])
                item['parsed'] = parsed
            if parsed:
                host = parsed.get('address') or parsed.get('add')
                if host:
                    hosts.add(host)

        dns_cache = {}
        loop = asyncio.get_event_loop()
        async def resolve_host(host):
            try:
                ip = await loop.run_in_executor(self._executor, socket.gethostbyname, host)
                dns_cache[host] = ip
            except:
                dns_cache[host] = None
        await asyncio.gather(*[resolve_host(h) for h in hosts])
        logger.info(f"✅ Resolved {len([ip for ip in dns_cache.values() if ip])} hosts")

        probe_results = []
        global_sem = asyncio.Semaphore(100)
        host_sems = {}
        host_sem_limit = 5

        async def probe_with_limits(item):
            cfg = item['config']
            parsed = item.get('parsed')
            if not parsed:
                parsed = self._parse_config(cfg)
                item['parsed'] = parsed
            if not parsed:
                return {'success': False, 'error': 'parse_failed'}

            host = parsed.get('address') or parsed.get('add')
            if host not in host_sems:
                host_sems[host] = asyncio.Semaphore(host_sem_limit)

            ml_score = item.get('ml_score', 50.0)
            async with global_sem, host_sems[host]:
                result = await self.probe.probe(cfg, parsed, ml_score=ml_score)
                result['profile_key'] = item.get('profile_key', self.feature_extractor.get_profile_key(cfg))
                await self.async_writer.enqueue({
                    'type': 'probe',
                    **result
                })
                return result

        probe_tasks = [probe_with_limits(item) for item in scored_configs]
        probe_results = await asyncio.gather(*probe_tasks, return_exceptions=True)

        good = []
        for idx, res in enumerate(probe_results):
            if isinstance(res, Exception):
                logger.debug(f"Probe exception: {res}")
                continue
            if res.get('success'):
                good.append(scored_configs[idx]['config'])

        logger.info(f"✅ Active check: {len(good)} configs passed")
        return good

    async def _deduplicate(self, good_configs: List[str], scored_configs: List[Dict]) -> List[str]:
        """Шаг 5: Дедупликация."""
        logger.info("🧹 Deep deduplication...")
        if not good_configs:
            return []
        quality_scores = {item['config']: item.get('ml_score', item['score']) for item in scored_configs if item['config'] in good_configs}
        deduped = await self.deduplicator.deduplicate_configs_async(good_configs, quality_scores)
        logger.info(f"✅ After dedup: {len(deduped)}")
        return deduped

    async def _archive(self, deduped: List[str]) -> bool:
        """Шаг 6: Архивация."""
        logger.info("💾 Archiving logic...")
        if not deduped:
            return False

        name_mapping = await self._load_name_mapping_async()
        new_configs_with_names = []
        for cfg in deduped:
            key = self._get_config_key(cfg)
            if key not in name_mapping:
                name_mapping[key] = self._generate_name(cfg)
            new_configs_with_names.append(cfg)

        archive_configs = await self._load_archive_async()
        seen_keys = set()
        merged = []
        for cfg in archive_configs + new_configs_with_names:
            key = self._get_config_key(cfg)
            if key not in seen_keys:
                seen_keys.add(key)
                merged.append(cfg)

        logger.info(f"🔄 Merged archive: {len(archive_configs)} old + {len(new_configs_with_names)} new → {len(merged)} unique")
        await self._save_archive_with_names_async(merged, name_mapping)
        await self._save_simple_async(new_configs_with_names, name_mapping)

        logger.info(f"✅ Archive saved: {len(merged)} configs in {self.output_file}")
        logger.info(f"✅ Simple output saved: {len(new_configs_with_names)} configs in {self.simple_file}")
        return True

    # ========== Основной метод run ==========

    @handle_errors(logger=logger, context="Pipeline run")
    async def run(self) -> bool:
        try:
            start_time = time.time()
            logger.info("=" * 60)
            logger.info("🚀 Starting Proxy-Hunter Pipeline (refactored)")
            logger.info("=" * 60)

            raw = await self._fetch()
            if self._shutdown_requested or not raw:
                return False

            valid = await self._validate(raw)
            if self._shutdown_requested or not valid:
                return False

            scored = await self._score(valid)
            if self._shutdown_requested or not scored:
                return False

            good = await self._probe(scored)
            if self._shutdown_requested or not good:
                return False

            deduped = await self._deduplicate(good, scored)
            if self._shutdown_requested or not deduped:
                return False

            archived = await self._archive(deduped)
            if not archived:
                return False

            try:
                from xray_balancer import ConfigToXray
                converter = ConfigToXray(self.output_file, 'configs/xray_loadbalanced_config.json')
                converter.process_configs()
            except Exception as e:
                logger.warning(f"Xray balancer failed: {e}")

            await self._update_run_stats(raw, valid, scored, good, deduped)

            elapsed = time.time() - start_time
            logger.info("=" * 60)
            logger.info(f"✅ Pipeline completed in {elapsed:.2f}s")
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
            await self.async_writer.stop()
            await SessionPool().close()
            if self.db is not None:
                await self.db.close()
            self._process_executor.shutdown(wait=False)
            self._executor.shutdown(wait=False)

    async def _update_run_stats(self, raw, valid, scored, good, deduped):
        """Обновление статистики в БД."""
        # ... (логика сохранения статистики в БД)
        pass

    async def save_state(self):
        """Сохранение состояния."""
        # ... (сохранение состояния)
        pass


async def main():
    container = Container()
    await container.init_db()
    pipeline = container.get_pipeline()
    success = await pipeline.run()
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    asyncio.run(main())
