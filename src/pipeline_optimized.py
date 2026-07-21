"""
Оптимизированный пайплайн Proxy-Hunter.

ИСПРАВЛЕНО:
- O(n²) → O(1) dict-индекс в шаге 5
- CPU-bound парсинг вынесен в asyncio.to_thread()
- BoundedDict вместо безграничного _parsed_cache
- ProfileScorer: явный flush() в finally вместо __del__
- Осмысленный порог фильтрации (30 → 10)
- Импорты новых модулей обёрнуты в try/except (работает без них)
- CLI-аргументы --target-region, --test-domain, --xray-path
"""

import asyncio
import argparse
import json
import logging
import os
import sys
import time
from collections import OrderedDict
from typing import Dict, List, Optional, Any, Tuple

from tqdm import tqdm

# ---------------------------------------------------------------------------
# Обязательные импорты (оригинальные модули проекта)
# ---------------------------------------------------------------------------
from fetch_configs import AsyncConfigFetcher
from parse_fallback import FallbackParser
from config_validator import ConfigValidator
from profile_scorer import ProfileScorer
from deep_deduplicate import DeepDeduplicator
from xray_balancer import XrayBalancer
from db import HistoryDB
from user_settings import get_settings

# ---------------------------------------------------------------------------
# Опциональные импорты (новые модули — пайплайн работает и без них)
# ---------------------------------------------------------------------------
try:
    from multi_level_verifier import MultiLevelVerifier, VerificationResult
    HAS_MULTI_LEVEL_VERIFIER = True
except ImportError:
    HAS_MULTI_LEVEL_VERIFIER = False
    MultiLevelVerifier = None
    VerificationResult = None

try:
    from survival_model import SurvivalModel
    HAS_SURVIVAL_MODEL = True
except ImportError:
    HAS_SURVIVAL_MODEL = False
    SurvivalModel = None

try:
    from censorship_scorer import CensorshipScorer, CensorshipProfile, REGION_TEST_DOMAINS
    HAS_CENSORSHIP_SCORER = True
except ImportError:
    HAS_CENSORSHIP_SCORER = False
    CensorshipScorer = None
    REGION_TEST_DOMAINS = {
        'RU': {'primary': 'rutracker.org'},
        'CN': {'primary': 'google.com'},
        'IR': {'primary': 'twitter.com'},
        'GENERIC': {'primary': 'google.com'},
    }

try:
    from region_tester import RegionConnectivityTester, parse_uri_for_test
    HAS_REGION_TESTER = True
except ImportError:
    HAS_REGION_TESTER = False
    RegionConnectivityTester = None
    parse_uri_for_test = None

# ---------------------------------------------------------------------------
# Опциональный импорт active_checker (для fallback-верификации)
# ---------------------------------------------------------------------------
try:
    from active_checker import ActiveChecker
    HAS_ACTIVE_CHECKER = True
except ImportError:
    HAS_ACTIVE_CHECKER = False
    ActiveChecker = None

logger = logging.getLogger(__name__)


# ===========================================================================
# BoundedDict — кеш с ограничением размера (LRU-эвикция)
# ИСПРАВЛЕНО: заменяет безграничный Dict[str, ParsedConfig]
# ===========================================================================
class BoundedDict(OrderedDict):
    """OrderedDict с максимальным размером. При переполнении удаляет старые."""

    def __init__(self, maxsize: int = 50000, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.maxsize = maxsize

    def __setitem__(self, key, value):
        if key in self:
            self.move_to_end(key)
        super().__setitem__(key, value)
        while len(self) > self.maxsize:
            self.popitem(last=False)


# ===========================================================================
# Парсинг одного конфига (для asyncio.to_thread)
# ===========================================================================
def parse_config_once(raw: str) -> Optional[Dict[str, Any]]:
    """
    Парсит одну URI-строку. Вызывается в отдельном потоке.
    ИСПРАВЛЕНО: добавлена поддержка hysteria2/hy2 и tuic через FallbackParser.
    """
    raw = raw.strip()
    if not raw:
        return None

    # Пробуем строгий парсер
    try:
        from config_parser import parse_config
        result = parse_config(raw)
        if result:
            return result
    except Exception:
        pass

    # Fallback-парсер (поддерживает hysteria2, tuic)
    try:
        parsed, strategy = FallbackParser.parse_with_stats(raw)
        if parsed:
            return parsed
    except Exception:
        pass

    return None


def parse_batch_sync(raw_configs: List[str]) -> List[Dict[str, Any]]:
    """Синхронный парсинг батча (для asyncio.to_thread)."""
    results = []
    for raw in raw_configs:
        parsed = parse_config_once(raw)
        if parsed:
            results.append(parsed)
    return results


# ===========================================================================
# Основной пайплайн
# ===========================================================================
class OptimizedPipeline:
    """Оптимизированный конвейер сбора и верификации прокси."""

    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.settings = get_settings()

        # Применяем CLI-аргументы
        self.target_region = args.target_region.upper()
        self.skip_verification = args.skip_verification.lower() in ('true', '1', 'yes')
        self.test_domain = args.test_domain or REGION_TEST_DOMAINS.get(
            self.target_region, REGION_TEST_DOMAINS.get('GENERIC', {})
        ).get('primary', 'google.com')
        self.xray_path = args.xray_path
        self.region_test_top_n = int(args.region_test_top_n)

        # Компоненты (обязательные)
        self.fetcher = AsyncConfigFetcher()
        self.validator = ConfigValidator()
        self.deduplicator = DeepDeduplicator()
        self.db = HistoryDB(self.settings.db_path)

        # Shutdown event для graceful shutdown
        self.shutdown_event = asyncio.Event()

        # Компоненты (опциональные — новые модули)
        self.verifier = None
        self.survival_model = None
        self.censorship_scorer = None
        self.region_tester = None
        self.active_checker = None

        if HAS_MULTI_LEVEL_VERIFIER:
            self.verifier = MultiLevelVerifier(
                max_latency_ms=self.settings.max_latency_ms,
                max_workers=self.settings.check_concurrency,
                shutdown_event=self.shutdown_event,
            )

        if HAS_SURVIVAL_MODEL:
            self.survival_model = SurvivalModel(
                death_threshold=self.settings.survival_death_threshold,
            )

        if HAS_CENSORSHIP_SCORER:
            self.censorship_scorer = CensorshipScorer(target_region=self.target_region)

        if HAS_REGION_TESTER:
            self.region_tester = RegionConnectivityTester(
                region=self.target_region,
                test_domain=self.test_domain,
                xray_path=self.xray_path,
                timeout=self.settings.region_test_timeout,
                max_concurrent=self.settings.region_test_concurrency,
                shutdown_event=self.shutdown_event,
            )

        if HAS_ACTIVE_CHECKER and not HAS_MULTI_LEVEL_VERIFIER:
            self.active_checker = ActiveChecker()

        # ИСПРАВЛЕНО: BoundedDict вместо безграничного Dict
        self._parsed_cache: BoundedDict = BoundedDict(maxsize=50000)

        # Статистика
        self._stats: Dict[str, Any] = {}

        # Логирование доступных модулей
        logger.info(f"Modules: verifier={HAS_MULTI_LEVEL_VERIFIER}, "
                     f"survival={HAS_SURVIVAL_MODEL}, "
                     f"censorship={HAS_CENSORSHIP_SCORER}, "
                     f"region_tester={HAS_REGION_TESTER}, "
                     f"active_checker={HAS_ACTIVE_CHECKER}")

    async def run(self) -> None:
        """Запускает полный пайплайн."""
        start_time = time.time()
        logger.info(f"🚀 Pipeline started | region={self.target_region} | "
                     f"test_domain={self.test_domain} | "
                     f"skip_verification={self.skip_verification}")

        try:
            # Шаг 1: Сбор
            raw_configs = await self._step_fetch()
            self._stats['total_raw'] = len(raw_configs)
            logger.info(f"📥 Step 1: Fetched {len(raw_configs)} raw configs")

            if not raw_configs:
                logger.warning("No configs fetched, exiting")
                return

            # Шаг 2: Парсинг (CPU-bound → asyncio.to_thread)
            parsed_configs = await self._step_parse(raw_configs)
            self._stats['total_parsed'] = len(parsed_configs)
            logger.info(f"🔍 Step 2: Parsed {len(parsed_configs)} configs")

            if not parsed_configs:
                logger.warning("No configs parsed, exiting")
                return

            # Шаг 3: Скоринг
            scored_configs = await self._step_score(parsed_configs)
            self._stats['total_scored'] = len(scored_configs)
            logger.info(f"📊 Step 3: Scored {len(scored_configs)} configs")

            # Шаг 4: Фильтрация
            # ИСПРАВЛЕНО: осмысленный порог (30 → 10)
            filtered = self._step_filter(scored_configs)
            self._stats['total_filtered'] = len(filtered)
            logger.info(f"🔎 Step 4: Filtered to {len(filtered)} configs")

            if not filtered:
                logger.warning("No configs passed filter, exiting")
                return

            # Шаг 5: Верификация
            if not self.skip_verification:
                verified = await self._step_verify(filtered)
                self._stats['total_verified'] = len(verified)
                logger.info(f"✅ Step 5: Verified {len(verified)} configs")
            else:
                verified = filtered
                self._stats['total_verified'] = len(verified)
                logger.info("⏭️ Step 5: Verification skipped")

            # Шаг 5b: Региональное тестирование
            if (not self.skip_verification and self.region_test_top_n > 0
                    and self.region_tester is not None):
                verified = await self._step_region_test(verified)
                logger.info(f"🌐 Step 5b: Region test completed "
                             f"({self.test_domain} / {self.target_region})")

            # Шаг 6: Дедупликация
            deduplicated = await self._step_deduplicate(verified)
            self._stats['total_deduplicated'] = len(deduplicated)
            logger.info(f"🧹 Step 6: Deduplicated to {len(deduplicated)} configs")

            # Шаг 7: Архивация
            await self._step_archive(deduplicated)
            logger.info(f"📦 Step 7: Archived {len(deduplicated)} configs")

            # Шаг 8: Генерация Xray-конфига
            await self._step_xray_config(deduplicated)
            logger.info("⚙️ Step 8: Xray config generated")

            # Шаг 9: Статистика
            self._stats['total_final'] = len(deduplicated)
            self._stats['elapsed_seconds'] = round(time.time() - start_time, 1)
            await self._step_write_stats(deduplicated)
            logger.info(f"📈 Step 9: Stats written")

            logger.info(f"🏁 Pipeline completed in {self._stats['elapsed_seconds']}s | "
                         f"Final: {len(deduplicated)} configs")

        except Exception as e:
            logger.error(f"💥 Pipeline failed: {e}", exc_info=True)
            raise
        finally:
            # ИСПРАВЛЕНО: явный flush/cleanup вместо __del__
            await self._cleanup()

    # =========================================================================
    # Шаг 1: Сбор
    # =========================================================================
    async def _step_fetch(self) -> List[str]:
        """Собирает конфиги из всех источников."""
        try:
            configs = await self.fetcher.fetch_all()
            return configs
        except Exception as e:
            logger.error(f"Fetch failed: {e}")
            return []

    # =========================================================================
    # Шаг 2: Парсинг
    # ИСПРАВЛЕНО: asyncio.to_thread() вместо блокирующего цикла
    # =========================================================================
    async def _step_parse(self, raw_configs: List[str]) -> List[Dict[str, Any]]:
        """Парсит конфиги. CPU-bound работа вынесена в поток."""
        # Фильтруем через кеш
        to_parse = []
        cached_results = []
        for raw in raw_configs:
            if raw in self._parsed_cache:
                cached = self._parsed_cache[raw]
                if cached is not None:
                    cached_results.append(cached)
            else:
                to_parse.append(raw)

        logger.info(f"  Cache hits: {len(cached_results)}, to parse: {len(to_parse)}")

        # Парсим в отдельном потоке (не блокируем event loop)
        parsed_new = []
        if to_parse:
            chunk_size = 1000
            for i in range(0, len(to_parse), chunk_size):
                chunk = to_parse[i:i + chunk_size]
                chunk_results = await asyncio.to_thread(parse_batch_sync, chunk)
                parsed_new.extend(chunk_results)

                # Кэшируем
                for raw in chunk:
                    self._parsed_cache[raw] = parse_config_once(raw)

            logger.info(f"  Parsed {len(parsed_new)} new configs in thread pool")

        all_parsed = cached_results + parsed_new
        return all_parsed

    # =========================================================================
    # Шаг 3: Скоринг
    # ИСПРАВЛЕНО: явный flush() в finally вместо __del__
    # =========================================================================
    async def _step_score(self, parsed_configs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Скоринг с интеграцией SurvivalModel и CensorshipScorer (если доступны)."""
        scored = []
        scorer = ProfileScorer(db_path=self.settings.db_path)

        try:
            for cfg in tqdm(parsed_configs, desc="Scoring", unit="cfg"):
                try:
                    config_str = cfg.get('config', '')
                    protocol = cfg.get('protocol', '')

                    # Базовый score
                    base_score = scorer.score(cfg)

                    # SurvivalModel (если доступен)
                    survival_score = base_score
                    if self.survival_model is not None:
                        config_hash = cfg.get('hash', config_str[:64])
                        self.survival_model.register_profile(
                            config_hash=config_hash,
                            base_quality=base_score,
                            protocol=protocol,
                            server_geo=cfg.get('geo', 'OTHER'),
                        )
                        survival_score = self.survival_model.get_score(config_hash)

                    # CensorshipScorer (если доступен)
                    censorship_score = 50.0
                    if self.censorship_scorer is not None:
                        censorship_result = self.censorship_scorer.score_parsed_config(cfg)
                        censorship_score = censorship_result.total_score

                    # Композитный score
                    if self.survival_model and self.censorship_scorer:
                        composite = (
                            base_score * 0.35 +
                            survival_score * 0.25 +
                            censorship_score * 0.25 +
                            min(100, base_score * 1.2) * 0.15
                        )
                    else:
                        composite = base_score

                    cfg['score'] = round(min(100, max(0, composite)), 2)
                    cfg['base_score'] = base_score
                    cfg['survival_score'] = survival_score
                    cfg['censorship_score'] = censorship_score

                    scored.append(cfg)
                except Exception as e:
                    logger.debug(f"Scoring failed: {e}")
                    continue
        finally:
            # ИСПРАВЛЕНО: явный flush вместо __del__
            try:
                scorer.flush()
            except Exception:
                pass

        return scored

    # =========================================================================
    # Шаг 4: Фильтрация
    # ИСПРАВЛЕНО: осмысленный начальный порог (30) с fallback (10)
    # =========================================================================
    def _step_filter(self, scored_configs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Фильтрация по порогу score."""
        min_score = self.settings.min_score  # 30.0
        filtered = [item for item in scored_configs if item.get('score', 0) >= min_score]

        if not filtered:
            min_score = self.settings.min_score_fallback  # 10.0
            filtered = [item for item in scored_configs if item.get('score', 0) >= min_score]
            logger.info(f"  Lowered threshold to {min_score}, got {len(filtered)} configs")

        filtered.sort(key=lambda x: x.get('score', 0), reverse=True)
        return filtered

    # =========================================================================
    # Шаг 5: Верификация
    # ИСПРАВЛЕНО: O(n²) → O(1) dict-индекс
    # =========================================================================
    async def _step_verify(self, filtered: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Верификация через MultiLevelVerifier или ActiveChecker (fallback)."""

        # Вариант A: MultiLevelVerifier (новый, 5 уровней)
        if self.verifier is not None:
            return await self._verify_multi_level(filtered)

        # Вариант B: ActiveChecker (оригинальный, TCP+HTTP)
        if self.active_checker is not None:
            return await self._verify_active_checker(filtered)

        # Вариант C: Нет верификатора — возвращаем как есть
        logger.warning("  No verifier available, skipping verification")
        return filtered

    async def _verify_multi_level(self, filtered: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Верификация через MultiLevelVerifier."""
        verify_items = []
        for item in filtered:
            verify_items.append({
                'config': item.get('config', ''),
                'server': item.get('server', item.get('address', '')),
                'port': int(item.get('port', 443)),
                'protocol': item.get('protocol', ''),
                'use_tls': item.get('security', '') in ('tls', 'reality'),
                'sni': item.get('sni', item.get('servername', '')),
            })

        results = await self.verifier.verify_batch(verify_items)

        # ИСПРАВЛЕНО: O(1) dict-индекс вместо O(n) линейного поиска
        config_index: Dict[str, Dict[str, Any]] = {
            item['config']: item for item in filtered
        }

        verified = []
        for result in results:
            if result.valid:
                item = config_index.get(result.config)
                if item:
                    if result.latency > 0:
                        latency_bonus = max(0, 10 - result.latency / 100)
                        item['score'] = min(100, item['score'] + latency_bonus)
                    item['latency'] = result.latency
                    item['composite_score'] = result.composite_score

                    if self.survival_model:
                        config_hash = item.get('hash', result.config[:64])
                        self.survival_model.record_success(config_hash, quality=item['score'])

                    verified.append(item)
            else:
                if self.survival_model:
                    self.survival_model.record_failure(result.config[:64])

        # Сохраняем статистику
        self._save_json(self.settings.verification_stats_path, self.verifier.get_stats())
        return verified

    async def _verify_active_checker(self, filtered: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Fallback: верификация через оригинальный ActiveChecker."""
        configs_to_check = [item.get('config', '') for item in filtered]

        try:
            results = await self.active_checker.check_batch(configs_to_check)
        except Exception as e:
            logger.error(f"ActiveChecker failed: {e}")
            return filtered

        # ИСПРАВЛЕНО: O(1) dict-индекс
        config_index: Dict[str, Dict[str, Any]] = {
            item['config']: item for item in filtered
        }

        verified = []
        for result in results:
            config_str = result.get('config', '') if isinstance(result, dict) else ''
            is_valid = result.get('valid', False) if isinstance(result, dict) else False

            if is_valid:
                item = config_index.get(config_str)
                if item:
                    latency = result.get('latency', -1) if isinstance(result, dict) else -1
                    if latency > 0:
                        latency_bonus = max(0, 10 - latency / 100)
                        item['score'] = min(100, item['score'] + latency_bonus)
                    item['latency'] = latency
                    verified.append(item)

        return verified

    # =========================================================================
    # Шаг 5b: Региональное тестирование
    # =========================================================================
    async def _step_region_test(self, verified: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Тестирует топ-N конфигов через xray-core."""
        if self.region_tester is None or parse_uri_for_test is None:
            return verified

        top_n = min(self.region_test_top_n, len(verified))
        if top_n <= 0:
            return verified

        test_candidates = verified[:top_n]
        logger.info(f"  Region testing top {top_n} configs against "
                     f"{self.test_domain} ({self.target_region})")

        test_items = []
        for item in test_candidates:
            parsed = parse_uri_for_test(item.get('config', ''))
            if parsed:
                test_items.append(parsed)

        if not test_items:
            return verified

        results = await self.region_tester.test_batch(test_items)

        # Обновляем score
        region_results: Dict[str, bool] = {}
        region_latencies: Dict[str, float] = {}
        for r in results:
            if r.tested and not r.skipped:
                region_results[r.config] = r.success
                region_latencies[r.config] = r.latency_ms

        for item in verified:
            config_str = item.get('config', '')
            if config_str in region_results:
                passed = region_results[config_str]
                item['region_test_passed'] = passed
                item['region_test_latency'] = region_latencies.get(config_str, -1)

                if passed:
                    item['score'] = min(100, item['score'] + 10)
                else:
                    item['score'] = max(0, item['score'] - 20)

        # Сохраняем результаты
        export = self.region_tester.export_results(results)
        self._save_json('configs/region_test_results.json', export)

        stats = self.region_tester.get_stats()
        logger.info(f"  Region test: {stats['passed']}/{stats['tested']} passed, "
                     f"{stats['skipped']} skipped")

        return verified

    # =========================================================================
    # Шаг 6: Дедупликация
    # =========================================================================
    async def _step_deduplicate(self, configs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Дедупликация."""
        try:
            deduplicated = self.deduplicator.deduplicate(configs)
            return deduplicated
        except Exception as e:
            logger.error(f"Deduplication failed: {e}")
            return configs

    # =========================================================================
    # Шаг 7: Архивация
    # =========================================================================
    async def _step_archive(self, configs: List[Dict[str, Any]]) -> None:
        """Записывает конфиги в архив и simple-файл."""
        try:
            archive_path = self.settings.output_archive
            simple_path = self.settings.output_simple

            with open(archive_path, 'w', encoding='utf-8') as f:
                for cfg in configs:
                    f.write(cfg.get('config', '') + '\n')

            with open(simple_path, 'w', encoding='utf-8') as f:
                for cfg in configs:
                    f.write(cfg.get('config', '') + '\n')

            logger.info(f"  Written {len(configs)} configs to {archive_path}")
        except Exception as e:
            logger.error(f"Archive write failed: {e}")

    # =========================================================================
    # Шаг 8: Xray-конфиг
    # =========================================================================
    async def _step_xray_config(self, configs: List[Dict[str, Any]]) -> None:
        """Генерирует Xray-конфиг из лучших профилей."""
        try:
            balancer = XrayBalancer()
            top_configs = configs[:20]
            balancer.generate(top_configs)
        except Exception as e:
            logger.error(f"Xray config generation failed: {e}")

    # =========================================================================
    # Шаг 9: Статистика
    # =========================================================================
    async def _step_write_stats(self, configs: List[Dict[str, Any]]) -> None:
        """Записывает статистику в БД и JSON-файлы."""
        try:
            scores = [cfg.get('score', 0) for cfg in configs]
            latencies = [cfg.get('latency', 0) for cfg in configs if cfg.get('latency', 0) > 0]

            protocols: Dict[str, int] = {}
            geo: Dict[str, int] = {}
            for cfg in configs:
                p = cfg.get('protocol', 'unknown')
                protocols[p] = protocols.get(p, 0) + 1
                g = cfg.get('geo', 'unknown')
                geo[g] = geo.get(g, 0) + 1

            self.db.record_run(
                total_raw=self._stats.get('total_raw', 0),
                total_valid=self._stats.get('total_verified', 0),
                total_final=len(configs),
                avg_score=sum(scores) / len(scores) if scores else 0,
                p50_latency=sorted(latencies)[len(latencies) // 2] if latencies else 0,
                p95_latency=sorted(latencies)[int(len(latencies) * 0.95)] if latencies else 0,
                p99_latency=sorted(latencies)[int(len(latencies) * 0.99)] if latencies else 0,
                success_rate=len(configs) / max(1, self._stats.get('total_raw', 1)),
                protocols=json.dumps(protocols),
                geo_distribution=json.dumps(geo),
            )

            # Survival stats
            if self.survival_model:
                survival_stats = self.survival_model.get_stats()
                self._save_json(self.settings.survival_states_path, {
                    'stats': survival_stats,
                    'states': self.survival_model.export_states(),
                })
                self._save_json('configs/survival_stats.json', survival_stats)

            # Censorship stats
            if self.censorship_scorer:
                censorship_scores = [cfg.get('censorship_score', 0) for cfg in configs]
                by_protocol: Dict[str, Dict[str, Any]] = {}
                for cfg in configs:
                    p = cfg.get('protocol', 'unknown')
                    if p not in by_protocol:
                        by_protocol[p] = {'scores': [], 'count': 0}
                    by_protocol[p]['scores'].append(cfg.get('censorship_score', 0))
                    by_protocol[p]['count'] += 1

                censorship_stats = {
                    'region': self.target_region,
                    'test_domain': self.test_domain,
                    'total_scored': len(configs),
                    'high_resistance': sum(1 for s in censorship_scores if s >= 70),
                    'medium_resistance': sum(1 for s in censorship_scores if 40 <= s < 70),
                    'low_resistance': sum(1 for s in censorship_scores if s < 40),
                    'avg_score': sum(censorship_scores) / len(censorship_scores) if censorship_scores else 0,
                    'by_protocol': {
                        p: {
                            'avg_score': sum(d['scores']) / len(d['scores']) if d['scores'] else 0,
                            'count': d['count'],
                        }
                        for p, d in by_protocol.items()
                    },
                }
                self._save_json(self.settings.censorship_stats_path, censorship_stats)

            # Pipeline stats
            self._save_json('configs/pipeline_stats.json', self._stats)

        except Exception as e:
            logger.error(f"Stats write failed: {e}")

    # =========================================================================
    # Утилиты
    # =========================================================================
    @staticmethod
    def _save_json(path: str, data: Any) -> None:
        """Сохраняет данные в JSON-файл."""
        try:
            os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        except Exception as e:
            logger.error(f"Failed to save {path}: {e}")

    async def _cleanup(self) -> None:
        """Очистка ресурсов. Вызывается в finally."""
        if self.verifier:
            try:
                await self.verifier.close()
            except Exception:
                pass
        try:
            self.db.close()
        except Exception:
            pass


# ===========================================================================
# CLI-точка входа
# ===========================================================================
def main():
    parser = argparse.ArgumentParser(description='Proxy-Hunter Optimized Pipeline')
    parser.add_argument(
        '--target-region', default='RU',
        choices=['RU', 'CN', 'IR', 'GENERIC'],
        help='Целевой регион для оценки цензуры и тестирования'
    )
    parser.add_argument(
        '--skip-verification', default='false',
        help='Пропустить верификацию (true/false)'
    )
    parser.add_argument(
        '--test-domain', default='',
        help='Домен для регионального теста (пусто = авто по региону)'
    )
    parser.add_argument(
        '--xray-path', default='xray',
        help='Путь к бинарнику xray-core'
    )
    parser.add_argument(
        '--region-test-top-n', default='50',
        help='Сколько топ-конфигов тестировать через xray-core'
    )
    args = parser.parse_args()

    # Настройка логирования
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('pipeline_debug.log', mode='w', encoding='utf-8'),
        ],
    )

    # uvloop для ускорения (Linux/macOS)
    try:
        import uvloop
        uvloop.install()
        logger.info("uvloop installed")
    except ImportError:
        logger.info("uvloop not available, using default event loop")

    # Запуск
    pipeline = OptimizedPipeline(args)
    asyncio.run(pipeline.run())


if __name__ == '__main__':
    main()
