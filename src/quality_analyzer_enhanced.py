"""
Расширенный анализатор качества с поддержкой:
- Перцентилей (P50, P95, P99)
- Скользящего среднего успешности
- Географического распределения
- Детекции аномалий (Z-score, IQR)
- Адаптивных порогов
- Корреляционного анализа
- Предсказания времени жизни
- Шифрования IP-адресов
- Асинхронной записи
- Параллельной обработки
- Автоматического создания файла истории
- Пакетной записи аномалий
- Поэтапного восстановления при повреждении JSON
"""

import json
import os
import hashlib
import logging
import threading
import queue
import time
import shutil
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
import numpy as np
from scipy import stats
from concurrent.futures import ThreadPoolExecutor, as_completed
import portalocker

logger = logging.getLogger(__name__)

# Настройка асинхронной очереди для записи
save_queue = queue.Queue()
save_thread = None
SAVE_INTERVAL = 5  # секунд между пакетными записями

# NEW: пакет для аномалий
_anomaly_batch = []
_ANOMALY_BATCH_SIZE = 50
_anomaly_lock = threading.Lock()


@dataclass
class RunStats:
    timestamp: str
    total_raw: int
    total_valid: int
    total_quality: int
    total_final: int
    avg_score: float
    p50_latency: float
    p95_latency: float
    p99_latency: float
    success_rate: float
    protocols: Dict[str, int]
    geo_distribution: Dict[str, int]
    anomalies: List[Dict]
    protocol_correlations: Dict[str, float]


@dataclass
class ConfigQualityHistory:
    config_hash: str
    protocol: str
    server: str
    country: str
    scores: List[float]
    latencies: List[float]
    timestamps: List[str]
    success_count: int
    fail_count: int
    last_seen: str
    is_active: bool = True


class EnhancedQualityAnalyzer:
    def __init__(self, history_file: str = 'configs/quality_history.json',
                 max_history_runs: int = 100,
                 encryption_salt: str = 'proxy_hunter_salt_2026'):
        self.history_file = history_file
        self.max_history_runs = max_history_runs
        self.encryption_salt = encryption_salt
        self._lock = threading.Lock()
        self.history = self._load_history_with_recovery()
        self._save_queue = queue.Queue()
        self._start_save_thread()

    def _start_save_thread(self):
        def save_worker():
            while True:
                try:
                    data = self._save_queue.get(timeout=SAVE_INTERVAL)
                    if data is None:
                        break
                    self._save_history_sync(data)
                except queue.Empty:
                    # Периодическая проверка, не нужно ли сохранить накопленные данные
                    # NEW: если есть накопленные аномалии, сбрасываем
                    self._flush_anomalies_if_needed(force=False)
                except Exception as e:
                    logger.error(f"Save worker error: {e}")
        global save_thread
        if save_thread is None or not save_thread.is_alive():
            save_thread = threading.Thread(target=save_worker, daemon=True)
            save_thread.start()

    def _hash_ip(self, ip: str) -> str:
        if not ip:
            return "unknown"
        salt = self.encryption_salt
        return hashlib.sha256(f"{salt}:{ip}".encode()).hexdigest()[:16]

    def _init_history(self) -> Dict:
        """Возвращает словарь с полной структурой истории."""
        return {
            'runs': [],
            'configs': {},
            'protocol_stats': {},
            'country_stats': {},
            'anomalies': [],
            'thresholds': {
                'score_min': 30.0,
                'latency_max': 2000.0,
                'success_rate_min': 0.5
            },
            'last_updated': datetime.now().isoformat()
        }

    def _ensure_history_structure(self, data: Dict) -> Dict:
        """Гарантирует наличие всех обязательных ключей в загруженной истории."""
        required_keys = ['runs', 'configs', 'protocol_stats', 'country_stats',
                         'anomalies', 'thresholds', 'last_updated']
        for key in required_keys:
            if key not in data:
                if key == 'thresholds':
                    data[key] = {'score_min': 30.0, 'latency_max': 2000.0, 'success_rate_min': 0.5}
                elif key == 'last_updated':
                    data[key] = datetime.now().isoformat()
                else:
                    data[key] = {} if key in ('configs', 'protocol_stats', 'country_stats') else []
        return data

    def _load_history_with_recovery(self) -> Dict:
        """
        Загружает историю с поэтапным восстановлением при повреждении JSON.
        Пытается загрузить основной файл, при ошибке — бэкапы.
        """
        if not os.path.exists(self.history_file):
            logger.info(f"History file not found. Creating new: {self.history_file}")
            return self._init_history()

        # Пытаемся загрузить основной файл
        try:
            with open(self.history_file, 'r') as f:
                data = json.load(f)
            # Проверяем структуру и восстанавливаем при необходимости
            data = self._ensure_history_structure(data)
            return data
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"History file corrupted: {e}. Attempting recovery from backups.")

        # Поиск бэкапов: .bak, .bak1, .bak2 ...
        backup_candidates = [f"{self.history_file}.bak"]
        for i in range(1, 10):
            backup_candidates.append(f"{self.history_file}.bak{i}")

        for backup_path in backup_candidates:
            if os.path.exists(backup_path):
                try:
                    with open(backup_path, 'r') as f:
                        data = json.load(f)
                    logger.info(f"Recovered history from {backup_path}")
                    # Копируем восстановленный файл обратно
                    shutil.copy2(backup_path, self.history_file)
                    data = self._ensure_history_structure(data)
                    return data
                except (json.JSONDecodeError, OSError) as e2:
                    logger.warning(f"Backup {backup_path} also corrupted: {e2}")
                    continue

        # Если ничего не помогло, создаём новый
        logger.error("All backups corrupted. Creating fresh history.")
        # Создаём бэкап повреждённого файла с меткой времени
        if os.path.exists(self.history_file):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            corrupted_backup = f"{self.history_file}.corrupted_{timestamp}"
            shutil.copy2(self.history_file, corrupted_backup)
            logger.info(f"Saved corrupted file as {corrupted_backup}")
        return self._init_history()

    def _save_history_sync(self, data: Dict = None):
        if data is None:
            data = self.history
        # Создаём бэкап перед записью
        if os.path.exists(self.history_file):
            try:
                shutil.copy2(self.history_file, f"{self.history_file}.bak")
            except Exception:
                pass
        with open(self.history_file, 'w') as f:
            portalocker.lock(f, portalocker.LOCK_EX)
            json.dump(data, f, indent=2)
            portalocker.unlock(f)

    def save_run_stats(self, stats: Dict):
        run = RunStats(
            timestamp=datetime.now().isoformat(),
            total_raw=stats.get('raw', 0),
            total_valid=stats.get('valid', 0),
            total_quality=stats.get('quality', 0),
            total_final=stats.get('final', 0),
            avg_score=stats.get('avg_score', 0),
            p50_latency=stats.get('p50_latency', 0),
            p95_latency=stats.get('p95_latency', 0),
            p99_latency=stats.get('p99_latency', 0),
            success_rate=stats.get('success_rate', 0),
            protocols=stats.get('protocols', {}),
            geo_distribution=stats.get('geo_distribution', {}),
            anomalies=stats.get('anomalies', []),
            protocol_correlations=stats.get('protocol_correlations', {})
        )

        with self._lock:
            # Убеждаемся, что ключ 'runs' существует
            if 'runs' not in self.history:
                self.history['runs'] = []
            self.history['runs'].append(asdict(run))
            if len(self.history['runs']) > self.max_history_runs:
                self.history['runs'] = self.history['runs'][-self.max_history_runs:]

            if 'protocol_stats' not in self.history:
                self.history['protocol_stats'] = {}
            for proto, count in run.protocols.items():
                if proto not in self.history['protocol_stats']:
                    self.history['protocol_stats'][proto] = {'total': 0, 'runs': []}
                self.history['protocol_stats'][proto]['total'] += count

            if 'country_stats' not in self.history:
                self.history['country_stats'] = {}
            for country, count in run.geo_distribution.items():
                if country not in self.history['country_stats']:
                    self.history['country_stats'][country] = 0
                self.history['country_stats'][country] += count

            # Аномалии добавляем через пакетный механизм
            for anomaly in run.anomalies:
                anomaly['timestamp'] = run.timestamp
                self._append_anomaly(anomaly)

            self.history['last_updated'] = run.timestamp

        # Асинхронная запись
        self._save_queue.put(self.history.copy())

    def _append_anomaly(self, anomaly: Dict):
        """Добавляет аномалию в пакет и сбрасывает при достижении размера."""
        global _anomaly_batch
        with _anomaly_lock:
            _anomaly_batch.append(anomaly)
            if len(_anomaly_batch) >= _ANOMALY_BATCH_SIZE:
                self._flush_anomalies(force=True)

    def _flush_anomalies(self, force: bool = False):
        """Сбрасывает накопленные аномалии в историю."""
        global _anomaly_batch
        with _anomaly_lock:
            if not _anomaly_batch:
                return
            # Добавляем в историю
            with self._lock:
                if 'anomalies' not in self.history:
                    self.history['anomalies'] = []
                self.history['anomalies'].extend(_anomaly_batch)
                if len(self.history['anomalies']) > 500:
                    self.history['anomalies'] = self.history['anomalies'][-500:]
            _anomaly_batch = []
            # Запись всей истории (можно отложить)
            self._save_queue.put(self.history.copy())

    def _flush_anomalies_if_needed(self, force: bool = False):
        """Периодический сброс."""
        if len(_anomaly_batch) >= _ANOMALY_BATCH_SIZE or force:
            self._flush_anomalies(force)

    def get_protocol_rolling_averages(self, window: int = 10) -> Dict[str, float]:
        result = {}
        if 'protocol_stats' not in self.history:
            return result
        protocol_success = defaultdict(list)
        for run in self.history.get('runs', [])[-window:]:
            for proto, count in run.get('protocols', {}).items():
                if run.get('total_raw', 0) > 0:
                    success_rate = run.get('total_final', 0) / run.get('total_raw', 1)
                    protocol_success[proto].append(success_rate)
        for proto, rates in protocol_success.items():
            if rates:
                result[proto] = sum(rates) / len(rates)
        return result

    def get_geo_distribution(self) -> Dict[str, int]:
        return self.history.get('country_stats', {})

    def calculate_protocol_correlations(self) -> Dict[str, float]:
        protocol_data = defaultdict(list)
        for run in self.history.get('runs', []):
            for proto, count in run.get('protocols', {}).items():
                if count > 0 and run.get('avg_score', 0) > 0:
                    protocol_data[proto].append(run['avg_score'])
        result = {}
        for proto, scores in protocol_data.items():
            if len(scores) > 5:
                times = list(range(len(scores)))
                try:
                    corr, _ = stats.pearsonr(times, scores)
                    result[proto] = round(corr, 3)
                except:
                    result[proto] = 0.0
        return result

    def detect_anomalies(self, configs_data: List[Dict]) -> List[Dict]:
        anomalies = []
        if not configs_data:
            return anomalies
        scores = [item['quality'].get('score', 0) for item in configs_data]
        latencies = [item['quality'].get('latency', 0) for item in configs_data]
        if len(scores) < 5:
            return anomalies
        mean_score = np.mean(scores)
        std_score = np.std(scores) if np.std(scores) > 0 else 1
        z_scores = [(s - mean_score) / std_score for s in scores]
        q1 = np.percentile(latencies, 25)
        q3 = np.percentile(latencies, 75)
        iqr = q3 - q1
        lower_bound = q1 - 1.5 * iqr
        upper_bound = q3 + 1.5 * iqr

        for idx, item in enumerate(configs_data):
            is_anomaly = False
            anomaly_type = []
            if abs(z_scores[idx]) > 2.5:
                is_anomaly = True
                anomaly_type.append('z_score')
            if latencies[idx] < lower_bound or latencies[idx] > upper_bound:
                is_anomaly = True
                anomaly_type.append('iqr')
            config_hash = self._hash_ip(item.get('server', ''))
            if config_hash in self.history.get('configs', {}):
                prev_scores = self.history['configs'][config_hash].get('scores', [])
                if prev_scores and len(prev_scores) > 2:
                    avg_prev = sum(prev_scores[-3:]) / len(prev_scores[-3:])
                    if scores[idx] < avg_prev * 0.5:
                        is_anomaly = True
                        anomaly_type.append('drop')
            if is_anomaly:
                anomalies.append({
                    'config_preview': item.get('config', '')[:80],
                    'protocol': item.get('protocol', 'unknown'),
                    'country': item.get('country', 'unknown'),
                    'score': scores[idx],
                    'latency': latencies[idx],
                    'z_score': round(z_scores[idx], 2),
                    'anomaly_types': anomaly_type,
                    'severity': 'high' if len(anomaly_type) >= 2 else 'medium'
                })
        return anomalies

    def get_adaptive_thresholds(self) -> Dict[str, float]:
        thresholds = self.history.get('thresholds', {})
        runs = self.history.get('runs', [])
        if len(runs) < 5:
            return thresholds
        recent_runs = runs[-20:] if len(runs) > 20 else runs
        scores = [r.get('avg_score', 0) for r in recent_runs if r.get('avg_score', 0) > 0]
        latencies = []
        success_rates = []
        for r in recent_runs:
            if r.get('p50_latency', 0) > 0:
                latencies.append(r.get('p50_latency', 0))
            if r.get('success_rate', 0) > 0:
                success_rates.append(r.get('success_rate', 0))
        if scores:
            new_score_min = max(10, np.percentile(scores, 25) * 0.7)
            thresholds['score_min'] = round(new_score_min, 1)
        if latencies:
            new_latency_max = np.percentile(latencies, 75) * 1.5
            thresholds['latency_max'] = round(new_latency_max, 1)
        if success_rates:
            new_success_min = max(0.2, np.percentile(success_rates, 25) * 0.8)
            thresholds['success_rate_min'] = round(new_success_min, 3)
        self.history['thresholds'] = thresholds
        return thresholds

    def update_config_history(self, config: str, quality: Dict, protocol: str,
                              server: str, country: str):
        config_hash = self._hash_ip(server)
        timestamp = datetime.now().isoformat()
        with self._lock:
            if 'configs' not in self.history:
                self.history['configs'] = {}
            if config_hash not in self.history['configs']:
                self.history['configs'][config_hash] = {
                    'protocol': protocol,
                    'server': server,
                    'country': country,
                    'scores': [],
                    'latencies': [],
                    'timestamps': [],
                    'success_count': 0,
                    'fail_count': 0,
                    'last_seen': timestamp,
                    'is_active': True
                }
            cfg = self.history['configs'][config_hash]
            cfg['scores'].append(quality.get('score', 0))
            cfg['latencies'].append(quality.get('latency', 0))
            cfg['timestamps'].append(timestamp)
            cfg['last_seen'] = timestamp
            max_history = 50
            if len(cfg['scores']) > max_history:
                cfg['scores'] = cfg['scores'][-max_history:]
                cfg['latencies'] = cfg['latencies'][-max_history:]
                cfg['timestamps'] = cfg['timestamps'][-max_history:]
            if quality.get('valid', False):
                cfg['success_count'] += 1
            else:
                cfg['fail_count'] += 1
            if len(cfg['scores']) >= 5:
                recent_scores = cfg['scores'][-5:]
                avg_recent = sum(recent_scores) / len(recent_scores)
                if avg_recent < 20 and cfg['fail_count'] > cfg['success_count'] * 2:
                    cfg['is_active'] = False

    def predict_lifetime(self, config_hash: str) -> Optional[float]:
        if config_hash not in self.history.get('configs', {}):
            return None
        cfg = self.history['configs'][config_hash]
        if len(cfg['scores']) < 3:
            return None
        timestamps = [datetime.fromisoformat(ts) for ts in cfg['timestamps']]
        if len(timestamps) < 2:
            return None
        intervals = []
        for i in range(1, len(timestamps)):
            intervals.append((timestamps[i] - timestamps[i-1]).total_seconds() / 3600)
        avg_interval = sum(intervals) / len(intervals) if intervals else 0
        if avg_interval == 0:
            return None
        if len(cfg['scores']) >= 3:
            recent_avg = sum(cfg['scores'][-3:]) / 3
            overall_avg = sum(cfg['scores']) / len(cfg['scores'])
            if overall_avg > 0:
                health_ratio = recent_avg / overall_avg
                if health_ratio < 0.5:
                    return avg_interval * 0.3
                elif health_ratio < 0.8:
                    return avg_interval * 0.6
                else:
                    return avg_interval * 1.2
        return avg_interval * 1.0

    def get_best_countries(self, limit: int = 5) -> List[Tuple[str, int]]:
        stats = self.history.get('country_stats', {})
        return sorted(stats.items(), key=lambda x: x[1], reverse=True)[:limit]

    def get_degrading_configs(self, threshold: float = 0.3) -> List[Dict]:
        degrading = []
        for cfg_hash, cfg in self.history.get('configs', {}).items():
            if len(cfg['scores']) < 5:
                continue
            recent_avg = sum(cfg['scores'][-3:]) / 3
            overall_avg = sum(cfg['scores']) / len(cfg['scores'])
            if overall_avg > 0 and recent_avg / overall_avg < threshold:
                degrading.append({
                    'config_hash': cfg_hash,
                    'protocol': cfg.get('protocol', 'unknown'),
                    'country': cfg.get('country', 'unknown'),
                    'recent_avg': round(recent_avg, 1),
                    'overall_avg': round(overall_avg, 1),
                    'degradation_ratio': round(recent_avg / overall_avg, 2),
                    'last_seen': cfg.get('last_seen', '')
                })
        return sorted(degrading, key=lambda x: x['degradation_ratio'])[:20]

    def export_tsv_for_ml(self, output_file: str = 'configs/quality_data.csv'):
        rows = []
        for run in self.history.get('runs', []):
            row = {
                'timestamp': run.get('timestamp', ''),
                'total_final': run.get('total_final', 0),
                'avg_score': run.get('avg_score', 0),
                'p50_latency': run.get('p50_latency', 0),
                'p95_latency': run.get('p95_latency', 0),
                'p99_latency': run.get('p99_latency', 0),
                'success_rate': run.get('success_rate', 0),
            }
            for proto, count in run.get('protocols', {}).items():
                row[f'proto_{proto}'] = count
            rows.append(row)
        if rows:
            import csv
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=rows[0].keys())
                writer.writeheader()
                writer.writerows(rows)
            logger.info(f"Exported ML data to {output_file}")

    def get_summary_stats(self) -> Dict:
        runs = self.history.get('runs', [])
        if not runs:
            return {'total_runs': 0}
        latest = runs[-1] if runs else {}
        return {
            'total_runs': len(runs),
            'latest_run': latest,
            'protocols': self.history.get('protocol_stats', {}),
            'countries': self.history.get('country_stats', {}),
            'anomalies_count': len(self.history.get('anomalies', [])),
            'thresholds': self.history.get('thresholds', {}),
            'total_configs_tracked': len(self.history.get('configs', {}))
        }

    # NEW: метод для принудительной записи всех накопленных данных
    def flush(self):
        self._flush_anomalies(force=True)
        # Дожидаемся опустошения очереди
        while not self._save_queue.empty():
            time.sleep(0.1)
        self._save_history_sync(self.history)
