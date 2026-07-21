"""
Сбор и анализ статистики локальных проверок для корректировки региональных весов.
Поддерживает агрегацию по протоколам, портам, SNI и автоматическое обновление весов.
"""

import json
import os
import logging
from typing import Dict, List, Optional, Any
from collections import defaultdict
import time
import copy

logger = logging.getLogger(__name__)

class RegionalStats:
    def __init__(self, stats_file: str = 'configs/regional_stats.json'):
        self.stats_file = stats_file
        self.stats = self._load_stats()
        # Агрегированные данные для пересчёта весов
        self.aggregated = self._aggregate()

    def _load_stats(self) -> Dict:
        if os.path.exists(self.stats_file):
            try:
                with open(self.stats_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def _save_stats(self):
        with open(self.stats_file, 'w') as f:
            json.dump(self.stats, f, indent=2)

    def _aggregate(self) -> Dict:
        """
        Агрегирует статистику по ключам: (region, protocol, port, sni)
        """
        agg = {
            'protocols': defaultdict(lambda: {'total': 0, 'success': 0, 'latencies': []}),
            'ports': defaultdict(lambda: {'total': 0, 'success': 0, 'latencies': []}),
            'sni': defaultdict(lambda: {'total': 0, 'success': 0, 'latencies': []}),
        }
        for key, data in self.stats.items():
            # ключ: region:config_preview, но мы не можем извлечь протокол/порт/sni из preview.
            # Поэтому будем хранить дополнительные поля при записи.
            # Для обратной совместимости оставим, но для агрегации нужно расширить формат.
            # В новом формате ключ: region:protocol:port:sni
            pass
        return agg

    def record_local_check(self, config: str, parsed: Dict, success: bool, latency: float, region: str = 'RU'):
        """
        Записывает результат локальной проверки с извлечением протокола, порта, SNI.
        """
        protocol = parsed.get('protocol') or config.split('://')[0].lower()
        port = int(parsed.get('port', 443))
        sni = parsed.get('sni', '')
        # Генерируем ключ для детальной статистики
        detail_key = f"{region}:{protocol}:{port}:{sni}"
        if detail_key not in self.stats:
            self.stats[detail_key] = {'successes': 0, 'fails': 0, 'latencies': [], 'last_seen': 0}
        self.stats[detail_key]['successes'] += 1 if success else 0
        self.stats[detail_key]['fails'] += 0 if success else 1
        if latency > 0:
            self.stats[detail_key]['latencies'].append(latency)
        self.stats[detail_key]['last_seen'] = time.time()
        self._save_stats()

    def get_aggregated_success_rate(self, region: str, protocol: str, port: int, sni: str) -> Optional[float]:
        """
        Возвращает агрегированную успешность для комбинации параметров.
        """
        key = f"{region}:{protocol}:{port}:{sni}"
        data = self.stats.get(key)
        if not data:
            return None
        total = data['successes'] + data['fails']
        if total == 0:
            return None
        return data['successes'] / total

    def update_weights(self, region: str, scorer) -> None:
        """
        Обновляет региональные веса в объекте RegionalScorer на основе накопленной статистики.
        """
        # Собираем все данные для данного региона
        region_keys = [k for k in self.stats.keys() if k.startswith(f"{region}:")]
        if not region_keys:
            return
        # Агрегируем по протоколам, портам, SNI
        proto_rates = defaultdict(list)
        port_rates = defaultdict(list)
        sni_rates = defaultdict(list)
        for key in region_keys:
            _, proto, port_str, sni = key.split(':', 3)
            data = self.stats[key]
            total = data['successes'] + data['fails']
            if total == 0:
                continue
            rate = data['successes'] / total
            port = int(port_str)
            proto_rates[proto].append(rate)
            port_rates[port].append(rate)
            if sni:
                sni_rates[sni].append(rate)
        # Вычисляем средние
        def avg(rates):
            return sum(rates) / len(rates) if rates else 1.0
        # Обновляем веса в scorer
        for proto in scorer.REGIONAL_BONUS[region]['protocols'].keys():
            avg_rate = avg(proto_rates.get(proto, []))
            # нормализуем относительно среднего
            # коэффициент = avg_rate / 0.5 (базовое ожидание 50% успеха)
            weight = avg_rate / 0.5
            weight = max(0.5, min(2.0, weight))
            scorer.REGIONAL_BONUS[region]['protocols'][proto] = weight
        for port in scorer.REGIONAL_BONUS[region]['ports'].keys():
            avg_rate = avg(port_rates.get(port, []))
            weight = avg_rate / 0.5
            weight = max(0.5, min(2.0, weight))
            scorer.REGIONAL_BONUS[region]['ports'][port] = weight
        for sni in scorer.REGIONAL_BONUS[region]['sni'].keys():
            avg_rate = avg(sni_rates.get(sni, []))
            weight = avg_rate / 0.5
            weight = max(0.5, min(2.0, weight))
            scorer.REGIONAL_BONUS[region]['sni'][sni] = weight
        # Также обновляем Reality-бонус (может быть вычислен из успешности Reality-конфигов)
        reality_rate = avg([rate for key, data in self.stats.items() if key.startswith(f"{region}:") and 'reality' in data.get('tags', [])])
        if reality_rate:
            scorer.REGIONAL_BONUS[region]['reality_bonus'] = max(1.0, reality_rate / 0.5)

        logger.info(f"Weights updated for region {region} based on {len(region_keys)} records.")

    def get_stats_for_config(self, config: str, parsed: Dict, region: str = 'RU') -> Optional[Dict]:
        """
        Возвращает статистику для конкретного конфига (по протоколу, порту, SNI).
        """
        protocol = parsed.get('protocol') or config.split('://')[0].lower()
        port = int(parsed.get('port', 443))
        sni = parsed.get('sni', '')
        key = f"{region}:{protocol}:{port}:{sni}"
        return self.stats.get(key)

    def compute_adjustment(self, config: str, parsed: Dict, region: str = 'RU') -> float:
        """
        Вычисляет корректирующий множитель на основе истории проверок для данного конфига.
        """
        stats = self.get_stats_for_config(config, parsed, region)
        if not stats:
            return 1.0
        total = stats['successes'] + stats['fails']
        if total == 0:
            return 1.0
        success_rate = stats['successes'] / total
        if success_rate > 0.7:
            return 1.2
        elif success_rate < 0.3:
            return 0.7
        else:
            return 1.0
