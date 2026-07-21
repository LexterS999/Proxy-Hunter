"""
Глубокая дедупликация с использованием xxHash и индексом по IP-префиксам.

ИСПРАВЛЕНО: O(n²) вложенный цикл заменён на O(n) с использованием
индекса по IP-префиксам (dict: prefix -> set of config keys).
"""

import re
import json
import logging
import os
import xxhash
from typing import Dict, List, Set, Optional, Tuple
from collections import defaultdict

import config_parser
from parse_fallback import FallbackParser
from bloom_async import ShardedBloomDeduplicator

logger = logging.getLogger(__name__)


class DeepDeduplicator:
    def __init__(self) -> None:
        self.fingerprints: Dict[str, Dict] = {}
        self.fingerprint_to_config: Dict[str, str] = {}
        self.best_configs: Dict[str, str] = {}
        self._bloom = ShardedBloomDeduplicator(cache_dir="bloom_shards")
        # Упрощённый индекс: множество ключей сервер+порт+протокол+креденшл
        self._index: Set[str] = set()
        self._server_cache: Dict[str, Dict] = {}
        # НОВЫЙ: индекс по IP-префиксам для O(1) поиска похожих серверов
        self._prefix_index: Dict[str, Set[str]] = defaultdict(set)

    def generate_fingerprint(self, config: str) -> Optional[Dict]:
        try:
            config_lower = config.lower()
            result: Dict = {
                'protocol': None,
                'server': None,
                'port': None,
                'credential': None,
                'fingerprint': None
            }
            data, method = FallbackParser.parse_with_stats(config)
            if not data:
                return None

            if config_lower.startswith('vmess://'):
                result['protocol'] = 'vmess'
                result['server'] = data.get('add')
                result['port'] = int(data.get('port', 0))
                result['credential'] = data.get('id', '')
                net = data.get('net', 'tcp')
                path = data.get('path', '')
                result['fingerprint'] = xxhash.xxh64(
                    f"{result['server']}:{result['port']}:{result['credential']}:{net}:{path}".encode()
                ).hexdigest()

            elif config_lower.startswith('vless://'):
                result['protocol'] = 'vless'
                result['server'] = data.get('address')
                result['port'] = int(data.get('port', 0))
                result['credential'] = data.get('uuid', '')
                flow = data.get('flow', '')
                transport = data.get('type', 'tcp')
                result['fingerprint'] = xxhash.xxh64(
                    f"{result['server']}:{result['port']}:{result['credential']}:{flow}:{transport}".encode()
                ).hexdigest()

            elif config_lower.startswith('trojan://'):
                result['protocol'] = 'trojan'
                result['server'] = data.get('address')
                result['port'] = int(data.get('port', 0))
                result['credential'] = data.get('password', '')
                result['fingerprint'] = xxhash.xxh64(
                    f"{result['server']}:{result['port']}:{result['credential']}".encode()
                ).hexdigest()

            elif config_lower.startswith('ss://'):
                result['protocol'] = 'ss'
                result['server'] = data.get('address')
                result['port'] = int(data.get('port', 0))
                result['credential'] = f"{data.get('method', '')}:{data.get('password', '')}"
                result['fingerprint'] = xxhash.xxh64(
                    f"{result['server']}:{result['port']}:{result['credential']}".encode()
                ).hexdigest()

            elif config_lower.startswith(('hysteria2://', 'hy2://')):
                result['protocol'] = 'hysteria2'
                result['server'] = data.get('address')
                result['port'] = int(data.get('port', 0))
                result['credential'] = data.get('password', '')
                result['fingerprint'] = xxhash.xxh64(
                    f"{result['server']}:{result['port']}:{result['credential']}".encode()
                ).hexdigest()

            elif config_lower.startswith('tuic://'):
                result['protocol'] = 'tuic'
                result['server'] = data.get('address')
                result['port'] = int(data.get('port', 0))
                result['credential'] = f"{data.get('uuid', '')}:{data.get('password', '')}"
                result['fingerprint'] = xxhash.xxh64(
                    f"{result['server']}:{result['port']}:{result['credential']}".encode()
                ).hexdigest()

            return result if result['fingerprint'] else None
        except Exception as e:
            logger.debug(f"Fingerprint generation failed: {e}")
            return None

    def _get_index_key(self, fp_data: Dict) -> str:
        """Упрощённый ключ: сервер:порт:протокол:креденшл (хеш)"""
        return f"{fp_data['server']}:{fp_data['port']}:{fp_data['protocol']}:{fp_data['credential']}"

    def _get_prefix_key(self, server: str, protocol: str, threshold: int = 3) -> str:
        """
        Генерирует ключ префикса для индексации.
        Для IP: первые threshold октетов.
        Для доменов: первые threshold частей домена.
        """
        if not server:
            return f"{protocol}:unknown"
        parts = server.split('.')
        if len(parts) >= threshold:
            prefix = '.'.join(parts[:threshold])
        else:
            prefix = server
        return f"{protocol}:{prefix}"

    def is_similar_server(self, fp1: Dict, fp2: Dict, threshold: int = 3) -> bool:
        """
        Упрощённая проверка: сравниваем IP-префиксы (первые threshold октетов).
        ИСПРАВЛЕНО: threshold уменьшен с 6 до 3 для корректной работы с IPv4.
        """
        if not fp1 or not fp2:
            return False
        if fp1.get('protocol') != fp2.get('protocol'):
            return False
        server1 = fp1.get('server', '')
        server2 = fp2.get('server', '')
        port1 = fp1.get('port', 0)
        port2 = fp2.get('port', 0)

        if server1 == server2 and port1 == port2:
            return True
        if abs(port1 - port2) > 5:
            return False

        # Проверка префикса IP (первые threshold октетов)
        parts1 = server1.split('.')
        parts2 = server2.split('.')
        if len(parts1) >= threshold and len(parts2) >= threshold:
            prefix1 = '.'.join(parts1[:threshold])
            prefix2 = '.'.join(parts2[:threshold])
            return prefix1 == prefix2
        return False

    def _find_similar_in_index(self, fp_data: Dict, threshold: int = 3) -> bool:
        """
        O(1) проверка наличия похожего сервера в индексе префиксов.
        ИСПРАВЛЕНО: заменяет O(n) перебор seen_similar.
        """
        if not fp_data:
            return False
        server = fp_data.get('server', '')
        protocol = fp_data.get('protocol', '')
        port = fp_data.get('port', 0)

        prefix_key = self._get_prefix_key(server, protocol, threshold)

        if prefix_key not in self._prefix_index:
            return False

        # Проверяем только конфиги с тем же префиксом (обычно 1-5 штук)
        for existing_config in self._prefix_index[prefix_key]:
            existing_fp = self._server_cache.get(existing_config)
            if existing_fp and self.is_similar_server(fp_data, existing_fp, threshold):
                return True
        return False

    def _add_to_prefix_index(self, config: str, fp_data: Dict, threshold: int = 3) -> None:
        """Добавляет конфиг в индекс префиксов."""
        if not fp_data:
            return
        server = fp_data.get('server', '')
        protocol = fp_data.get('protocol', '')
        prefix_key = self._get_prefix_key(server, protocol, threshold)
        self._prefix_index[prefix_key].add(config)
        self._server_cache[config] = fp_data

    async def deduplicate_configs_async(
        self,
        configs: List[str],
        quality_scores: Dict[str, float] = None
    ) -> List[str]:
        if quality_scores is None:
            quality_scores = {}

        groups: Dict[str, List[str]] = defaultdict(list)
        fingerprint_data: Dict[str, Dict] = {}

        for config in configs:
            # Быстрая проверка через Bloom
            if await self._bloom.contains(config):
                fp_data = self.generate_fingerprint(config)
                if fp_data:
                    index_key = self._get_index_key(fp_data)
                    if index_key in self._index:
                        continue

            fp_data = self.generate_fingerprint(config)
            if fp_data:
                await self._bloom.add(config)
                groups[fp_data['fingerprint']].append(config)
                fingerprint_data[config] = fp_data

        await self._bloom.save()

        best_configs: List[str] = []
        seen_fingerprints: Set[str] = set()

        for fingerprint, group in groups.items():
            if fingerprint in seen_fingerprints:
                continue

            # ИСПРАВЛЕНО: O(1) проверка через индекс префиксов вместо O(n) перебора
            fp_data = fingerprint_data.get(group[0])
            if fp_data and self._find_similar_in_index(fp_data):
                continue

            # Выбираем лучший по качеству
            best = max(group, key=lambda c: quality_scores.get(c, 0))
            fp_best = fingerprint_data.get(best) or self.generate_fingerprint(best)

            if fp_best:
                index_key = self._get_index_key(fp_best)
                self._index.add(index_key)
                best_configs.append(best)
                seen_fingerprints.add(fingerprint)
                # Добавляем в индекс префиксов
                self._add_to_prefix_index(best, fp_best)
            else:
                # Если не удалось сгенерировать, добавляем первый
                best_configs.append(group[0])
                seen_fingerprints.add(fingerprint)

        logger.info(f"Deep deduplication: {len(configs)} → {len(best_configs)} configs")
        return best_configs

    def deduplicate_configs(
        self,
        configs: List[str],
        quality_scores: Dict[str, float] = None
    ) -> List[str]:
        import asyncio
        return asyncio.run(self.deduplicate_configs_async(configs, quality_scores))

    def remove_low_quality(
        self,
        configs: List[str],
        quality_data: List[Dict],
        min_score: float = 30.0
    ) -> List[str]:
        filtered = [
            item['config'] for item in quality_data
            if item['quality'].get('score', 0) >= min_score
        ]
        logger.info(f"Quality filter: {len(configs)} → {len(filtered)} configs (min_score={min_score})")
        return filtered
