"""
Глубокая дедупликация с использованием xxHash и упрощённым индексом.
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
    def __init__(self):
        self.fingerprints = {}
        self.fingerprint_to_config = {}
        self.best_configs = {}
        self._bloom = ShardedBloomDeduplicator(cache_dir="bloom_shards")
        # Упрощённый индекс: множество ключей сервер+порт+протокол+креденшл
        self._index: Set[str] = set()
        self._server_cache = {}

    def generate_fingerprint(self, config: str) -> Optional[Dict]:
        try:
            config_lower = config.lower()
            result = {
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

    def is_similar_server(self, fp1: Dict, fp2: Dict, threshold: int = 6) -> bool:
        """Упрощённая проверка: сравниваем IP-префиксы (первые threshold октетов)"""
        if not fp1 or not fp2:
            return False
        if fp1.get('protocol') != fp2.get('protocol'):
            return False
        server1, server2 = fp1.get('server'), fp2.get('server')
        port1, port2 = fp1.get('port'), fp2.get('port')
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

    async def deduplicate_configs_async(self, configs: List[str], quality_scores: Dict[str, float] = None) -> List[str]:
        if quality_scores is None:
            quality_scores = {}

        groups = defaultdict(list)
        fingerprint_data = {}

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

        best_configs = []
        seen_fingerprints = set()
        seen_similar = set()

        for fingerprint, group in groups.items():
            if fingerprint in seen_fingerprints:
                continue
            # Проверяем схожесть с уже отобранными
            similar = False
            for seen in list(seen_similar):
                fp1 = fingerprint_data.get(group[0])
                fp2 = fingerprint_data.get(seen)
                if self.is_similar_server(fp1, fp2):
                    similar = True
                    break
            if similar:
                continue

            # Выбираем лучший по качеству
            best = max(group, key=lambda c: quality_scores.get(c, 0))
            fp_best = self.generate_fingerprint(best)
            if fp_best:
                index_key = self._get_index_key(fp_best)
                self._index.add(index_key)
                best_configs.append(best)
                seen_fingerprints.add(fingerprint)
                seen_similar.add(best)
            else:
                # Если не удалось сгенерировать, добавляем первый
                best_configs.append(group[0])
                seen_fingerprints.add(fingerprint)
                seen_similar.add(group[0])

        logger.info(f"Deep deduplication: {len(configs)} → {len(best_configs)} configs")
        return best_configs

    def deduplicate_configs(self, configs: List[str], quality_scores: Dict[str, float] = None) -> List[str]:
        import asyncio
        return asyncio.run(self.deduplicate_configs_async(configs, quality_scores))

    def remove_low_quality(self, configs: List[str], quality_data: List[Dict], min_score: float = 30.0) -> List[str]:
        filtered = [
            item['config'] for item in quality_data
            if item['quality'].get('score', 0) >= min_score
        ]
        logger.info(f"Quality filter: {len(configs)} → {len(filtered)} configs (min_score={min_score})")
        return filtered
