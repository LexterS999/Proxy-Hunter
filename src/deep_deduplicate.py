"""
Глубокая дедупликация с оптимизацией через Bloom filter и префиксные деревья.
Теперь использует асинхронный Bloom фильтр (на основе pybloom_live) с шардированием.
"""

import re
import json
import logging
import os
import mmh3
import hashlib
from typing import Dict, List, Set, Optional, Tuple
from collections import defaultdict
from urllib.parse import urlparse, parse_qs

import config_parser as parser
from parse_fallback import FallbackParser
from bloom_async import ShardedBloomDeduplicator
from protocol_registry import registry

logger = logging.getLogger(__name__)

class PrefixTrieNode:
    __slots__ = ('children', 'is_end', 'data')
    def __init__(self):
        self.children = {}
        self.is_end = False
        self.data = None

class PrefixTrie:
    def __init__(self):
        self.root = PrefixTrieNode()

    def insert(self, ip: str, data: any):
        parts = ip.split('.')
        node = self.root
        for part in parts:
            if part not in node.children:
                node.children[part] = PrefixTrieNode()
            node = node.children[part]
        node.is_end = True
        node.data = data

    def search(self, ip: str) -> Optional[any]:
        parts = ip.split('.')
        node = self.root
        for part in parts:
            if part not in node.children:
                return None
            node = node.children[part]
        return node.data if node.is_end else None

    def search_prefix(self, ip: str, depth: int = 3) -> Optional[any]:
        parts = ip.split('.')
        if len(parts) < depth:
            return None
        node = self.root
        for i in range(depth):
            part = parts[i]
            if part not in node.children:
                return None
            node = node.children[part]
        while node:
            if node.is_end:
                return node.data
            node = node.children.get(next(iter(node.children))) if node.children else None
        return None

class DeepDeduplicator:
    def __init__(self):
        self.fingerprints = {}
        self.fingerprint_to_config = {}
        self.best_configs = {}
        self._bloom = ShardedBloomDeduplicator(cache_dir="bloom_shards")
        self._trie = PrefixTrie()
        self._server_cache = {}
        self._seen_in_run = set()  # для дедупликации внутри одного запуска

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
                result['fingerprint'] = hashlib.md5(
                    f"{result['server']}:{result['port']}:{result['credential']}:{net}:{path}".encode()
                ).hexdigest()
            elif config_lower.startswith('vless://'):
                result['protocol'] = 'vless'
                result['server'] = data.get('address')
                result['port'] = int(data.get('port', 0))
                result['credential'] = data.get('uuid', '')
                flow = data.get('flow', '')
                transport = data.get('type', 'tcp')
                result['fingerprint'] = hashlib.md5(
                    f"{result['server']}:{result['port']}:{result['credential']}:{flow}:{transport}".encode()
                ).hexdigest()
            elif config_lower.startswith('trojan://'):
                result['protocol'] = 'trojan'
                result['server'] = data.get('address')
                result['port'] = int(data.get('port', 0))
                result['credential'] = data.get('password', '')
                result['fingerprint'] = hashlib.md5(
                    f"{result['server']}:{result['port']}:{result['credential']}".encode()
                ).hexdigest()
            elif config_lower.startswith('ss://'):
                result['protocol'] = 'ss'
                result['server'] = data.get('address')
                result['port'] = int(data.get('port', 0))
                result['credential'] = f"{data.get('method', '')}:{data.get('password', '')}"
                result['fingerprint'] = hashlib.md5(
                    f"{result['server']}:{result['port']}:{result['credential']}".encode()
                ).hexdigest()
            elif config_lower.startswith(('hysteria2://', 'hy2://')):
                result['protocol'] = 'hysteria2'
                result['server'] = data.get('address')
                result['port'] = int(data.get('port', 0))
                result['credential'] = data.get('password', '')
                result['fingerprint'] = hashlib.md5(
                    f"{result['server']}:{result['port']}:{result['credential']}".encode()
                ).hexdigest()
            elif config_lower.startswith('tuic://'):
                result['protocol'] = 'tuic'
                result['server'] = data.get('address')
                result['port'] = int(data.get('port', 0))
                result['credential'] = f"{data.get('uuid', '')}:{data.get('password', '')}"
                result['fingerprint'] = hashlib.md5(
                    f"{result['server']}:{result['port']}:{result['credential']}".encode()
                ).hexdigest()
            return result if result['fingerprint'] else None
        except Exception as e:
            logger.debug(f"Fingerprint generation failed: {e}")
            return None

    def _get_server_key(self, server: str, port: int) -> str:
        return f"{server}:{port}"

    def _get_ip_prefix(self, server: str, depth: int = 3) -> str:
        parts = server.split('.')
        if len(parts) >= depth:
            return '.'.join(parts[:depth])
        return server

    def is_similar_server(self, fp1: Dict, fp2: Dict, threshold: int = 6) -> bool:
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
        prefix1 = self._get_ip_prefix(server1, threshold)
        prefix2 = self._get_ip_prefix(server2, threshold)
        if prefix1 == prefix2:
            return True
        if self._trie.search_prefix(server1, threshold):
            return True
        return False

    async def deduplicate_configs_async(self, configs: List[str], quality_scores: Dict[str, float] = None) -> List[str]:
        if quality_scores is None:
            quality_scores = {}

        groups = defaultdict(list)
        fingerprint_data = {}

        # Локальный set для дедупликации в рамках одного запуска
        seen_in_run = set()

        for config in configs:
            # Проверяем персистентный Bloom
            if await self._bloom.contains(config):
                # Если конфиг уже был когда-либо обработан, пропускаем
                continue
            # Если уже видели в этом запуске, пропускаем
            if config in seen_in_run:
                continue

            fp_data = self.generate_fingerprint(config)
            if fp_data:
                # Добавляем в Bloom для будущих запусков
                await self._bloom.add(config)
                groups[fp_data['fingerprint']].append(config)
                fingerprint_data[config] = fp_data
                seen_in_run.add(config)

        await self._bloom.save()

        best_configs = []
        seen_fingerprints = set()
        seen_similar = set()

        for fingerprint, group in groups.items():
            if fingerprint in seen_fingerprints:
                continue
            similar = False
            for seen in list(seen_similar):
                fp1 = fingerprint_data.get(group[0])
                fp2 = fingerprint_data.get(seen)
                if self.is_similar_server(fp1, fp2):
                    similar = True
                    break
            if similar:
                continue

            best = max(group, key=lambda c: quality_scores.get(c, 0))
            fp_best = self.generate_fingerprint(best)
            if fp_best and fp_best.get('server'):
                self._trie.insert(fp_best.get('server'), fp_best)
            best_configs.append(best)
            seen_fingerprints.add(fingerprint)
            seen_similar.add(best)

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
