"""
Глубокая дедупликация с использованием xxHash и упрощённым индексом.
Добавлен ScalableBloomFilter, упрощена логика is_similar_server.
"""

import re
import json
import logging
import os
import ipaddress
import socket
import asyncio
from functools import lru_cache
import xxhash
from typing import Dict, List, Set, Optional, Tuple
from collections import defaultdict

import config_parser
from parse_fallback import FallbackParser
from bloom_async import ShardedBloomDeduplicator
from config_identity import ConfigIdentity

logger = logging.getLogger(__name__)

# ============================
# ScalableBloomFilter
# ============================

try:
    from pybloom_live import BloomFilter
except ImportError:
    class BloomFilter:
        def __init__(self, capacity, error_rate):
            self.capacity = capacity
            self.error_rate = error_rate
            self.data = set()
        def add(self, item):
            self.data.add(item)
        def __contains__(self, item):
            return item in self.data
        def __len__(self):
            return len(self.data)

class ScalableBloomFilter:
    def __init__(self, initial_capacity=100000, error_rate=0.001):
        self.filters = [BloomFilter(initial_capacity, error_rate)]
        self.error_rate = error_rate

    def add(self, item):
        for f in self.filters:
            if item in f:
                return
        if len(self.filters[-1]) >= self.filters[-1].capacity:
            new_cap = self.filters[-1].capacity * 2
            self.filters.append(BloomFilter(new_cap, self.error_rate))
        self.filters[-1].add(item)

    def __contains__(self, item):
        for f in self.filters:
            if item in f:
                return True
        return False

# ============================
# Основной класс DeepDeduplicator
# ============================

class DeepDeduplicator:
    def __init__(self):
        self.fingerprints = {}
        self.fingerprint_to_config = {}
        self.best_configs = {}
        self._bloom = ShardedBloomDeduplicator(cache_dir="bloom_shards")
        self._subnet_index: Dict[str, Set[str]] = defaultdict(set)
        self._server_cache = {}
        self._index = set()
        self._protocol_priority = {
            'vless': 1,
            'vmess': 1,
            'trojan': 2,
            'ss': 2,
            'hysteria2': 2,
            'tuic': 3
        }
        self._use_subnet_dedup = False

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
            return result if result['fingerprint'] else None
        except Exception as e:
            logger.debug(f"Fingerprint generation failed: {e}")
            return None

    def _get_index_key(self, fp_data: Dict) -> str:
        return f"{fp_data['server']}:{fp_data['port']}:{fp_data['protocol']}:{fp_data['credential']}"

    def _get_subnet_key(self, server: str, port: int, protocol: str) -> str:
        return f"{server}:{port}:{protocol}"

    def is_similar_server(self, fp1: Dict, fp2: Dict) -> bool:
        if not fp1 or not fp2:
            return False
        if fp1.get('protocol') != fp2.get('protocol'):
            return False
        server1, server2 = fp1.get('server'), fp2.get('server')
        port1, port2 = fp1.get('port'), fp2.get('port')
        if port1 == port2 and server1 == server2:
            return True
        return False

    async def _resolve_hostname_async(self, hostname: str) -> Optional[str]:
        """
        Разрешает имя хоста в IP-адрес.
        Использует aiodns (с созданием DNSResolver на лету) или socket.gethostbyname.
        """
        try:
            import aiodns
            loop = asyncio.get_running_loop()
            resolver = aiodns.DNSResolver(loop=loop)
            result = await resolver.query(hostname, 'A')
            if result:
                return result[0].host
        except ImportError:
            pass
        except Exception:
            pass

        try:
            return socket.gethostbyname(hostname)
        except:
            return None

    async def contains_batch(self, configs: List[str]) -> Dict[str, bool]:
        return await self._bloom.contains_batch(configs)

    async def deduplicate_configs_async(self, configs: List[str], quality_scores: Dict[str, float] = None) -> List[str]:
        if quality_scores is None:
            quality_scores = {}

        groups = defaultdict(list)
        fingerprint_data = {}

        presence = await self._bloom.contains_batch(configs)
        for config in configs:
            if presence.get(config, False):
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
        seen_servers = set()

        for fingerprint, group in groups.items():
            if fingerprint in seen_fingerprints:
                continue
            sample_config = group[0]
            sample_fp = fingerprint_data.get(sample_config)
            if sample_fp:
                server_key = f"{sample_fp['server']}:{sample_fp['port']}:{sample_fp['protocol']}"
                if server_key in seen_servers:
                    continue
                seen_servers.add(server_key)

            def combined_score(cfg):
                q = quality_scores.get(cfg, 0)
                proto = cfg.split('://')[0].lower() if '://' in cfg else ''
                priority = self._protocol_priority.get(proto, 3)
                priority_score = max(0, 1 - (priority - 1) * 0.3)
                return q * 0.6 + priority_score * 40

            best = max(group, key=combined_score)
            fp_best = self.generate_fingerprint(best)
            if fp_best:
                index_key = self._get_index_key(fp_best)
                self._index.add(index_key)
                best_configs.append(best)
                seen_fingerprints.add(fingerprint)
            else:
                best_configs.append(group[0])
                seen_fingerprints.add(fingerprint)

        logger.info(f"Deep deduplication: {len(configs)} → {len(best_configs)} configs")
        return best_configs

    def deduplicate_configs(self, configs: List[str], quality_scores: Dict[str, float] = None) -> List[str]:
        try:
            loop = asyncio.get_running_loop()
            return asyncio.run(self.deduplicate_configs_async(configs, quality_scores))
        except RuntimeError:
            return asyncio.run(self.deduplicate_configs_async(configs, quality_scores))

    def remove_low_quality(self, configs: List[str], quality_data: List[Dict], min_score: float = 30.0) -> List[str]:
        filtered = [
            item['config'] for item in quality_data
            if item['quality'].get('score', 0) >= min_score
        ]
        logger.info(f"Quality filter: {len(configs)} → {len(filtered)} configs (min_score={min_score})")
        return filtered
