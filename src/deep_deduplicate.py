"""
Глубокая дедупликация с использованием xxHash и упрощённым индексом.
Все методы асинхронные.
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

_dns_cache = {}
_dns_cache_time = {}
_DNS_TTL = 300


@lru_cache(maxsize=1024)
def _resolve_hostname(hostname: str) -> Optional[str]:
    if not hostname:
        return None
    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass
    try:
        ip = socket.gethostbyname(hostname)
        return ip
    except Exception:
        return None


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
        try:
            ip = ipaddress.ip_address(server)
            if ip.version == 4:
                network = ipaddress.ip_network(f"{server}/24", strict=False)
                return f"{network}:{protocol}:{port}"
            elif ip.version == 6:
                network = ipaddress.ip_network(f"{server}/48", strict=False)
                return f"{network}:{protocol}:{port}"
        except ValueError:
            resolved = _resolve_hostname(server)
            if resolved:
                try:
                    ip = ipaddress.ip_address(resolved)
                    if ip.version == 4:
                        network = ipaddress.ip_network(f"{resolved}/24", strict=False)
                        return f"{network}:{protocol}:{port}"
                    elif ip.version == 6:
                        network = ipaddress.ip_network(f"{resolved}/48", strict=False)
                        return f"{network}:{protocol}:{port}"
                except ValueError:
                    pass
            return f"{server}:{protocol}:{port}"
        return f"{server}:{protocol}:{port}"

    def is_similar_server(self, fp1: Dict, fp2: Dict) -> bool:
        if not fp1 or not fp2:
            return False
        if fp1.get('protocol') != fp2.get('protocol'):
            return False
        server1, server2 = fp1.get('server'), fp2.get('server')
        port1, port2 = fp1.get('port'), fp2.get('port')
        if abs(port1 - port2) > 5:
            return False
        subnet1 = self._get_subnet_key(server1, port1, fp1['protocol'])
        subnet2 = self._get_subnet_key(server2, port2, fp2['protocol'])
        return subnet1 == subnet2

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
        seen_subnets = set()

        for fingerprint, group in groups.items():
            if fingerprint in seen_fingerprints:
                continue
            sample_config = group[0]
            sample_fp = fingerprint_data.get(sample_config)
            if sample_fp:
                subnet_key = self._get_subnet_key(sample_fp['server'], sample_fp['port'], sample_fp['protocol'])
                if subnet_key in seen_subnets:
                    continue
                seen_subnets.add(subnet_key)

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

    # Синхронный метод для обратной совместимости
    def deduplicate_configs(self, configs: List[str], quality_scores: Dict[str, float] = None) -> List[str]:
        try:
            loop = asyncio.get_running_loop()
            # Если цикл уже запущен, создаём задачу
            return asyncio.run(self.deduplicate_configs_async(configs, quality_scores))
        except RuntimeError:
            # Нет запущенного цикла
            return asyncio.run(self.deduplicate_configs_async(configs, quality_scores))

    def remove_low_quality(self, configs: List[str], quality_data: List[Dict], min_score: float = 30.0) -> List[str]:
        filtered = [
            item['config'] for item in quality_data
            if item['quality'].get('score', 0) >= min_score
        ]
        logger.info(f"Quality filter: {len(configs)} → {len(filtered)} configs (min_score={min_score})")
        return filtered
