"""
Модуль для проверки прокси через реальный Xray-core (проверка протокола).
Запускает Xray с конфигом из одной строки, отправляет HTTP-запрос через SOCKS5.
"""

import asyncio
import json
import logging
import subprocess
import tempfile
import os
import time
from typing import Dict, Optional, List
import aiohttp
from aiohttp import ClientTimeout
import socket

from config_parser import decode_vmess, parse_vless, parse_trojan, parse_shadowsocks

logger = logging.getLogger(__name__)

class XrayProbe:
    """Проверяет работоспособность конфига через запуск Xray и HTTP через SOCKS5."""

    def __init__(self, xray_path: str = "xray", timeout: float = 8.0):
        self.xray_path = xray_path
        self.timeout = timeout
        self._socks_port = None
        self._process = None
        self._temp_dir = None

    async def probe_config(self, config: str) -> Dict:
        """Запускает Xray с заданным конфигом и проверяет доступность через SOCKS5."""
        result = {'config': config, 'success': False, 'latency': -1.0, 'error': None, 'status_code': 0}
        try:
            # Создаём временный конфиг для Xray
            xray_config = self._build_xray_config(config)
            if not xray_config:
                result['error'] = 'failed_to_build_config'
                return result

            # Запускаем Xray
            with tempfile.TemporaryDirectory() as tmpdir:
                config_path = os.path.join(tmpdir, 'config.json')
                with open(config_path, 'w') as f:
                    json.dump(xray_config, f, indent=2)

                # Определяем порт для SOCKS5
                socks_port = 10808
                self._socks_port = socks_port
                # Запускаем Xray в фоне
                proc = await asyncio.create_subprocess_exec(
                    self.xray_path, 'run', '-c', config_path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                self._process = proc
                # Даём время на запуск
                await asyncio.sleep(1.0)

                # Проверяем через SOCKS5
                start = time.time()
                session = aiohttp.ClientSession()
                proxy_url = f"socks5://127.0.0.1:{socks_port}"
                try:
                    async with session.get("https://www.google.com/generate_204",
                                           proxy=proxy_url,
                                           timeout=ClientTimeout(total=self.timeout)) as resp:
                        result['latency'] = (time.time() - start) * 1000
                        result['status_code'] = resp.status
                        if resp.status in (200, 204):
                            result['success'] = True
                        else:
                            result['error'] = f"HTTP {resp.status}"
                except Exception as e:
                    result['error'] = str(e)
                finally:
                    await session.close()

                # Завершаем процесс
                if proc.returncode is None:
                    proc.terminate()
                    await asyncio.sleep(0.5)
                    if proc.returncode is None:
                        proc.kill()
                await proc.wait()

        except Exception as e:
            result['error'] = str(e)
            logger.error(f"Xray probe error: {e}")

        return result

    def _build_xray_config(self, config: str) -> Optional[Dict]:
        """Создаёт минимальный конфиг Xray для одного outbound."""
        try:
            # Определяем протокол
            parsed = None
            if config.startswith('vmess://'):
                parsed = decode_vmess(config)
                if parsed:
                    outbound = {
                        "protocol": "vmess",
                        "settings": {
                            "vnext": [{
                                "address": parsed.get('add'),
                                "port": int(parsed.get('port')),
                                "users": [{
                                    "id": parsed.get('id'),
                                    "alterId": int(parsed.get('aid', 0)),
                                    "security": parsed.get('scy', 'auto')
                                }]
                            }]
                        },
                        "streamSettings": self._build_stream_settings(parsed)
                    }
            elif config.startswith('vless://'):
                parsed = parse_vless(config)
                if parsed:
                    outbound = {
                        "protocol": "vless",
                        "settings": {
                            "vnext": [{
                                "address": parsed.get('address'),
                                "port": parsed.get('port'),
                                "users": [{
                                    "id": parsed.get('uuid'),
                                    "flow": parsed.get('flow', ''),
                                    "encryption": "none"
                                }]
                            }]
                        },
                        "streamSettings": self._build_stream_settings(parsed)
                    }
            elif config.startswith('trojan://'):
                parsed = parse_trojan(config)
                if parsed:
                    outbound = {
                        "protocol": "trojan",
                        "settings": {
                            "servers": [{
                                "address": parsed.get('address'),
                                "port": parsed.get('port'),
                                "password": parsed.get('password'),
                            }]
                        },
                        "streamSettings": self._build_stream_settings(parsed)
                    }
            elif config.startswith('ss://'):
                parsed = parse_shadowsocks(config)
                if parsed:
                    outbound = {
                        "protocol": "shadowsocks",
                        "settings": {
                            "servers": [{
                                "address": parsed.get('address'),
                                "port": parsed.get('port'),
                                "method": parsed.get('method'),
                                "password": parsed.get('password')
                            }]
                        },
                        "streamSettings": {"network": "tcp"}
                    }
            else:
                return None

            # Собираем полный конфиг
            xray_config = {
                "log": {"loglevel": "warning"},
                "inbounds": [
                    {
                        "port": self._socks_port or 10808,
                        "protocol": "socks",
                        "settings": {"auth": "noauth", "udp": True},
                        "tag": "socks-in"
                    }
                ],
                "outbounds": [outbound],
                "routing": {
                    "rules": [
                        {"type": "field", "outboundTag": "proxy", "network": "tcp,udp"}
                    ]
                }
            }
            return xray_config
        except Exception as e:
            logger.error(f"Failed to build Xray config: {e}")
            return None

    def _build_stream_settings(self, parsed: Dict) -> Dict:
        """Строит streamSettings на основе parsed."""
        settings = {"network": "tcp", "security": "none"}
        net = parsed.get('type', parsed.get('net', 'tcp')).lower()
        settings["network"] = net

        if net == 'ws':
            settings["wsSettings"] = {
                "path": parsed.get('path', '/'),
                "headers": {"Host": parsed.get('host', parsed.get('address', ''))}
            }
        elif net == 'grpc':
            settings["grpcSettings"] = {
                "serviceName": parsed.get('serviceName', parsed.get('path', ''))
            }
        # Другие транспорты можно добавить по аналогии

        # Security
        security = parsed.get('security', parsed.get('tls', 'none')).lower()
        if security in ('tls', 'reality'):
            settings["security"] = security
            if security == 'reality':
                settings["realitySettings"] = {
                    "serverName": parsed.get('sni', parsed.get('address', '')),
                    "publicKey": parsed.get('pbk', ''),
                    "shortId": parsed.get('sid', ''),
                    "fingerprint": parsed.get('fp', 'chrome')
                }
            elif security == 'tls':
                settings["tlsSettings"] = {
                    "serverName": parsed.get('sni', parsed.get('address', '')),
                    "allowInsecure": False,
                    "fingerprint": parsed.get('fp', 'chrome'),
                    "alpn": parsed.get('alpn', '').split(',') if parsed.get('alpn') else ["h2", "http/1.1"]
                }
        return settings

    async def probe_batch(self, configs: List[str], limit: int = 100) -> List[Dict]:
        """Проверяет первые limit конфигов."""
        configs = configs[:limit]
        results = []
        for cfg in configs:
            res = await self.probe_config(cfg)
            results.append(res)
        return results
