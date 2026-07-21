"""
SNI Probe — инструмент для исследования блокировок по SNI у провайдеров.
Выполняет две проверки: Control Check (прямое подключение к домену)
и Probe Check (подключение к вашему серверу с SNI чужого домена).
"""

import asyncio
import ssl
import logging
import time
from typing import Dict, List, Optional, Tuple
import aiohttp
from aiohttp import ClientTimeout
import socket

logger = logging.getLogger(__name__)

class SNIProbe:
    def __init__(self, timeout: float = 5.0, port: int = 443):
        self.timeout = timeout
        self.port = port

    async def control_check(self, domain: str) -> Dict:
        """
        Control Check: прямое подключение к домену без подмены SNI.
        """
        result = {
            'domain': domain,
            'port': self.port,
            'success': False,
            'latency': -1.0,
            'error': None,
            'tls_handshake': -1.0
        }
        try:
            start = time.time()
            context = ssl.create_default_context()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(domain, self.port, ssl=context, server_hostname=domain),
                timeout=self.timeout
            )
            latency = (time.time() - start) * 1000
            writer.close()
            await writer.wait_closed()
            result['success'] = True
            result['latency'] = latency
            result['tls_handshake'] = latency
        except Exception as e:
            result['error'] = str(e)
        return result

    async def probe_check(self, server_ip: str, sni: str) -> Dict:
        """
        Probe Check: подключение к серверу (по IP) с использованием чужого SNI.
        """
        result = {
            'server_ip': server_ip,
            'sni': sni,
            'port': self.port,
            'success': False,
            'latency': -1.0,
            'error': None,
            'tls_handshake': -1.0
        }
        try:
            start = time.time()
            context = ssl.create_default_context()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(server_ip, self.port, ssl=context, server_hostname=sni),
                timeout=self.timeout
            )
            latency = (time.time() - start) * 1000
            writer.close()
            await writer.wait_closed()
            result['success'] = True
            result['latency'] = latency
            result['tls_handshake'] = latency
        except Exception as e:
            result['error'] = str(e)
        return result

    async def probe_batch(self, server_ip: str, sni_list: List[str]) -> List[Dict]:
        """
        Проверяет сервер с несколькими SNI.
        """
        tasks = [self.probe_check(server_ip, sni) for sni in sni_list]
        return await asyncio.gather(*tasks)

    async def analyze(self, domain: str, server_ip: str, sni_list: List[str]) -> Dict:
        """
        Полный анализ: сначала control check, затем probe checks.
        """
        control = await self.control_check(domain)
        probe_results = await self.probe_batch(server_ip, sni_list)
        return {
            'control': control,
            'probes': probe_results,
            'analysis': {
                'control_success': control['success'],
                'working_snis': [p['sni'] for p in probe_results if p['success']],
                'blocked_snis': [p['sni'] for p in probe_results if not p['success']]
            }
        }
