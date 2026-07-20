import asyncio
import ssl
import time
import logging
import socket
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs
import aiohttp
from aiohttp import ClientTimeout

from config_parser import decode_vmess, parse_vless, parse_trojan, parse_shadowsocks
from retry_utils import retry_with_backoff
from session_pool import SessionPool
from config_identity import ConfigIdentity

logger = logging.getLogger(__name__)

# Кеш TCP-рукопожатий
_tcp_cache = {}
_TCP_CACHE_TTL = 300  # 5 минут

class IntelligentProbe:
    def __init__(self, timeout=5.0, max_attempts=3):
        self.timeout = timeout
        self.max_attempts = max_attempts

    async def probe(self, config: str, parsed: dict = None, ml_score: float = 50.0) -> Dict:
        """
        Выполняет зондирование с адаптивным числом попыток, fast fail и кешированием TCP.
        ml_score используется для выбора числа попыток: >70 -> 1, 40-70 -> 2, <40 -> 3.
        """
        if parsed is None:
            from parse_fallback import FallbackParser
            parsed, _ = FallbackParser.parse_with_stats(config)
            if not parsed:
                return {'success': False, 'error': 'parse_failed'}

        # Адаптивное число попыток
        if ml_score > 70:
            max_attempts = 1
        elif ml_score > 40:
            max_attempts = 2
        else:
            max_attempts = min(self.max_attempts, 3)

        protocol = config.split('://')[0].lower()
        transport = parsed.get('type', parsed.get('net', 'tcp'))
        host = parsed.get('address') or parsed.get('add')
        port = int(parsed.get('port', 443))
        sni = parsed.get('sni', host)
        path = parsed.get('path', '/')
        host_header = parsed.get('host', host)

        # Адаптивный таймаут на основе истории (если есть в parsed)
        avg_lat = parsed.get('avg_latency_24h', 1000)
        timeout = max(2.0, min(10.0, avg_lat / 100 + 2))

        results = []
        for attempt in range(1, max_attempts + 1):
            probe_result = await self._single_probe(
                protocol, transport, host, port, sni, host_header, path,
                parsed, attempt, max_attempts, timeout
            )
            results.append(probe_result)
            if probe_result.get('success'):
                break
            # Fast fail: если ошибка фатальная, прерываем
            error = probe_result.get('error')
            if error in ('connection_refused', 'dns_failed', 'ssl_error'):
                break
            await asyncio.sleep(0.5 * attempt)

        success = any(r.get('success') for r in results)
        latencies = [r['latency'] for r in results if r.get('success')]
        avg_lat = sum(latencies) / len(latencies) if latencies else 0
        best = min(results, key=lambda x: x.get('latency', 9999)) if results else {}

        return {
            'success': success,
            'latency': avg_lat,
            'tls_handshake': best.get('tls_handshake', 0),
            'http_first_byte': best.get('http_first_byte', 0),
            'http_total': best.get('http_total', 0),
            'status_code': best.get('status_code', 0),
            'attempts': results,
            'error': best.get('error') if not success else None,
            'protocol': protocol,
            'transport': transport,
            'sni_used': sni,
            'host_used': host_header,
            'path_used': path,
            'attempt_number': len(results),
            'total_attempts': max_attempts,
        }

    async def _single_probe(self, protocol, transport, host, port, sni, host_header, path,
                             parsed, attempt, total_attempts, timeout) -> Dict:
        start_time = time.time()
        result = {
            'attempt': attempt,
            'total_attempts': total_attempts,
            'success': False,
            'latency': 0,
            'tls_handshake': 0,
            'http_first_byte': 0,
            'http_total': 0,
            'status_code': 0,
            'error': None,
        }

        try:
            # 1. TCP/TLS рукопожатие с кешированием
            use_tls = parsed.get('security') in ('tls', 'reality') or parsed.get('tls') in ('tls', 'reality')
            cache_key = (host, port, use_tls)
            if cache_key in _tcp_cache:
                cached = _tcp_cache[cache_key]
                if time.time() - cached['ts'] > _TCP_CACHE_TTL:
                    del _tcp_cache[cache_key]
                else:
                    result['tls_handshake'] = cached['latency']
                    # Если кеш говорит, что соединение недоступно, сразу возвращаем ошибку
                    if cached['error']:
                        result['error'] = cached['error']
                        return result
            else:
                tls_start = time.time()
                try:
                    if use_tls:
                        context = ssl.create_default_context()
                        if parsed.get('allow_insecure') in ('1', 'true'):
                            context.check_hostname = False
                            context.verify_mode = ssl.CERT_NONE
                        if sni:
                            context.check_hostname = False
                        reader, writer = await asyncio.wait_for(
                            asyncio.open_connection(host, port, ssl=context, server_hostname=sni),
                            timeout=timeout
                        )
                    else:
                        reader, writer = await asyncio.wait_for(
                            asyncio.open_connection(host, port, ssl=False),
                            timeout=timeout
                        )
                    tcp_latency = (time.time() - tls_start) * 1000
                    writer.close()
                    await writer.wait_closed()
                    _tcp_cache[cache_key] = {'latency': tcp_latency, 'ts': time.time(), 'error': None}
                    result['tls_handshake'] = tcp_latency
                except ConnectionRefusedError:
                    result['error'] = 'connection_refused'
                    _tcp_cache[cache_key] = {'latency': 0, 'ts': time.time(), 'error': 'connection_refused'}
                    return result
                except socket.gaierror:
                    result['error'] = 'dns_failed'
                    _tcp_cache[cache_key] = {'latency': 0, 'ts': time.time(), 'error': 'dns_failed'}
                    return result
                except ssl.SSLError:
                    result['error'] = 'ssl_error'
                    _tcp_cache[cache_key] = {'latency': 0, 'ts': time.time(), 'error': 'ssl_error'}
                    return result
                except Exception as e:
                    result['error'] = str(e)
                    _tcp_cache[cache_key] = {'latency': 0, 'ts': time.time(), 'error': str(e)}
                    return result

            # 2. HTTP-зонд (используем HEAD вместо GET)
            session = await SessionPool().get_session()
            scheme = 'https' if use_tls else 'http'
            url = f"{scheme}://{host}:{port}{path}"

            headers = {'Host': host_header} if host_header else {}
            if protocol == 'vmess':
                alter_id = parsed.get('aid', 0)
                if alter_id and alter_id > 0:
                    headers['X-AlterId'] = str(alter_id)
            elif protocol == 'vless':
                flow = parsed.get('flow', '')
                if flow:
                    headers['X-VLESS-Flow'] = flow
            elif protocol == 'trojan':
                password = parsed.get('password', '')
                if password:
                    headers['X-Trojan-Password'] = password

            http_start = time.time()
            async with session.head(url, headers=headers, timeout=ClientTimeout(total=timeout)) as resp:
                result['http_first_byte'] = (time.time() - http_start) * 1000
                result['status_code'] = resp.status
                await resp.read()
                result['http_total'] = (time.time() - http_start) * 1000

            if result['status_code'] < 400:
                result['success'] = True
                result['latency'] = (time.time() - start_time) * 1000
            else:
                result['error'] = f"HTTP {result['status_code']}"
        except asyncio.TimeoutError:
            result['error'] = 'timeout'
        except Exception as e:
            result['error'] = str(e)

        return result
