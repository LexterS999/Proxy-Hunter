"""
config_parser.py - Парсер прокси-конфигураций различных протоколов
"""

import base64
import json
import re
import logging
from functools import lru_cache
from typing import Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, unquote

logger = logging.getLogger(__name__)


# [CHANGE] удалён PORT_RANGES, который создавал list(range(1, 65536)) при импорте
# (расход памяти + бессмысленная "валидация" — весь диапазон == любой порт).
def _valid_port(port: Any) -> bool:
    """Лёгкая проверка порта без создания больших списков."""
    try:
        return isinstance(port, int) and 1 <= port <= 65535
    except (ValueError, TypeError):
        return False


class ConfigParser:
    """Парсер прокси-конфигов"""

    SUPPORTED_PROTOCOLS = ['vmess', 'vless', 'trojan', 'ss', 'hysteria2', 'hy2',
                           'wireguard', 'tuic']

    def __init__(self):
        self.stats = {
            'total': 0,
            'parsed': 0,
            'failed': 0,
            'by_protocol': {}
        }

    @lru_cache(maxsize=2048)
    def safe_b64decode(self, data: str) -> Optional[str]:
        """Безопасное base64-декодирование"""
        if not data:
            return None
        try:
            s = data.strip().replace('-', '+').replace('_', '/')
            padding = 4 - len(s) % 4
            if padding != 4:
                s += '=' * padding
            return base64.b64decode(s).decode('utf-8', errors='ignore')
        except Exception:
            return None

    def parse_config(self, config: str) -> Optional[Dict[str, Any]]:
        """Парсит строку конфига в структурированный dict"""
        if not config or not isinstance(config, str):
            return None

        config = config.strip()
        self.stats['total'] += 1

        try:
            lower = config.lower()
            if lower.startswith('vmess://'):
                result = self._parse_vmess(config)
            elif lower.startswith('vless://'):
                result = self._parse_vless(config)
            elif lower.startswith('trojan://'):
                result = self._parse_trojan(config)
            elif lower.startswith('ss://'):
                result = self._parse_shadowsocks(config)
            elif lower.startswith('hysteria2://') or lower.startswith('hy2://'):
                result = self._parse_hysteria2(config)
            elif lower.startswith('wireguard://'):
                result = self._parse_wireguard(config)
            elif lower.startswith('tuic://'):
                result = self._parse_tuic(config)
            else:
                self.stats['failed'] += 1
                return None

            if result:
                self.stats['parsed'] += 1
                proto = result.get('protocol', 'unknown')
                self.stats['by_protocol'][proto] = self.stats['by_protocol'].get(proto, 0) + 1
                return result

            self.stats['failed'] += 1
            return None
        except Exception as e:
            logger.debug(f"⚠️ Ошибка парсинга: {e}")
            self.stats['failed'] += 1
            return None

    def _parse_vmess(self, config: str) -> Optional[Dict]:
        try:
            decoded = self.safe_b64decode(config[8:].strip())
            if not decoded:
                return None
            obj = json.loads(decoded)

            host = str(obj.get('add') or obj.get('host') or obj.get('server') or '')
            try:
                port = int(obj.get('port', 0) or 0)
            except (ValueError, TypeError):
                port = 0

            # [CHANGE] лёгкая проверка порта
            if not host or not _valid_port(port):
                return None

            return {
                'protocol': 'vmess',
                'address': host,
                'port': port,
                'uuid': str(obj.get('id', '') or ''),
                'alter_id': int(obj.get('aid', 0) or 0),
                'network': str(obj.get('net', 'tcp') or 'tcp'),
                'security': str(obj.get('tls', '') or ''),
                'sni': str(obj.get('sni', '') or ''),
                'host_header': str(obj.get('host', '') or ''),
                'path': str(obj.get('path', '') or ''),
                'type': str(obj.get('type', '') or ''),
                'fingerprint': self._make_fingerprint('vmess', host, port, obj.get('id', '')),
                'raw': config,
            }
        except Exception:
            return None

    def _parse_vless(self, config: str) -> Optional[Dict]:
        try:
            parsed = urlparse(config)
            host = parsed.hostname or ''
            port = parsed.port or 0
            uuid = unquote(parsed.username or '')
            params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

            if not host or not _valid_port(port) or not uuid:
                return None

            return {
                'protocol': 'vless',
                'address': host,
                'port': port,
                'uuid': uuid,
                'network': params.get('type', 'tcp'),
                'security': params.get('security', ''),
                'sni': params.get('sni', ''),
                'flow': params.get('flow', ''),
                'pbk': params.get('pbk', ''),
                'sid': params.get('sid', ''),
                'fp': params.get('fp', ''),
                'path': params.get('path', ''),
                'fingerprint': self._make_fingerprint('vless', host, port, uuid),
                'raw': config,
            }
        except Exception:
            return None

    def _parse_trojan(self, config: str) -> Optional[Dict]:
        try:
            parsed = urlparse(config)
            host = parsed.hostname or ''
            port = parsed.port or 0
            password = unquote(parsed.username or '')
            params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

            if not host or not _valid_port(port) or not password:
                return None

            return {
                'protocol': 'trojan',
                'address': host,
                'port': port,
                'password': password,
                'sni': params.get('sni', ''),
                'network': params.get('type', 'tcp'),
                'fingerprint': self._make_fingerprint('trojan', host, port, password),
                'raw': config,
            }
        except Exception:
            return None

    def _parse_shadowsocks(self, config: str) -> Optional[Dict]:
        try:
            body = config[5:].strip()
            # Формат: base64(method:password)@host:port  или  ss://base64(method:password@host:port)
            if '@' in body:
                userinfo, hostport = body.rsplit('@', 1)
                decoded = self.safe_b64decode(userinfo) or userinfo
                if ':' in decoded:
                    method, password = decoded.split(':', 1)
                else:
                    method, password = '', decoded
                host, _, port_s = hostport.partition(':')
                port = int(port_s) if port_s.isdigit() else 0
            else:
                decoded = self.safe_b64decode(body)
                if not decoded or '@' not in decoded:
                    return None
                userinfo, hostport = decoded.rsplit('@', 1)
                method, password = userinfo.split(':', 1) if ':' in userinfo else ('', userinfo)
                host, _, port_s = hostport.partition(':')
                port = int(port_s) if port_s.isdigit() else 0

            if not host or not _valid_port(port):
                return None

            return {
                'protocol': 'shadowsocks',
                'address': host,
                'port': port,
                'method': method,
                'password': password,
                'fingerprint': self._make_fingerprint('ss', host, port, password),
                'raw': config,
            }
        except Exception:
            return None

    def _parse_hysteria2(self, config: str) -> Optional[Dict]:
        try:
            parsed = urlparse(config)
            host = parsed.hostname or ''
            port = parsed.port or 0
            password = unquote(parsed.username or '')
            params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

            if not host or not _valid_port(port):
                return None

            return {
                'protocol': 'hysteria2',
                'address': host,
                'port': port,
                'password': password,
                'sni': params.get('sni', ''),
                'insecure': params.get('insecure', '0'),
                'fingerprint': self._make_fingerprint('hysteria2', host, port, password),
                'raw': config,
            }
        except Exception:
            return None

    def _parse_wireguard(self, config: str) -> Optional[Dict]:
        try:
            parsed = urlparse(config)
            host = parsed.hostname or ''
            port = parsed.port or 0
            private_key = unquote(parsed.username or '')
            params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

            if not host or not _valid_port(port):
                return None

            return {
                'protocol': 'wireguard',
                'address': host,
                'port': port,
                'private_key': private_key,
                'public_key': params.get('publickey', ''),
                'reserved': params.get('reserved', ''),
                'mtu': params.get('mtu', '1420'),
                'fingerprint': self._make_fingerprint('wireguard', host, port, private_key),
                'raw': config,
            }
        except Exception:
            return None

    def _parse_tuic(self, config: str) -> Optional[Dict]:
        try:
            parsed = urlparse(config)
            host = parsed.hostname or ''
            port = parsed.port or 0
            uuid = unquote(parsed.username or '')
            password = unquote(parsed.password or '')
            params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

            if not host or not _valid_port(port):
                return None

            return {
                'protocol': 'tuic',
                'address': host,
                'port': port,
                'uuid': uuid,
                'password': password,
                'sni': params.get('sni', ''),
                'congestion_control': params.get('congestion_control', 'bbr'),
                'fingerprint': self._make_fingerprint('tuic', host, port, uuid),
                'raw': config,
            }
        except Exception:
            return None

    @staticmethod
    def _make_fingerprint(protocol: str, host: str, port: int, cred: str) -> str:
        """Отпечаток для дедупликации (детерминированный)."""
        try:
            import xxhash
            return xxhash.xxh64(f"{protocol}:{host}:{port}:{cred}".encode()).hexdigest()
        except ImportError:
            import hashlib
            return hashlib.sha256(f"{protocol}:{host}:{port}:{cred}".encode()).hexdigest()[:16]

    def get_stats(self) -> Dict:
        return self.stats.copy()
