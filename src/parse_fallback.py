"""
Модуль для парсинга прокси-конфигураций с множественными стратегиями.
Использует строгий парсинг, затем «мягкий», затем эвристический.
"""

import re
import base64
import json
import logging
from typing import Dict, Optional, Tuple, Any
from urllib.parse import urlparse, parse_qs, unquote

logger = logging.getLogger(__name__)


class FallbackParser:
    """Парсер с несколькими стратегиями для извлечения данных из конфигураций"""
    
    # Регулярные выражения для эвристического парсинга
    UUID_PATTERN = re.compile(
        r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        re.IGNORECASE
    )
    IP_PORT_PATTERN = re.compile(r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):([0-9]{1,5})')
    DOMAIN_PORT_PATTERN = re.compile(r'([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}):([0-9]{1,5})')
    
    @staticmethod
    def is_base64(s: str) -> bool:
        try:
            s = s.rstrip('=')
            return bool(re.match(r'^[A-Za-z0-9+/\-_]+$', s))
        except:
            return False
            
    @staticmethod
    def safe_b64decode(s: str) -> Optional[str]:
        try:
            s = s.replace('-', '+').replace('_', '/')
            padding = '=' * (-len(s) % 4)
            return base64.b64decode(s + padding).decode('utf-8', errors='ignore')
        except:
            return None
    
    @classmethod
    def parse_vmess_fallback(cls, config: str) -> Optional[Dict]:
        """Парсинг VMess с несколькими стратегиями"""
        if not config.startswith('vmess://'):
            return None
            
        encoded = config[8:].strip()
        
        # Стратегия 1: стандартный парсинг через библиотечный парсер
        try:
            import config_parser as parser
            data = parser.decode_vmess(config)
            if data and data.get('add') and data.get('port') and data.get('id'):
                return data
        except Exception as e:
            logger.debug(f"Standard VMess parse failed: {e}")
        
        # Стратегия 2: «мягкий» парсинг с исправлением
        try:
            # Очищаем от мусора
            encoded_clean = re.sub(r'[^A-Za-z0-9+/=_-]', '', encoded)
            decoded = cls.safe_b64decode(encoded_clean)
            if decoded:
                data = json.loads(decoded)
                # Нормализуем поля
                if data.get('add') and data.get('port'):
                    data['port'] = int(data['port'])
                    return data
        except Exception as e:
            logger.debug(f"Soft VMess parse failed: {e}")
        
        # Стратегия 3: эвристический парсинг через регулярные выражения
        try:
            # Ищем UUID
            uuid_match = cls.UUID_PATTERN.search(config)
            if not uuid_match:
                return None
            uuid = uuid_match.group(0)
            
            # Ищем IP:port или domain:port
            ip_match = cls.IP_PORT_PATTERN.search(config)
            domain_match = cls.DOMAIN_PORT_PATTERN.search(config)
            
            if ip_match:
                address = ip_match.group(1)
                port = int(ip_match.group(2))
            elif domain_match:
                address = domain_match.group(1)
                port = int(domain_match.group(2))
            else:
                return None
                
            return {
                'add': address,
                'port': port,
                'id': uuid,
                'aid': 0,
                'net': 'tcp',
                'tls': 'none',
                'ps': config[:30]
            }
        except Exception as e:
            logger.debug(f"Heuristic VMess parse failed: {e}")
            
        return None
    
    @classmethod
    def parse_vless_fallback(cls, config: str) -> Optional[Dict]:
        """Парсинг VLESS с несколькими стратегиями"""
        if not config.startswith('vless://'):
            return None
            
        # Стратегия 1: стандартный парсинг
        try:
            import config_parser as parser
            data = parser.parse_vless(config)
            if data and data.get('address') and data.get('port') and data.get('uuid'):
                return data
        except Exception as e:
            logger.debug(f"Standard VLESS parse failed: {e}")
        
        # Стратегия 2: эвристический парсинг
        try:
            # Извлекаем UUID
            uuid_match = cls.UUID_PATTERN.search(config)
            if not uuid_match:
                return None
            uuid = uuid_match.group(0)
            
            # Извлекаем адрес и порт
            parsed = urlparse(config)
            if parsed.hostname and parsed.port:
                address = parsed.hostname
                port = parsed.port
            else:
                ip_match = cls.IP_PORT_PATTERN.search(config)
                domain_match = cls.DOMAIN_PORT_PATTERN.search(config)
                if ip_match:
                    address = ip_match.group(1)
                    port = int(ip_match.group(2))
                elif domain_match:
                    address = domain_match.group(1)
                    port = int(domain_match.group(2))
                else:
                    return None
            
            # Извлекаем параметры
            params = parse_qs(parsed.query) if parsed.query else {}
            
            return {
                'uuid': uuid,
                'address': address,
                'port': port,
                'flow': params.get('flow', [''])[0],
                'sni': params.get('sni', [address])[0],
                'type': params.get('type', ['tcp'])[0],
                'security': params.get('security', ['none'])[0],
                'pbk': params.get('pbk', [''])[0],
                'sid': params.get('sid', [''])[0]
            }
        except Exception as e:
            logger.debug(f"Heuristic VLESS parse failed: {e}")
            
        return None
    
    @classmethod
    def parse_trojan_fallback(cls, config: str) -> Optional[Dict]:
        """Парсинг Trojan с несколькими стратегиями"""
        if not config.startswith('trojan://'):
            return None
            
        # Стратегия 1: стандартный парсинг
        try:
            import config_parser as parser
            data = parser.parse_trojan(config)
            if data and data.get('address') and data.get('port') and data.get('password'):
                return data
        except Exception as e:
            logger.debug(f"Standard Trojan parse failed: {e}")
        
        # Стратегия 2: эвристический
        try:
            parsed = urlparse(config)
            if parsed.username and parsed.hostname and parsed.port:
                return {
                    'password': unquote(parsed.username),
                    'address': parsed.hostname,
                    'port': parsed.port,
                    'sni': parsed.hostname,
                    'type': 'tcp',
                    'security': 'tls'
                }
        except Exception as e:
            logger.debug(f"Heuristic Trojan parse failed: {e}")
            
        return None
    
    @classmethod
    def parse_ss_fallback(cls, config: str) -> Optional[Dict]:
        """Парсинг Shadowsocks с несколькими стратегиями"""
        if not config.startswith('ss://'):
            return None
            
        # Стратегия 1: стандартный парсинг
        try:
            import config_parser as parser
            data = parser.parse_shadowsocks(config)
            if data and data.get('address') and data.get('port') and data.get('method'):
                return data
        except Exception as e:
            logger.debug(f"Standard SS parse failed: {e}")
        
        # Стратегия 2: эвристический
        try:
            content = config[5:]
            if '@' in content:
                # Формат: method:password@host:port
                auth_part, server_part = content.split('@', 1)
                if ':' in auth_part:
                    method, password = auth_part.split(':', 1)
                else:
                    # Может быть base64
                    decoded = cls.safe_b64decode(auth_part)
                    if decoded and ':' in decoded:
                        method, password = decoded.split(':', 1)
                    else:
                        return None
                host, port_str = server_part.rsplit(':', 1)
                return {
                    'method': method.lower(),
                    'password': password,
                    'address': host,
                    'port': int(port_str)
                }
        except Exception as e:
            logger.debug(f"Heuristic SS parse failed: {e}")
            
        return None
    
    @classmethod
    def parse_any(cls, config: str) -> Optional[Dict]:
        """
        Универсальный парсинг с автоматическим определением протокола
        и применением всех стратегий.
        """
        if config.startswith('vmess://'):
            return cls.parse_vmess_fallback(config)
        elif config.startswith('vless://'):
            return cls.parse_vless_fallback(config)
        elif config.startswith('trojan://'):
            return cls.parse_trojan_fallback(config)
        elif config.startswith('ss://'):
            return cls.parse_ss_fallback(config)
        else:
            return None
    
    @classmethod
    def parse_with_stats(cls, config: str) -> Tuple[Optional[Dict], str]:
        """
        Парсит конфигурацию и возвращает (данные, метод_парсинга).
        Метод: 'strict', 'soft', 'heuristic', 'failed'
        """
        if config.startswith('vmess://'):
            try:
                import config_parser as parser
                data = parser.decode_vmess(config)
                if data and data.get('add') and data.get('port') and data.get('id'):
                    return data, 'strict'
            except:
                pass
            data = cls.parse_vmess_fallback(config)
            if data and data.get('add') and data.get('port') and data.get('id'):
                return data, 'heuristic'
            return None, 'failed'
            
        elif config.startswith('vless://'):
            try:
                import config_parser as parser
                data = parser.parse_vless(config)
                if data and data.get('address') and data.get('port') and data.get('uuid'):
                    return data, 'strict'
            except:
                pass
            data = cls.parse_vless_fallback(config)
            if data:
                return data, 'heuristic'
            return None, 'failed'
            
        elif config.startswith('trojan://'):
            try:
                import config_parser as parser
                data = parser.parse_trojan(config)
                if data and data.get('address') and data.get('port') and data.get('password'):
                    return data, 'strict'
            except:
                pass
            data = cls.parse_trojan_fallback(config)
            if data:
                return data, 'heuristic'
            return None, 'failed'
            
        elif config.startswith('ss://'):
            try:
                import config_parser as parser
                data = parser.parse_shadowsocks(config)
                if data and data.get('address') and data.get('port') and data.get('method'):
                    return data, 'strict'
            except:
                pass
            data = cls.parse_ss_fallback(config)
            if data:
                return data, 'heuristic'
            return None, 'failed'
            
        return None, 'unknown'
