import logging
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse
import config_parser

logger = logging.getLogger(__name__)

class ConfigQualityChecker:
    """Проверяет качество конфигураций без активных пингов."""
    
    def __init__(self, timeout: float = 3.0, max_workers: int = 30):
        self.timeout = timeout
        self.max_workers = max_workers
    
    def extract_server_info(self, config: str) -> Optional[Dict]:
        """Извлекает информацию о сервере из конфигурации."""
        try:
            if config.startswith('vmess://'):
                data = config_parser.decode_vmess(config)
                if data:
                    return {'host': data.get('add'), 'port': data.get('port'), 'protocol': 'vmess', 'parsed': data}
            elif config.startswith('vless://'):
                data = config_parser.parse_vless(config)
                if data:
                    return {'host': data.get('address'), 'port': data.get('port'), 'protocol': 'vless', 'parsed': data}
            elif config.startswith('trojan://'):
                data = config_parser.parse_trojan(config)
                if data:
                    return {'host': data.get('address'), 'port': data.get('port'), 'protocol': 'trojan', 'parsed': data}
            elif config.startswith('ss://'):
                data = config_parser.parse_shadowsocks(config)
                if data:
                    return {'host': data.get('address'), 'port': data.get('port'), 'protocol': 'ss', 'parsed': data}
            return None
        except Exception as e:
            logger.debug(f"Failed to extract server info: {e}")
            return None
    
    def check_config_quality(self, config: str) -> Dict:
        """Возвращает базовую информацию о конфигурации без проверок."""
        server_info = self.extract_server_info(config)
        if not server_info:
            return {'valid': False, 'latency': 9999.0, 'score': 0, 'error': 'no_server_info'}
        return {
            'valid': True,
            'latency': 0,  # не используется
            'score': 100,  # временно, будет пересчитано позже
            'protocol': server_info['protocol'],
            'server': server_info['host'],
            'port': server_info['port'],
            'parsed': server_info['parsed']
        }
    
    def batch_check(self, configs: list, min_score: float = 25.0) -> list:
        """Пакетная обработка — просто собирает данные."""
        results = []
        for config in configs:
            result = self.check_config_quality(config)
            if result.get('valid', False):
                results.append({
                    'config': config,
                    'quality': result
                })
        return results
