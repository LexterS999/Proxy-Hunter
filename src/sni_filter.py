"""
SNI-фильтр для эмуляции блокировок (Buildcage).
Позволяет создать среду, которая блокирует все SNI, кроме разрешённых.
"""

import logging
from typing import List, Set, Dict

logger = logging.getLogger(__name__)

class SNIFilter:
    def __init__(self, allowed_snis: List[str] = None):
        self.allowed_snis = set(allowed_snis or ['cloudflare.com', 'www.cloudflare.com'])

    def is_allowed(self, sni: str) -> bool:
        if not sni:
            return False
        # Проверяем точное совпадение или суффикс
        for allowed in self.allowed_snis:
            if sni == allowed or sni.endswith('.' + allowed):
                return True
        return False

    def filter_config(self, config: str, parsed: Dict) -> bool:
        """
        Проверяет, разрешён ли SNI в конфиге.
        """
        sni = parsed.get('sni', '')
        return self.is_allowed(sni)

    def simulate_blocking(self, configs: List[Dict]) -> List[Dict]:
        """
        Фильтрует список конфигов, оставляя только те, у которых SNI разрешён.
        """
        return [c for c in configs if self.filter_config(c.get('config', ''), c.get('parsed', {}))]
