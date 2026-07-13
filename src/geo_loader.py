"""
Модуль для загрузки и использования локальных баз данных GeoIP2/MMDB.
Поддерживает кэширование и проверку обновлений по ETag/Last-Modified.
Реализован как синглтон, проверяет наличие C-расширения _maxminddb.
"""

import os
import logging
import tempfile
import requests
from pathlib import Path
from typing import Optional, Tuple, Dict
import hashlib
import json
import time
import maxminddb

logger = logging.getLogger(__name__)

# Проверка наличия C-расширения
try:
    import _maxminddb
    HAS_C_EXTENSION = True
    logger.info("libmaxminddb C extension is available (fast path)")
except ImportError:
    HAS_C_EXTENSION = False
    logger.warning(
        "libmaxminddb C extension not installed. "
        "Performance may be degraded. Install with: pip install maxminddb[geoip2]"
    )


class GeoLoader:
    """
    Загружает и читает базы данных MaxMind DB для страны и ASN с кэшированием.
    Реализован как синглтон для предотвращения повторной загрузки.
    """

    _instance = None

    def __new__(cls, country_url: str = None, asn_url: str = None, cache_dir: str = 'configs/cache', cache_ttl_hours: int = 24):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, country_url: str = None, asn_url: str = None,
                 cache_dir: str = 'configs/cache', cache_ttl_hours: int = 24):
        if self._initialized:
            return
        # Используем значения по умолчанию, если не переданы
        from user_settings import GEO_COUNTRY_URL, GEO_ASN_URL
        self.country_url = country_url or GEO_COUNTRY_URL
        self.asn_url = asn_url or GEO_ASN_URL
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_ttl_seconds = cache_ttl_hours * 3600
        self._country_reader = None
        self._asn_reader = None
        self._temp_dir = None
        self._metadata_file = self.cache_dir / 'geo_metadata.json'
        self._metadata = self._load_metadata()
        self._initialized = True

    def _load_metadata(self) -> Dict:
        if self._metadata_file.exists():
            try:
                with open(self._metadata_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        return {}

    def _save_metadata(self):
        try:
            with open(self._metadata_file, 'w') as f:
                json.dump(self._metadata, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save geo metadata: {e}")

    def _get_cache_path(self, url: str) -> Path:
        url_hash = hashlib.md5(url.encode()).hexdigest()[:16]
        return self.cache_dir / f"geo_{url_hash}.mmdb"

    def _is_cache_valid(self, url: str) -> bool:
        cache_path = self._get_cache_path(url)
        if not cache_path.exists():
            return False
        cache_key = f"{url}_timestamp"
        if cache_key in self._metadata:
            age = time.time() - self._metadata[cache_key]
            if age < self.cache_ttl_seconds:
                return True
        return False

    def _is_db_stale(self, cache_path: Path) -> bool:
        if not cache_path.exists():
            return True
        age = time.time() - cache_path.stat().st_mtime
        return age > 7 * 24 * 3600

    def _download_if_needed(self, url: str) -> Optional[Path]:
        cache_path = self._get_cache_path(url)
        if cache_path.exists() and not self._is_db_stale(cache_path):
            logger.info(f"Using cached database: {cache_path}")
            return cache_path

        try:
            logger.info(f"Downloading Geo database from {url} ...")
            response = requests.get(url, stream=True, timeout=60)
            response.raise_for_status()

            with open(cache_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            cache_key = f"{url}_timestamp"
            self._metadata[cache_key] = time.time()
            self._save_metadata()
            logger.info(f"Database cached to {cache_path}")
            return cache_path

        except Exception as e:
            logger.error(f"Failed to download database: {e}")
            return None

    def _open_database(self, url: str) -> Optional[maxminddb.Reader]:
        cache_path = self._download_if_needed(url)
        if cache_path and cache_path.exists():
            try:
                return maxminddb.open_database(str(cache_path))
            except Exception as e:
                logger.error(f"Failed to open database {cache_path}: {e}")
                try:
                    cache_path.unlink()
                except:
                    pass
        return None

    def ensure_databases(self):
        if self._country_reader is None:
            self._country_reader = self._open_database(self.country_url)
        if self._asn_reader is None:
            self._asn_reader = self._open_database(self.asn_url)

    def get_country(self, ip: str) -> Tuple[str, str]:
        if self._country_reader is None:
            return ('XX', 'Unknown')
        try:
            result = self._country_reader.get(ip)
            if result and 'country' in result:
                country = result['country']
                code = country.get('iso_code', 'XX')
                name = country.get('names', {}).get('en', code)
                return (code, name)
            return ('XX', 'Unknown')
        except Exception as e:
            logger.debug(f"Country lookup error for {ip}: {e}")
            return ('XX', 'Unknown')

    def get_asn(self, ip: str) -> Tuple[Optional[str], Optional[str]]:
        if self._asn_reader is None:
            return (None, None)
        try:
            result = self._asn_reader.get(ip)
            if result:
                asn = result.get('autonomous_system_number')
                org = result.get('autonomous_system_organization')
                if asn is not None:
                    return (str(asn), org or 'Unknown')
            return (None, None)
        except Exception as e:
            logger.debug(f"ASN lookup error for {ip}: {e}")
            return (None, None)

    def is_datacenter(self, ip: str) -> bool:
        asn_num, asn_name = self.get_asn(ip)
        if not asn_name:
            return False
        dc_keywords = [
            'cloud', 'host', 'data', 'server', 'vps', 'dedicated',
            'colocation', 'infrastructure', 'digitalocean', 'aws',
            'amazon', 'azure', 'google cloud', 'oracle cloud',
            'linode', 'vultr', 'hetzner', 'ovh', 'scaleway', 'leaseweb'
        ]
        name_lower = asn_name.lower()
        for kw in dc_keywords:
            if kw in name_lower:
                return True
        return False

    def close_and_cleanup(self):
        if self._country_reader:
            self._country_reader.close()
            self._country_reader = None
        if self._asn_reader:
            self._asn_reader.close()
            self._asn_reader = None
        logger.info("Geo databases closed.")

    def __enter__(self):
        self.ensure_databases()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close_and_cleanup()
