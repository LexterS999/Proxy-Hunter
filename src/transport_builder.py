import logging
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)

def map_transport_for_singbox(net_type: str) -> str:
    transport_map = {
        'httpupgrade': 'ws',
        'splithttp': 'http',
        'xhttp': 'http'  # Добавлено
    }
    return transport_map.get(net_type, net_type)


def build_xray_settings(data: Dict) -> Dict:
    stream_settings = {"network": "tcp", "security": "none"}

    net_type = data.get('net', data.get('type', 'tcp')).lower()
    security = data.get('security', data.get('tls', 'none')).lower()
    address = data.get('address', data.get('add', ''))

    try:
        stream_settings["network"] = net_type

        if net_type == 'ws':
            stream_settings["wsSettings"] = {
                "path": data.get('path', '/'),
                "headers": {"Host": data.get('host', address)}
            }
        elif net_type == 'grpc':
            stream_settings["grpcSettings"] = {
                "serviceName": data.get('path', data.get('serviceName', ''))
            }
        elif net_type in ('http', 'h2'):
            stream_settings["httpSettings"] = {
                "host": [data.get('host', address)],
                "path": data.get('path', '/')
            }
        elif net_type == 'quic':
            stream_settings["quicSettings"] = {"security": "none", "header": {"type": "none"}}
        elif net_type == 'kcp':
            stream_settings["kcpSettings"] = {"header": {"type": "none"}}
        elif net_type == 'httpupgrade':
            stream_settings["httpupgradeSettings"] = {
                "path": data.get('path', '/'),
                "host": data.get('host', address)
            }
        elif net_type == 'splithttp':
            stream_settings["splithttpSettings"] = {
                "path": data.get('path', '/'),
                "host": data.get('host', address)
            }
        elif net_type == 'xhttp':
            stream_settings["xhttpSettings"] = {
                "path": data.get('path', '/'),
                "host": data.get('host', address)
            }

        if security == 'reality':
            stream_settings["security"] = "reality"
            stream_settings["realitySettings"] = {
                "serverName": data.get('sni', address),
                "publicKey": data.get('pbk', ''),
                "shortId": data.get('sid', ''),
                "fingerprint": data.get('fp', 'chrome')
            }
        elif security == 'tls' or (data.get('protocol') == 'trojan'):
            stream_settings["security"] = "tls"
            stream_settings["tlsSettings"] = {
                "serverName": data.get('sni', address),
                "allowInsecure": False,
                "fingerprint": data.get('fp', 'chrome'),
                "alpn": data.get('alpn', '').split(',') if data.get('alpn') else ["h2", "http/1.1"]
            }
        elif security == 'xtls':
            stream_settings["security"] = "xtls"
            stream_settings["xtlsSettings"] = {
                "serverName": data.get('sni', address),
                "allowInsecure": False,
                "alpn": data.get('alpn', '').split(',') if data.get('alpn') else ["h2", "http/1.1"]
            }

    except Exception as e:
        logger.warning(f"Error building Xray settings: {e}")

    return stream_settings
