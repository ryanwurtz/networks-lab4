import json
import socket
from pathlib import Path

# DO NOT MODIFY


DEFAULT_TIMEOUT = 2.0
SERVER_MAP_PATH = Path(__file__).resolve().parent.parent / "fake_hierarchy" / "server_map.json"


def _resolve_server(server_ip: str) -> tuple[str, int]:
    data = json.loads(SERVER_MAP_PATH.read_text())
    host, port = data.get(server_ip, [server_ip, 53])
    return host, port


def send_dns_query(server_ip: str, packet: bytes, timeout: float = DEFAULT_TIMEOUT) -> socket.socket:
    host, port = _resolve_server(server_ip)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.sendto(packet, (host, port))
    return sock


def recv_dns_response(sock: socket.socket) -> bytes:
    response, _ = sock.recvfrom(4096)
    sock.close()
    return response