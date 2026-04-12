#!/usr/bin/env python3
from __future__ import annotations

import argparse
import pickle
import socketserver
import threading
import time
from pathlib import Path

BASE = Path(__file__).resolve().parent / "fake_hierarchy"


def _read_name(packet: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    while True:
        if offset >= len(packet):
            raise ValueError("name extends beyond packet")

        length = packet[offset]
        if length == 0:
            offset += 1
            break

        if length & 0xC0:
            raise ValueError("compressed names not supported in incoming queries")

        offset += 1
        end = offset + length
        if end > len(packet):
            raise ValueError("truncated label")

        labels.append(packet[offset:end].decode("ascii"))
        offset = end

    return ".".join(labels), offset


def _parse_question(packet: bytes) -> tuple[str, int, int, int]:
    if len(packet) < 12:
        raise ValueError("packet too short")

    qdcount = int.from_bytes(packet[4:6], "big")
    if qdcount != 1:
        raise ValueError("expected exactly one question")

    offset = 12
    qname, offset = _read_name(packet, offset)

    if offset + 4 > len(packet):
        raise ValueError("truncated question")

    qtype = int.from_bytes(packet[offset:offset + 2], "big")
    qclass = int.from_bytes(packet[offset + 2:offset + 4], "big")
    return qname, qtype, qclass, offset + 4


def _get_rd_bit(packet: bytes) -> int:
    if len(packet) < 4:
        raise ValueError("packet too short for flags")
    flags = int.from_bytes(packet[2:4], "big")
    return 1 if (flags & 0x0100) else 0


def _set_txid(packet: bytes, txid: int) -> bytes:
    if len(packet) < 2:
        raise ValueError("packet too short for TXID")
    return txid.to_bytes(2, "big") + packet[2:]


class FakeDNSUDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address, handler_class, *, role: str, db_path: Path, log_path: Path):
        super().__init__(server_address, handler_class)
        self.role = role
        with db_path.open("rb") as f:
            self.db: dict[str, bytes] = pickle.load(f)
        self.log_path = log_path

    def log(self, message: str) -> None:
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(message + "\n")


class FakeDNSHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        server: FakeDNSUDPServer = self.server  # type: ignore[assignment]

        try:
            qname, qtype, qclass, _ = _parse_question(data)
            rd = _get_rd_bit(data)

            if qtype != 1 or qclass != 1:
                server.log(
                    f"role={server.role} qname={qname} qtype={qtype} qclass={qclass} rd={rd} result=BAD_QUERY_TYPE"
                )
                return

            if server.role == "recursive" and rd != 1:
                server.log(f"role={server.role} qname={qname} rd={rd} result=BAD_RD")
                return

            if server.role != "recursive" and rd != 0:
                server.log(f"role={server.role} qname={qname} rd={rd} result=BAD_RD")
                return

            response = server.db.get(qname)
            if response is None:
                server.log(
                    f"role={server.role} qname={qname} qtype={qtype} qclass={qclass} rd={rd} result=MISS"
                )
                return

            txid = int.from_bytes(data[:2], "big")
            response = _set_txid(response, txid)
            server.log(f"role={server.role} qname={qname} qtype={qtype} qclass={qclass} rd={rd} result=OK")
            sock.sendto(response, self.client_address)
        except Exception as exc:
            server.log(f"role={server.role} result=ERROR error={exc}")


SERVERS = [
    ("recursive", 2053, "recursive_db.pkl"),
    ("root", 3053, "root_db.pkl"),
    ("tld", 4053, "tld_db.pkl"),
    ("auth-a", 5053, "auth_a_db.pkl"),
    ("auth-b", 6053, "auth_b_db.pkl"),
]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--log", default=str(BASE / "fake_dns.log"))
    args = parser.parse_args()

    log_path = Path(args.log)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text("", encoding="utf-8")

    servers: list[FakeDNSUDPServer] = []
    for role, port, db_name in SERVERS:
        srv = FakeDNSUDPServer(
            (args.host, port),
            FakeDNSHandler,
            role=role,
            db_path=BASE / db_name,
            log_path=log_path,
        )
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()
        servers.append(srv)
        print(f"started {role} fake DNS on {args.host}:{port}", flush=True)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        for srv in servers:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    main()