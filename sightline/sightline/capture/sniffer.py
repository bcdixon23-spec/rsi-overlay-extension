"""Live packet capture with no third-party dependencies, on Linux and Windows.

  * Linux   - an AF_PACKET raw socket delivers full Ethernet frames (link type
              ETHERNET). Needs root or CAP_NET_RAW.
  * Windows - an AF_INET raw socket with SIO_RCVALL delivers IP packets (link
              type RAW). Needs Administrator.
  * Other   - no portable live-capture path; capture with Wireshark/tcpdump and
              analyse the saved file with `sightline pcap FILE`.

A lightweight post-capture filter (host/port/proto) avoids needing a BPF
compiler; it is applied in Python after each frame is decoded.
"""

from __future__ import annotations

import os
import socket
import struct
import sys
import time
from dataclasses import dataclass, field
from typing import Iterator

from sightline.capture import decode as dec
from sightline.capture.pcap import LINKTYPE_ETHERNET, LINKTYPE_RAW

ETH_P_ALL = 0x0003
IS_LINUX = sys.platform.startswith("linux")
IS_WINDOWS = os.name == "nt"


class CaptureError(RuntimeError):
    pass


@dataclass
class CaptureFilter:
    hosts: set[str] = field(default_factory=set)
    ports: set[int] = field(default_factory=set)
    protos: set[str] = field(default_factory=set)

    @classmethod
    def parse(cls, spec: str | None) -> "CaptureFilter":
        """Parse 'host 10.0.0.1 port 80 tcp' / 'port 22,443 udp' style filters."""
        f = cls()
        if not spec:
            return f
        tokens = spec.replace(",", " ").split()
        i = 0
        while i < len(tokens):
            tok = tokens[i].lower()
            if tok in ("host", "net") and i + 1 < len(tokens):
                f.hosts.add(tokens[i + 1])
                i += 2
            elif tok == "port" and i + 1 < len(tokens):
                j = i + 1
                while j < len(tokens) and tokens[j].isdigit():
                    f.ports.add(int(tokens[j]))
                    j += 1
                i = j
            elif tok in ("tcp", "udp", "icmp", "arp", "icmpv6"):
                f.protos.add(tok)
                i += 1
            elif tok.isdigit():
                f.ports.add(int(tok))
                i += 1
            else:
                f.hosts.add(tokens[i])
                i += 1
        return f

    def matches(self, pkt: dec.Decoded) -> bool:
        if self.protos and pkt.proto not in self.protos:
            return False
        if self.hosts and pkt.src not in self.hosts and pkt.dst not in self.hosts:
            return False
        if self.ports and (pkt.sport not in self.ports and pkt.dport not in self.ports):
            return False
        return True


@dataclass
class CaptureStats:
    frames: int = 0
    bytes: int = 0
    matched: int = 0
    started: float = 0.0
    stopped: float = 0.0


def list_interfaces() -> list[str]:
    try:
        return [name for _, name in socket.if_nameindex()]
    except (OSError, AttributeError):
        return []


def _default_interface() -> str:
    names = [n for n in list_interfaces() if n != "lo"]
    return names[0] if names else (list_interfaces() or ["lo"])[0]


def _primary_ip() -> str:
    """Best-guess local IP for Windows raw capture (no traffic is sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("203.0.113.1", 9))  # TEST-NET-3, unrouteable; just sets the local addr
        return s.getsockname()[0]
    except OSError:
        return "0.0.0.0"
    finally:
        s.close()


@dataclass
class LiveCapture:
    interface: str = ""
    snaplen: int = 65535
    count: int = 0  # 0 = unlimited
    seconds: float = 0.0  # 0 = unlimited
    max_bytes: int = 0
    cfilter: CaptureFilter = field(default_factory=CaptureFilter)
    promiscuous: bool = False
    stats: CaptureStats = field(default_factory=CaptureStats)
    linktype: int = LINKTYPE_ETHERNET

    def __post_init__(self):
        if not self.interface:
            self.interface = _primary_ip() if IS_WINDOWS else _default_interface()

    # ---------------------------------------------------------- backends

    def _open_linux(self) -> socket.socket:
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        except PermissionError:
            raise CaptureError(_PERM_LINUX) from None
        except OSError as exc:
            raise CaptureError(f"could not open capture socket: {exc}") from exc
        try:
            sock.bind((self.interface, 0))
        except OSError as exc:
            sock.close()
            raise CaptureError(
                f"cannot capture on {self.interface!r}: {exc}. Interfaces: {', '.join(list_interfaces())}"
            ) from exc
        if self.promiscuous:
            _set_promisc_linux(sock, self.interface)
        self.linktype = LINKTYPE_ETHERNET
        sock.settimeout(0.5)
        return sock

    def _open_windows(self) -> socket.socket:
        host = self.interface if _looks_like_ip(self.interface) else _primary_ip()
        if host in ("", "0.0.0.0"):
            raise CaptureError("could not determine a local IP to capture on; pass --iface <local-ip>")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sock.bind((host, 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)  # promiscuous: all IP traffic
        except PermissionError:
            raise CaptureError(_PERM_WINDOWS) from None
        except (OSError, AttributeError) as exc:
            raise CaptureError(f"could not start Windows capture on {host}: {exc}") from exc
        self.interface = host
        self.linktype = LINKTYPE_RAW
        sock.settimeout(0.5)
        return sock

    def _open(self) -> socket.socket:
        if IS_LINUX and hasattr(socket, "AF_PACKET"):
            return self._open_linux()
        if IS_WINDOWS:
            return self._open_windows()
        raise CaptureError(
            "live capture is only built in on Linux and Windows. On macOS/BSD, capture with "
            "Wireshark or tcpdump and run: sightline pcap <file.pcap>"
        )

    def _close(self, sock: socket.socket) -> None:
        if IS_WINDOWS:
            try:
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except OSError:
                pass
        sock.close()

    # ------------------------------------------------------------ capture

    def frames(self) -> Iterator[tuple[float, bytes, int]]:
        """Yield (timestamp, data, original_length) until a limit is reached."""
        sock = self._open()
        self.stats.started = time.time()
        deadline = self.stats.started + self.seconds if self.seconds else None
        try:
            while True:
                if deadline and time.time() >= deadline:
                    break
                try:
                    raw = sock.recv(self.snaplen)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not raw:
                    continue
                self.stats.frames += 1
                self.stats.bytes += len(raw)
                yield time.time(), raw, len(raw)
                if self.count and self.stats.frames >= self.count:
                    break
                if self.max_bytes and self.stats.bytes >= self.max_bytes:
                    break
        finally:
            self.stats.stopped = time.time()
            self._close(sock)

    def packets(self) -> Iterator[dec.Decoded]:
        for ts, raw, orig in self.frames():
            pkt = dec.decode(raw, ts, orig, self.linktype)
            if self.cfilter.matches(pkt):
                self.stats.matched += 1
                yield pkt


_PERM_LINUX = (
    "permission denied opening a capture socket. Run with sudo, or grant the capability once:\n"
    "  sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f $(which python3))"
)
_PERM_WINDOWS = (
    "permission denied. Live capture on Windows needs an Administrator prompt "
    "(right-click > Run as administrator)."
)


def _looks_like_ip(value: str) -> bool:
    try:
        socket.inet_aton(value)
        return True
    except OSError:
        return False


def _set_promisc_linux(sock: socket.socket, interface: str) -> None:
    SOL_PACKET, PACKET_ADD_MEMBERSHIP, PACKET_MR_PROMISC = 263, 1, 1
    try:
        ifindex = socket.if_nametoindex(interface)
        mreq = struct.pack("IHH8s", ifindex, PACKET_MR_PROMISC, 0, b"")
        sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)
    except OSError:
        pass  # capturing still works without promiscuous mode


def can_capture() -> bool:
    if IS_LINUX and hasattr(socket, "AF_PACKET"):
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    if IS_WINDOWS:
        return True  # admin is checked when the socket is opened
    return False


def capture_backend() -> str:
    if IS_LINUX:
        return "Linux AF_PACKET (Ethernet)"
    if IS_WINDOWS:
        return "Windows raw socket SIO_RCVALL (IP)"
    return "unavailable (use pcap files)"
