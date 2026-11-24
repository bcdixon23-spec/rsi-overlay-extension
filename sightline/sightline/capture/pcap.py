"""Read and write classic libpcap capture files.

The format is deliberately the classic .pcap (not pcapng) so that captures
Sightline writes open directly in Wireshark, tcpdump and tshark, and captures
from those tools can be analysed by Sightline. Layout per the libpcap spec:

  global header (24 bytes): magic, version_major, version_minor, thiszone,
                            sigfigs, snaplen, network (link type)
  record header (16 bytes): ts_sec, ts_usec, incl_len, orig_len
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator

MAGIC_USEC = 0xA1B2C3D4
MAGIC_NSEC = 0xA1B23C4D
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101  # raw IP, no link layer
LINKTYPE_LINUX_SLL = 113  # Linux "cooked" capture (SOCK_DGRAM)

_GLOBAL = struct.Struct("<IHHiIII")
_GLOBAL_BE = struct.Struct(">IHHiIII")
_REC = struct.Struct("<IIII")
_REC_BE = struct.Struct(">IIII")


class PcapError(ValueError):
    pass


@dataclass
class Frame:
    ts: float
    data: bytes
    orig_len: int
    linktype: int = LINKTYPE_ETHERNET


class PcapWriter:
    """Stream frames to a .pcap file."""

    def __init__(self, fh: BinaryIO, linktype: int = LINKTYPE_ETHERNET, snaplen: int = 262144):
        self.fh = fh
        self.linktype = linktype
        self.snaplen = snaplen
        self.fh.write(_GLOBAL.pack(MAGIC_USEC, 2, 4, 0, 0, snaplen, linktype))

    def write(self, ts: float, data: bytes, orig_len: int | None = None) -> None:
        orig = orig_len if orig_len is not None else len(data)
        clipped = data[: self.snaplen]
        sec = int(ts)
        usec = int(round((ts - sec) * 1_000_000))
        if usec >= 1_000_000:  # rounding can tip into the next second
            sec += 1
            usec -= 1_000_000
        self.fh.write(_REC.pack(sec, usec, len(clipped), orig))
        self.fh.write(clipped)

    def write_frame(self, frame: Frame) -> None:
        self.write(frame.ts, frame.data, frame.orig_len)

    def close(self) -> None:
        self.fh.close()

    def __enter__(self) -> "PcapWriter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def open_writer(path: str | Path, linktype: int = LINKTYPE_ETHERNET, snaplen: int = 262144) -> PcapWriter:
    return PcapWriter(Path(path).open("wb"), linktype, snaplen)


def read_frames(path: str | Path, limit: int | None = None) -> Iterator[Frame]:
    """Yield frames from a .pcap file (classic format, either byte order)."""
    with Path(path).open("rb") as fh:
        header = fh.read(24)
        if len(header) < 24:
            raise PcapError("file too short to be a pcap capture")
        magic = struct.unpack("<I", header[:4])[0]
        if magic in (MAGIC_USEC, MAGIC_NSEC):
            glob, rec, divisor = _GLOBAL, _REC, (1e9 if magic == MAGIC_NSEC else 1e6)
        elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
            glob, rec, divisor = _GLOBAL_BE, _REC_BE, (1e9 if magic == 0x4D3CB2A1 else 1e6)
        elif magic == 0x0A0D0D0A:
            raise PcapError("this is a pcapng file; export it as classic pcap (tcpdump/editcap -F pcap)")
        else:
            raise PcapError(f"not a pcap file (bad magic {magic:#010x})")
        _, _, _, _, _, _, linktype = glob.unpack(header)
        count = 0
        while True:
            rh = fh.read(16)
            if len(rh) < 16:
                break
            ts_sec, ts_sub, incl, orig = rec.unpack(rh)
            data = fh.read(incl)
            if len(data) < incl:
                break  # truncated final record
            yield Frame(ts_sec + ts_sub / divisor, data, orig, linktype)
            count += 1
            if limit and count >= limit:
                break
