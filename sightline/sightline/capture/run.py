"""Drive live capture and pcap analysis, producing a ScanResult."""

from __future__ import annotations

import secrets
from datetime import datetime
from pathlib import Path
from typing import Callable

from sightline.capture import decode as dec
from sightline.capture.analyze import Analyzer
from sightline.capture.pcap import open_writer, read_frames
from sightline.capture.sniffer import CaptureError, CaptureFilter, LiveCapture  # noqa: F401 (re-exported)
from sightline.models import ScanResult
from sightline.risk import prioritize
from sightline.targets import is_public

Progress = Callable[[str], None]


def _scan_id() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(2)


def _finalize(analyzer: Analyzer, name: str, source: str) -> ScanResult:
    result = analyzer.build_result(_scan_id(), name, source)
    public_hosts = {h.address for h in result.hosts if is_public(h.address)}
    result.findings = prioritize(result.findings, public_hosts)
    return result


def run_live(
    interface: str,
    *,
    count: int = 0,
    seconds: float = 0.0,
    snaplen: int = 65535,
    filter_spec: str | None = None,
    write_pcap: str | None = None,
    promiscuous: bool = False,
    name: str = "",
    progress: Progress | None = None,
) -> ScanResult:
    progress = progress or (lambda _m: None)
    cap = LiveCapture(
        interface=interface, count=count, seconds=seconds, snaplen=snaplen,
        cfilter=CaptureFilter.parse(filter_spec), promiscuous=promiscuous,
    )  # fmt: skip
    analyzer = Analyzer()
    writer = None
    limit_desc = []
    if count:
        limit_desc.append(f"{count} packets")
    if seconds:
        limit_desc.append(f"{seconds:g}s")
    progress(
        f"Capturing on {cap.interface}"
        + (f" (filter: {filter_spec})" if filter_spec else "")
        + (f", stop after {' or '.join(limit_desc)}" if limit_desc else " (Ctrl+C to stop)")
    )
    last_report = 0
    try:
        for ts, raw, orig in cap.frames():
            if write_pcap and writer is None:
                writer = open_writer(write_pcap, linktype=cap.linktype, snaplen=snaplen)
            if writer:
                writer.write(ts, raw, orig)
            pkt = dec.decode(raw, ts, orig, cap.linktype)
            if cap.cfilter.matches(pkt):
                analyzer.feed(pkt)
                for f in analyzer.findings[last_report:]:
                    progress(f"  [!] {f.severity.upper()}: {f.title} ({f.host})")
                last_report = len(analyzer.findings)
            if cap.stats.frames % 500 == 0 and cap.stats.frames:
                progress(f"  ... {cap.stats.frames} frames, {len(analyzer.hosts)} hosts, {len(analyzer.findings)} findings")
    except KeyboardInterrupt:
        progress("  stopping (interrupt)")
    finally:
        if writer:
            writer.close()
            progress(f"  wrote capture to {write_pcap}")
    source = f"live:{cap.interface}"
    progress(f"Captured {cap.stats.frames} frames in {analyzer.duration():.1f}s")
    return _finalize(analyzer, name or f"Capture on {cap.interface}", source)


def run_pcap(path: str, *, filter_spec: str | None = None, name: str = "", progress: Progress | None = None) -> ScanResult:
    progress = progress or (lambda _m: None)
    cfilter = CaptureFilter.parse(filter_spec)
    analyzer = Analyzer()
    progress(f"Reading {path}")
    frames = 0
    for frame in read_frames(path):
        frames += 1
        pkt = dec.decode(frame.data, frame.ts, frame.orig_len, frame.linktype)
        if cfilter.matches(pkt):
            analyzer.feed(pkt)
    progress(f"Analysed {frames} frames, {len(analyzer.hosts)} hosts, {len(analyzer.findings)} findings")
    return _finalize(analyzer, name or f"Capture {Path(path).name}", f"pcap:{Path(path).name}")


__all__ = ["run_live", "run_pcap", "CaptureError"]

