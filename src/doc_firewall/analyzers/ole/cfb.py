"""Zero-dependency reader for the OLE2 / Compound File Binary (CFB) format.

doc-firewall is an air-gapped scanner, so its legacy-Office (.doc/.xls/.ppt)
and VBA-macro detection must not silently go dark just because the optional
`olefile` package is not installed.  This module implements the small read-only
subset of the MS-CFB format the scanner needs, in pure stdlib:

    cf = CompoundFile.open(path_or_bytes)
    for path in cf.listdir(streams=True, storages=False):  # [['Macros','VBA','Module1'], ...]
        with cf.openstream(path) as s:
            data = s.read(65536)
    cf.close()

It is intentionally a drop-in for the handful of `olefile.OleFileIO` calls the
scanner makes (`listdir`, `openstream`, `getproperties`, `close`).  It is
read-only, bounds every allocation, never follows a sector chain in a cycle,
and — like the rest of the OLE analyzer — never raises on malformed input
(``open`` returns ``None`` instead).

Reference: [MS-CFB] Compound File Binary File Format.
"""
from __future__ import annotations

import io
import struct
from typing import List, Optional, Union

_CFB_SIGNATURE = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"

# Special FAT sector-chain sentinels.
_FREESECT = 0xFFFFFFFF
_ENDOFCHAIN = 0xFFFFFFFE
_FATSECT = 0xFFFFFFFD
_DIFSECT = 0xFFFFFFFC
_MAXREGSECT = 0xFFFFFFFA
_NOSTREAM = 0xFFFFFFFF

# Directory-entry object types.
_OBJ_STORAGE = 1
_OBJ_STREAM = 2
_OBJ_ROOT = 5

# Safety bounds — a malformed/hostile file must never exhaust memory or hang.
_MAX_SECTORS = 1_000_000        # cap total sectors walked across all chains
_MAX_DIR_ENTRIES = 100_000      # cap directory entries parsed
_MAX_STREAM_BYTES = 16 * 1024 * 1024   # cap bytes materialized per stream


class _DirEntry:
    __slots__ = ("name", "obj_type", "left", "right", "child",
                 "start_sector", "size")

    def __init__(self, name, obj_type, left, right, child, start_sector, size):
        self.name = name
        self.obj_type = obj_type
        self.left = left
        self.right = right
        self.child = child
        self.start_sector = start_sector
        self.size = size


class CompoundFile:
    """Minimal read-only OLE2/CFB container."""

    def __init__(self, data: bytes):
        self._data = data
        self._entries: List[_DirEntry] = []
        self._stream_paths: List[List[str]] = []
        self._storage_paths: List[List[str]] = []
        self._entry_by_path: dict[tuple, _DirEntry] = {}
        self._mini_stream: bytes = b""
        self._parse()

    # ---- construction -----------------------------------------------------

    @classmethod
    def open(cls, src: Union[str, bytes, io.BytesIO]) -> Optional["CompoundFile"]:
        """Open *src* (path, bytes, or BytesIO). Returns None if not a CFB
        file or on any parse error — never raises."""
        try:
            if isinstance(src, (bytes, bytearray)):
                data = bytes(src)
            elif isinstance(src, io.BytesIO):
                data = src.getvalue()
            else:
                with open(src, "rb") as fh:
                    data = fh.read()
            if not data.startswith(_CFB_SIGNATURE):
                return None
            return cls(data)
        except Exception:
            return None

    @staticmethod
    def is_cfb(data: bytes) -> bool:
        return data[:8] == _CFB_SIGNATURE

    # ---- header / FAT parsing --------------------------------------------

    def _parse(self) -> None:
        data = self._data
        if len(data) < 512:
            raise ValueError("truncated CFB header")

        # Header fields (little-endian).
        sector_shift = struct.unpack_from("<H", data, 30)[0]
        mini_shift = struct.unpack_from("<H", data, 32)[0]
        self._sector_size = 1 << sector_shift          # v3=512, v4=4096
        self._mini_sector_size = 1 << mini_shift       # usually 64
        num_fat_sectors = struct.unpack_from("<I", data, 44)[0]
        first_dir_sector = struct.unpack_from("<I", data, 48)[0]
        self._mini_cutoff = struct.unpack_from("<I", data, 56)[0] or 4096
        first_minifat_sector = struct.unpack_from("<I", data, 60)[0]
        num_minifat_sectors = struct.unpack_from("<I", data, 64)[0]
        first_difat_sector = struct.unpack_from("<I", data, 68)[0]
        num_difat_sectors = struct.unpack_from("<I", data, 72)[0]

        if self._sector_size <= 0 or self._sector_size > 1 << 20:
            raise ValueError("implausible sector size")

        # DIFAT: first 109 FAT-sector locations live in the header (offset 76),
        # the rest are chained through dedicated DIFAT sectors.
        difat: List[int] = list(struct.unpack_from("<109I", data, 76))
        sector = first_difat_sector
        guard = 0
        while sector not in (_ENDOFCHAIN, _FREESECT) and sector <= _MAXREGSECT:
            if guard > num_difat_sectors + 16 or guard > _MAX_SECTORS:
                break
            guard += 1
            raw = self._read_sector(sector)
            if not raw:
                break
            ints = struct.unpack_from("<%dI" % (len(raw) // 4), raw, 0)
            difat.extend(ints[:-1])      # last int is the next-DIFAT pointer
            sector = ints[-1]

        # Build the FAT from the FAT sectors named in the DIFAT.
        fat: List[int] = []
        for fsec in difat[: num_fat_sectors + 1] if num_fat_sectors else difat:
            if fsec == _FREESECT or fsec > _MAXREGSECT:
                continue
            raw = self._read_sector(fsec)
            if not raw:
                continue
            fat.extend(struct.unpack_from("<%dI" % (len(raw) // 4), raw, 0))
            if len(fat) > _MAX_SECTORS:
                break
        self._fat = fat

        # MiniFAT chain.
        minifat: List[int] = []
        sector = first_minifat_sector
        guard = 0
        while sector not in (_ENDOFCHAIN, _FREESECT) and sector <= _MAXREGSECT:
            if guard > num_minifat_sectors + 16 or guard > _MAX_SECTORS:
                break
            guard += 1
            raw = self._read_sector(sector)
            if not raw:
                break
            minifat.extend(struct.unpack_from("<%dI" % (len(raw) // 4), raw, 0))
            sector = self._next(sector)
        self._minifat = minifat

        # Directory entries (a FAT chain starting at first_dir_sector).
        dir_bytes = self._read_chain(first_dir_sector)
        self._parse_directory(dir_bytes)

        # The mini stream is the root entry's data (read via the regular FAT).
        if self._entries:
            root = self._entries[0]
            if root.obj_type == _OBJ_ROOT and root.start_sector <= _MAXREGSECT:
                self._mini_stream = self._read_chain(
                    root.start_sector, max_bytes=_MAX_STREAM_BYTES
                )[: root.size]

        self._build_tree()

    # ---- low-level sector reads ------------------------------------------

    def _read_sector(self, sector_id: int) -> bytes:
        # Sector N begins at file offset (N + 1) * sector_size (the 512-byte
        # header occupies "sector -1"; for v4 the header is padded to sector_size).
        if sector_id > _MAXREGSECT:
            return b""
        start = (sector_id + 1) * self._sector_size
        return self._data[start : start + self._sector_size]

    def _next(self, sector_id: int) -> int:
        if 0 <= sector_id < len(self._fat):
            return self._fat[sector_id]
        return _ENDOFCHAIN

    def _read_chain(self, start_sector: int, max_bytes: int = _MAX_STREAM_BYTES) -> bytes:
        """Follow a regular-FAT sector chain and return the concatenated bytes."""
        out = bytearray()
        sector = start_sector
        seen: set[int] = set()
        while sector not in (_ENDOFCHAIN, _FREESECT) and sector <= _MAXREGSECT:
            if sector in seen or len(seen) > _MAX_SECTORS:
                break                       # cycle / runaway guard
            seen.add(sector)
            out.extend(self._read_sector(sector))
            if len(out) >= max_bytes:
                return bytes(out[:max_bytes])
            sector = self._next(sector)
        return bytes(out)

    def _read_mini_chain(self, start_sector: int, size: int) -> bytes:
        """Follow a mini-FAT chain through the mini stream."""
        out = bytearray()
        sector = start_sector
        seen: set[int] = set()
        msz = self._mini_sector_size
        while sector not in (_ENDOFCHAIN, _FREESECT) and sector <= _MAXREGSECT:
            if sector in seen or len(seen) > _MAX_SECTORS:
                break
            seen.add(sector)
            off = sector * msz
            out.extend(self._mini_stream[off : off + msz])
            if len(out) >= size or len(out) >= _MAX_STREAM_BYTES:
                break
            if 0 <= sector < len(self._minifat):
                sector = self._minifat[sector]
            else:
                break
        return bytes(out[:size])

    # ---- directory -------------------------------------------------------

    def _parse_directory(self, dir_bytes: bytes) -> None:
        count = min(len(dir_bytes) // 128, _MAX_DIR_ENTRIES)
        for i in range(count):
            off = i * 128
            name_len = struct.unpack_from("<H", dir_bytes, off + 64)[0]
            obj_type = dir_bytes[off + 66]
            if obj_type not in (_OBJ_STORAGE, _OBJ_STREAM, _OBJ_ROOT):
                self._entries.append(_DirEntry("", 0, _NOSTREAM, _NOSTREAM,
                                               _NOSTREAM, _FREESECT, 0))
                continue
            # Name is UTF-16LE, name_len counts bytes including the NUL terminator.
            nb = max(0, min(name_len, 64) - 2)
            name = dir_bytes[off : off + nb].decode("utf-16-le", errors="replace")
            left = struct.unpack_from("<I", dir_bytes, off + 68)[0]
            right = struct.unpack_from("<I", dir_bytes, off + 72)[0]
            child = struct.unpack_from("<I", dir_bytes, off + 76)[0]
            start = struct.unpack_from("<I", dir_bytes, off + 116)[0]
            size = struct.unpack_from("<Q", dir_bytes, off + 120)[0]
            self._entries.append(
                _DirEntry(name, obj_type, left, right, child, start, size)
            )

    def _build_tree(self) -> None:
        """Walk the red-black directory tree into flat path lists."""
        if not self._entries:
            return
        root = self._entries[0]
        n = len(self._entries)

        def walk(entry_id: int, prefix: List[str], depth: int) -> None:
            if entry_id == _NOSTREAM or entry_id >= n or depth > 64:
                return
            e = self._entries[entry_id]
            walk(e.left, prefix, depth + 1)
            if e.obj_type == _OBJ_STREAM:
                path = prefix + [e.name]
                self._stream_paths.append(path)
                self._entry_by_path[tuple(path)] = e
            elif e.obj_type == _OBJ_STORAGE:
                path = prefix + [e.name]
                self._storage_paths.append(path)
                self._entry_by_path[tuple(path)] = e
                walk(e.child, path, depth + 1)
            walk(e.right, prefix, depth + 1)

        walk(root.child, [], 0)

    # ---- public olefile-compatible API -----------------------------------

    def listdir(self, streams: bool = True, storages: bool = False) -> List[List[str]]:
        out: List[List[str]] = []
        if streams:
            out.extend([list(p) for p in self._stream_paths])
        if storages:
            out.extend([list(p) for p in self._storage_paths])
        return out

    def openstream(self, path) -> io.BytesIO:
        """Return a BytesIO over the named stream (olefile-compatible)."""
        if isinstance(path, str):
            key = (path,)
        else:
            key = tuple(path)
        entry = self._entry_by_path.get(key)
        if entry is None or entry.obj_type != _OBJ_STREAM:
            raise OSError("stream not found: %r" % (path,))
        size = min(entry.size, _MAX_STREAM_BYTES)
        if entry.size < self._mini_cutoff:
            data = self._read_mini_chain(entry.start_sector, size)
        else:
            data = self._read_chain(entry.start_sector, max_bytes=size)[:size]
        return io.BytesIO(data)

    def getproperties(self, *_args, **_kwargs) -> dict:
        # Property-set parsing is not implemented; metadata enrichment in the
        # OLE parser treats this as best-effort and tolerates an empty result.
        return {}

    def exists(self, path) -> bool:
        key = (path,) if isinstance(path, str) else tuple(path)
        return key in self._entry_by_path

    def close(self) -> None:
        self._data = b""
        self._mini_stream = b""


__all__ = ["CompoundFile"]
