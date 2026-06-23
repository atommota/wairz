"""Unit tests for the firmware unpack pipeline (workers/unpack.py)."""
from __future__ import annotations

import os
from pathlib import Path

import struct

from app.workers.unpack import (
    _count_fs_markers,
    _has_linux_markers,
    detect_architecture,
    detect_architecture_from_uboot,
    find_filesystem_root,
)


def _elf32(machine: int, little: bool = True, etype: int = 3) -> bytes:
    """Build a minimal but parseable 52-byte ELF32 header.

    Only the header fields matter to ``_classify_elf`` (e_machine + EI_DATA);
    e_phoff/e_shoff are zeroed so pyelftools never tries to parse absent
    program/section tables.
    """
    ei_data = 1 if little else 2  # ELFDATA2LSB / ELFDATA2MSB
    e_ident = b"\x7fELF" + bytes([1, ei_data, 1, 0]) + b"\x00" * 8
    endian = "<" if little else ">"
    rest = struct.pack(
        endian + "HHIIIIIHHHHHH",
        etype,      # e_type
        machine,    # e_machine
        1,          # e_version
        0,          # e_entry
        0,          # e_phoff
        0,          # e_shoff
        0,          # e_flags
        52,         # e_ehsize
        0, 0, 0, 0, 0,  # ph/sh entsize/num, shstrndx
    )
    return e_ident + rest


def _uimage_header(arch_code: int) -> bytes:
    """Build a 64-byte U-Boot uImage header with the given ih_arch code."""
    return struct.pack(
        ">IIIIIIIBBBB",
        0x27051956,  # ih_magic
        0,           # ih_hcrc
        0,           # ih_time
        0,           # ih_size
        0,           # ih_load
        0,           # ih_ep
        0,           # ih_dcrc
        5,           # ih_os = Linux
        arch_code,   # ih_arch
        2,           # ih_type = Kernel
        0,           # ih_comp
    ) + b"Linux-test\x00" + b"\x00" * 21


# ARM = 40 (0x28) in ELF e_machine; ARM = 2 in U-Boot ih_arch.
_EM_ARM = 40
_EM_MIPS = 8


def _make_dirs(base: Path, layout: dict) -> None:
    """Create a directory tree from a nested dict.

    Values that are dicts become directories with recursive contents; other
    values become empty files.
    """
    for name, contents in layout.items():
        path = base / name
        if isinstance(contents, dict):
            path.mkdir(parents=True, exist_ok=True)
            _make_dirs(path, contents)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"" if contents is None else contents)


class TestCountMarkers:
    def test_counts_standard_layout(self, tmp_path: Path):
        _make_dirs(tmp_path, {
            "bin": {}, "sbin": {}, "etc": {}, "lib": {}, "usr": {},
        })
        assert _count_fs_markers(str(tmp_path)) == 5

    def test_zero_for_empty(self, tmp_path: Path):
        assert _count_fs_markers(str(tmp_path)) == 0

    def test_zero_for_nonexistent(self, tmp_path: Path):
        assert _count_fs_markers(str(tmp_path / "missing")) == 0

    def test_recognises_embedded_init_dir(self, tmp_path: Path):
        # Wyze cameras use /init/ instead of /etc/.
        _make_dirs(tmp_path, {"bin": {}, "init": {}, "ko": {}, "lib": {}})
        assert _count_fs_markers(str(tmp_path)) == 4


class TestHasLinuxMarkers:
    def test_two_markers_qualifies(self, tmp_path: Path):
        _make_dirs(tmp_path, {"bin": {}, "lib": {}})
        assert _has_linux_markers(str(tmp_path))

    def test_one_marker_does_not_qualify(self, tmp_path: Path):
        _make_dirs(tmp_path, {"bin": {}})
        assert not _has_linux_markers(str(tmp_path))


class TestFindFilesystemRoot:
    def test_picks_named_root_over_deep_match(self, tmp_path: Path):
        # Regression: the Wyze Battery Cam Solar firmware has no /etc/, so the
        # old "etc + (usr|bin)" heuristic missed the actual rootfs and the
        # "largest dir" fallback picked bin/busybox/bin/ (~50 busybox symlinks)
        # instead. Verify we now pick the squashfs-root regardless.
        _make_dirs(tmp_path, {
            "_fw.bin.extracted": {
                "squashfs-root": {
                    "bin": {
                        "busybox": {
                            # 50 fake busybox symlinks
                            "bin": {f"sym{i}": None for i in range(50)},
                            "sbin": {f"s{i}": None for i in range(20)},
                        },
                        "dnsmasq": None,
                        "ppsapp": None,
                    },
                    "init": {"initrun.sh": None},
                    "ko": {"foo.ko": None},
                    "lib": {},
                },
                # Sibling: same squashfs re-extracted by binwalk -Me
                "raw.squashfs.extracted": {
                    "bin": {"busybox": {"bin": {f"sym{i}": None for i in range(50)}}},
                    "init": {}, "ko": {}, "lib": {},
                },
            },
        })

        result = find_filesystem_root(str(tmp_path))
        assert result is not None
        assert os.path.basename(result) == "squashfs-root"

    def test_picks_shallowest_marker_dir_when_no_named_root(self, tmp_path: Path):
        # If there's no *-root dir, pick the shallowest dir with enough markers,
        # not a deeply-nested one.
        _make_dirs(tmp_path, {
            "rootfs": {
                "bin": {}, "sbin": {}, "etc": {}, "lib": {},
                "usr": {
                    "bin": {"foo": None, "bar": None},
                    "lib": {"baz": None},
                },
            },
        })
        result = find_filesystem_root(str(tmp_path))
        assert result is not None
        assert os.path.basename(result) == "rootfs"

    def test_prefers_unnumbered_named_root(self, tmp_path: Path):
        # If both squashfs-root and squashfs-root-0 exist, the shallowest one
        # wins on depth tie-break; in practice they're at the same depth so
        # we tie-break on marker count then path order.
        _make_dirs(tmp_path, {
            "squashfs-root": {"bin": {}, "etc": {}, "lib": {}, "var": {}},
            "squashfs-root-0": {"bin": {}, "etc": {}},
        })
        result = find_filesystem_root(str(tmp_path))
        assert result is not None
        # squashfs-root has more markers, so it wins on the tie-break
        assert os.path.basename(result) == "squashfs-root"

    def test_returns_none_when_no_qualifying_dir(self, tmp_path: Path):
        # No fallback to "biggest directory" — we'd rather fail explicitly
        # than mount the wrong directory.
        _make_dirs(tmp_path, {
            "junk": {f"file{i}": None for i in range(100)},
            "more_junk": {f"x{i}": None for i in range(50)},
        })
        assert find_filesystem_root(str(tmp_path)) is None

    def test_does_not_descend_into_named_root(self, tmp_path: Path):
        # An ext-root nested inside a squashfs-root should not be picked over
        # the outer squashfs-root.
        _make_dirs(tmp_path, {
            "squashfs-root": {
                "bin": {}, "etc": {}, "lib": {}, "var": {},
                # Some weird vendor that ships an ext image inside its rootfs.
                "tmp": {"ext-root": {"bin": {}, "etc": {}, "lib": {}}},
            },
        })
        result = find_filesystem_root(str(tmp_path))
        assert result is not None
        assert os.path.basename(result) == "squashfs-root"


class TestDetectArchitecture:
    def test_detects_arm_from_conventional_dirs(self, tmp_path: Path):
        _make_dirs(tmp_path, {"bin": {"busybox": _elf32(_EM_ARM)}})
        assert detect_architecture(str(tmp_path)) == ("arm", "little")

    def test_falls_back_to_top_level_elfs(self, tmp_path: Path):
        # Wyze /app-style partition: empty bin/ and lib/, executables at the
        # top level. Pass 1 finds nothing; the tree-walk fallback must catch
        # the top-level ELFs.
        _make_dirs(tmp_path, {
            "bin": {},
            "lib": {},
            "chime_app": _elf32(_EM_ARM),
            "hostapd": _elf32(_EM_ARM),
            "setup.sh": b"#!/bin/sh\n",
        })
        assert detect_architecture(str(tmp_path)) == ("arm", "little")

    def test_mipsel_split(self, tmp_path: Path):
        _make_dirs(tmp_path, {"bin": {"busybox": _elf32(_EM_MIPS, little=True)}})
        assert detect_architecture(str(tmp_path)) == ("mipsel", "little")

    def test_big_endian_mips(self, tmp_path: Path):
        _make_dirs(tmp_path, {"bin": {"busybox": _elf32(_EM_MIPS, little=False)}})
        assert detect_architecture(str(tmp_path)) == ("mips", "big")

    def test_majority_vote_wins(self, tmp_path: Path):
        _make_dirs(tmp_path, {"bin": {
            "a": _elf32(_EM_ARM), "b": _elf32(_EM_ARM),
            "c": _elf32(_EM_MIPS, little=False),
        }})
        assert detect_architecture(str(tmp_path)) == ("arm", "little")

    def test_returns_none_without_elfs(self, tmp_path: Path):
        _make_dirs(tmp_path, {"bin": {"script.sh": b"#!/bin/sh\n"}})
        assert detect_architecture(str(tmp_path)) == (None, None)

    def test_ignores_symlinks(self, tmp_path: Path):
        # A dangling/cyclic symlink must not crash the walk.
        _make_dirs(tmp_path, {"app": _elf32(_EM_ARM)})
        os.symlink(tmp_path / "missing", tmp_path / "broken")
        assert detect_architecture(str(tmp_path)) == ("arm", "little")


class TestDetectArchitectureFromUboot:
    def test_arm_uimage(self, tmp_path: Path):
        blob = tmp_path / "fw.bin"
        blob.write_bytes(_uimage_header(2))  # ih_arch 2 = ARM
        assert detect_architecture_from_uboot(str(blob)) == ("arm", "little")

    def test_mips_uimage(self, tmp_path: Path):
        blob = tmp_path / "fw.bin"
        blob.write_bytes(_uimage_header(5))  # ih_arch 5 = MIPS
        assert detect_architecture_from_uboot(str(blob)) == ("mips", "big")

    def test_magic_not_at_offset_zero(self, tmp_path: Path):
        blob = tmp_path / "fw.bin"
        blob.write_bytes(b"\x00" * 4096 + _uimage_header(2))
        assert detect_architecture_from_uboot(str(blob)) == ("arm", "little")

    def test_no_uimage_returns_none(self, tmp_path: Path):
        blob = tmp_path / "fw.bin"
        blob.write_bytes(b"not a uimage at all" * 100)
        assert detect_architecture_from_uboot(str(blob)) == (None, None)
