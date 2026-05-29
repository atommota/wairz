"""Ghidra-based binary analysis service with full-binary caching.

Runs Ghidra once per binary via AnalyzeBinary.java to extract all data
(functions, imports, exports, xrefs, disassembly, decompilation, binary_info),
stores everything in PostgreSQL analysis_cache, and serves subsequent queries
instantly from the DB.

Falls back to DecompileFunction.java for single-function decompilation requests
on functions not covered in the initial batch (top 200 by size).
"""

import asyncio
import contextlib
import fcntl
import hashlib
import json
import logging
import os
import shutil
import tempfile
import time
import uuid
from functools import lru_cache
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import async_session_factory
from app.models.analysis_cache import AnalysisCache

logger = logging.getLogger(__name__)

# Markers used by both AnalyzeBinary.java and DecompileFunction.java
_START_MARKER = "===ANALYSIS_START==="
_END_MARKER = "===ANALYSIS_END==="
_DECOMPILE_START = "===DECOMPILE_START==="
_DECOMPILE_END = "===DECOMPILE_END==="

# Architecture mapping: Ghidra processor names → common short names
_ARCH_MAP = {
    "ARM": "arm",
    "AARCH64": "aarch64",
    "MIPS": "mips",
    "x86": "x86",
    "x86-64": "x86",
    "PowerPC": "ppc",
    "sparc": "sparc",
}


_ANALYSIS_LOCK_DIR = Path(tempfile.gettempdir()) / "wairz-analysis-locks"


def _acquire_analysis_flock(lock_path: str) -> int:
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _release_analysis_flock(fd: int) -> None:
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


@contextlib.asynccontextmanager
async def _cross_process_analysis_lock(binary_sha256: str):
    """Host-wide exclusive lock keyed by binary sha256.

    The class-level asyncio.Event guard only dedupes coroutines within a
    single Python process. Each MCP client connection spawns its own
    wairz-mcp process, so concurrent connections can otherwise each
    decide "no cache yet, I'll run Ghidra" and spawn duplicate analyses
    against the same binary — observed in the wild as 7 parallel
    Ghidras on a 7 MB binary, none finishing. fcntl.flock serializes
    them at the OS level and is released automatically if a process
    crashes, so failed analyses don't leave the binary blocked.
    """
    _ANALYSIS_LOCK_DIR.mkdir(parents=True, exist_ok=True)
    lock_path = str(_ANALYSIS_LOCK_DIR / f"{binary_sha256}.lock")
    fd = await asyncio.to_thread(_acquire_analysis_flock, lock_path)
    try:
        yield
    finally:
        await asyncio.to_thread(_release_analysis_flock, fd)


def _compute_sha256(file_path: str) -> str:
    """Compute SHA256 hash of a file."""
    sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha.update(chunk)
    return sha.hexdigest()


def _map_architecture(ghidra_arch: str) -> str:
    """Map Ghidra architecture string to common short name."""
    for key, val in _ARCH_MAP.items():
        if key.lower() in ghidra_arch.lower():
            return val
    return ghidra_arch.lower()


def _parse_analysis_output(raw_output: str) -> dict | None:
    """Extract JSON from Ghidra AnalyzeBinary.java output between markers.

    Ghidra wraps println() output with log prefixes like:
      INFO  AnalyzeBinary.java> {json...} (GhidraScript)
    So we extract the outermost { ... } between the markers.
    """
    start = raw_output.find(_START_MARKER)
    end = raw_output.find(_END_MARKER)

    if start == -1 or end == -1:
        return None

    content = raw_output[start + len(_START_MARKER):end].strip()
    if not content:
        return None

    # Find the outermost JSON object braces within the content
    json_start = content.find("{")
    json_end = content.rfind("}")
    if json_start == -1 or json_end == -1 or json_end <= json_start:
        logger.error("No JSON object found between analysis markers")
        return None

    json_str = content[json_start:json_end + 1]

    try:
        return json.loads(json_str)
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse Ghidra analysis JSON: %s", exc)
        return None


def _parse_decompile_output(raw_output: str) -> str | None:
    """Extract decompiled code from DecompileFunction.java output between markers."""
    start = raw_output.find(_DECOMPILE_START)
    end = raw_output.find(_DECOMPILE_END)

    if start == -1 or end == -1:
        return None

    content = raw_output[start + len(_DECOMPILE_START):end].strip()
    return content if content else None


# Name of the single Ghidra project created per binary. The program inside is
# named after the imported file's basename, but every reuse run uses bare
# "-process" (which targets all programs in the project, of which there is
# exactly one), so the program name never has to be threaded through.
_PROJECT_NAME = "wairz"
_ANALYZED_MARKER = ".wairz_analyzed"


@lru_cache(maxsize=1)
def _ghidra_version() -> str:
    """Installed Ghidra version, read from application.properties.

    Used to namespace the persistent project store so a Ghidra upgrade never
    tries to open a project written by an older (incompatible) version.
    """
    props = os.path.join(
        get_settings().ghidra_path, "Ghidra", "application.properties",
    )
    try:
        with open(props, encoding="utf-8") as f:
            for line in f:
                if line.startswith("application.version="):
                    return line.split("=", 1)[1].strip() or "unknown"
    except OSError:
        pass
    return "unknown"


def _project_dir(binary_sha256: str) -> str:
    """Persistent Ghidra project directory for a binary, keyed by content hash.

    Layout: <GHIDRA_PROJECT_ROOT>/<ghidra_version>/<sha256>/. Keying by sha256
    means a binary shipped in many firmwares (e.g. busybox) is analyzed once
    and reused everywhere, across sessions/agents/users.
    """
    return os.path.join(
        get_settings().ghidra_project_root, _ghidra_version(), binary_sha256,
    )


def _analyze_headless_path() -> str:
    return os.path.join(get_settings().ghidra_path, "support", "analyzeHeadless")


def _build_import_command(
    binary_path: str,
    project_dir: str,
    script_name: str,
    script_args: list[str] | None = None,
) -> list[str]:
    """Import + auto-analyze a binary into a persistent project (one-time).

    Note: NO -deleteProject — the analyzed project is kept on disk for reuse.
    """
    cmd = [
        _analyze_headless_path(),
        project_dir,
        _PROJECT_NAME,
        "-import",
        binary_path,
        "-scriptPath",
        get_settings().ghidra_scripts_path,
        "-postScript",
        script_name,
    ]
    if script_args:
        cmd.extend(script_args)
    return cmd


def _build_process_command(
    project_dir: str,
    script_name: str,
    script_args: list[str] | None = None,
) -> list[str]:
    """Run a script against an already-analyzed persistent project (reuse).

    -noanalysis skips re-running auto-analysis (the expensive part — already
    done at import); -readOnly never writes back, so the saved project is
    untouched. Bare -process targets the project's single program.
    """
    cmd = [
        _analyze_headless_path(),
        project_dir,
        _PROJECT_NAME,
        "-process",
        "-noanalysis",
        "-readOnly",
        "-scriptPath",
        get_settings().ghidra_scripts_path,
        "-postScript",
        script_name,
    ]
    if script_args:
        cmd.extend(script_args)
    return cmd


async def _exec_headless(cmd: list[str], effective_timeout: int) -> str:
    """Run an analyzeHeadless command and return raw stdout.

    Captures stdout/stderr to tempfiles rather than asyncio PIPEs.
    AnalyzeBinary.java for a multi-MB binary can emit hundreds of MB of
    println output; with PIPE + communicate(), the kernel 64 KB pipe buffer
    fills before asyncio drains it and Ghidra deadlocks blocked in a
    FileOutputStream.write syscall. Tempfiles let the kernel buffer arbitrary
    output with no possibility of deadlock; we read them once Ghidra exits.
    """
    with tempfile.TemporaryFile(prefix="ghidra-stdout-") as stdout_f, \
         tempfile.TemporaryFile(prefix="ghidra-stderr-") as stderr_f:
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=stdout_f,
                stderr=stderr_f,
            )
        except FileNotFoundError:
            raise RuntimeError(
                f"Ghidra not found at {cmd[0]}. "
                "Install Ghidra or set GHIDRA_PATH in .env."
            )

        try:
            await asyncio.wait_for(process.wait(), timeout=effective_timeout)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            raise TimeoutError(
                f"Ghidra analysis timed out after {effective_timeout}s"
            )

        stdout_f.seek(0)
        stderr_f.seek(0)
        stdout = stdout_f.read()
        stderr = stderr_f.read()

    stdout_text = stdout.decode("utf-8", errors="replace")
    stderr_text = stderr.decode("utf-8", errors="replace")

    if process.returncode != 0:
        # Ghidra often returns non-zero but still produces output.
        known_markers = (
            _START_MARKER, _DECOMPILE_START,
            "===STRING_REFS_START===", "===TAINT_START===",
            "===STACK_LAYOUT_START===", "===GLOBAL_LAYOUT_START===",
        )
        if not any(m in stdout_text for m in known_markers):
            logger.error(
                "Ghidra failed (rc=%d): %s",
                process.returncode,
                stderr_text[-500:],
            )
            raise RuntimeError(
                f"Ghidra analysis failed (exit code {process.returncode})"
            )

    return stdout_text


async def _ensure_project_imported(
    binary_path: str, binary_sha256: str, effective_timeout: int,
) -> str | None:
    """Import + analyze the binary into its persistent project if not already.

    Returns AnalyzeBinary.java's raw output when it performs the import (so the
    caller can reuse it instead of a redundant -process run), or None if the
    project already existed. UNLOCKED — callers must hold
    _cross_process_analysis_lock(binary_sha256) so only one import runs and no
    two headless processes touch the same project concurrently.
    """
    project_dir = _project_dir(binary_sha256)
    marker = os.path.join(project_dir, _ANALYZED_MARKER)

    if os.path.exists(marker):
        return None

    # A project dir without the marker is a crashed/partial import — discard it
    # so the retry starts clean (avoids a stale Ghidra project lock).
    if os.path.isdir(project_dir):
        shutil.rmtree(project_dir, ignore_errors=True)
    os.makedirs(project_dir, exist_ok=True)

    logger.info(
        "Importing + analyzing %s into persistent project %s",
        os.path.basename(binary_path), binary_sha256[:12],
    )
    try:
        raw_output = await _exec_headless(
            _build_import_command(binary_path, project_dir, "AnalyzeBinary.java"),
            effective_timeout,
        )
    except BaseException:
        # Don't leave a half-imported project that future runs would treat as
        # reusable (the marker is only written on success, but the dir itself
        # could confuse a -process run, so clear it).
        shutil.rmtree(project_dir, ignore_errors=True)
        raise

    Path(marker).write_text(f"{binary_sha256}\n", encoding="utf-8")
    # A new project just landed — prune the store back to the cap if needed.
    await _gc_project_store()
    return raw_output


async def _run_process_script(
    binary_sha256: str,
    script_name: str,
    script_args: list[str] | None,
    effective_timeout: int,
) -> str:
    """Run a read-only script against the already-analyzed persistent project.

    UNLOCKED — callers hold _cross_process_analysis_lock(binary_sha256).
    """
    logger.info(
        "Reusing project %s for %s (-process, no re-analysis)",
        binary_sha256[:12], script_name,
    )
    _touch_project(binary_sha256)
    return await _exec_headless(
        _build_process_command(_project_dir(binary_sha256), script_name, script_args),
        effective_timeout,
    )


def _touch_project(binary_sha256: str) -> None:
    """Bump the project's access time so the LRU GC keeps hot projects."""
    marker = os.path.join(_project_dir(binary_sha256), _ANALYZED_MARKER)
    try:
        os.utime(marker, None)
    except OSError:
        pass


def _try_evict_project(sha256: str, project_dir: str) -> bool:
    """Evict a project iff no one holds its per-binary lock (non-blocking).

    Returns True if evicted. Skips projects currently being imported/reused so
    GC never rmtree's files out from under an in-flight Ghidra run.
    """
    lock_path = str(_ANALYSIS_LOCK_DIR / f"{sha256}.lock")
    try:
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o644)
    except OSError:
        return False
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, OSError):
            return False  # in use — leave it
        shutil.rmtree(project_dir, ignore_errors=True)
        fcntl.flock(fd, fcntl.LOCK_UN)
        return True
    finally:
        os.close(fd)


def _gc_project_store_sync() -> None:
    """Evict least-recently-used projects once the store exceeds the cap.

    'Recently used' = marker mtime, bumped on every import and reuse
    (_touch_project). Only fully-analyzed projects (marker present) are counted
    and evicted. Evictions are logged — never silent.
    """
    settings = get_settings()
    cap = settings.ghidra_project_cache_max
    if cap <= 0:
        return
    # Eviction takes the per-binary flock under this dir; ensure it exists even
    # when GC runs before any lock has been acquired this process.
    _ANALYSIS_LOCK_DIR.mkdir(parents=True, exist_ok=True)
    version_root = os.path.join(settings.ghidra_project_root, _ghidra_version())
    try:
        names = os.listdir(version_root)
    except OSError:
        return

    projects = []
    for name in names:
        d = os.path.join(version_root, name)
        marker = os.path.join(d, _ANALYZED_MARKER)
        try:
            if os.path.isdir(d) and os.path.exists(marker):
                projects.append((os.path.getmtime(marker), d, name))
        except OSError:
            continue

    if len(projects) <= cap:
        return

    projects.sort(key=lambda p: p[0])  # oldest access first
    evicted = 0
    for _, d, name in projects[: len(projects) - cap]:
        if _try_evict_project(name, d):
            evicted += 1
            logger.info(
                "GC: evicted LRU Ghidra project %s (store cap=%d)", name[:12], cap,
            )
    if evicted:
        logger.info(
            "GC: evicted %d project(s); store now ~%d (cap=%d)",
            evicted, len(projects) - evicted, cap,
        )


async def _gc_project_store() -> None:
    """Run the project-store GC off the event loop; never raises."""
    try:
        await asyncio.to_thread(_gc_project_store_sync)
    except Exception:
        logger.warning("Project-store GC failed (non-fatal)", exc_info=True)


async def run_ghidra_subprocess(
    binary_path: str,
    script_name: str,
    script_args: list[str] | None = None,
    timeout: int | None = None,
    binary_sha256: str | None = None,
) -> str:
    """Run a Ghidra headless script, reusing a persistent per-binary project.

    On first touch the binary is imported + auto-analyzed once into a persistent
    project; the script then runs against that project. Every subsequent call
    reuses the project via -process -readOnly -noanalysis (no re-import, no
    re-analysis) — turning minutes into seconds and sharing the work across
    sessions, agents, and users.

    timeout: optional override (seconds). Defaults to settings.ghidra_timeout,
    appropriate for synchronous MCP-bounded calls. Background workers pass a
    much larger value. The whole operation (import-if-needed + script) is bound
    by this single timeout, preserving the prior synchronous-call semantics.

    binary_sha256: pass it if already computed, to skip a re-hash.
    """
    effective_timeout = timeout if timeout is not None else get_settings().ghidra_timeout
    if binary_sha256 is None:
        binary_sha256 = await asyncio.to_thread(_compute_sha256, binary_path)

    # Serialize all headless access to this binary's project (import or reuse)
    # at the OS level: a local Ghidra project allows only one headless process
    # at a time, and this also dedupes concurrent first-touch imports.
    async with _cross_process_analysis_lock(binary_sha256):
        imported = await _ensure_project_imported(
            binary_path, binary_sha256, effective_timeout,
        )
        if script_name == "AnalyzeBinary.java" and imported is not None:
            # We just analyzed; reuse that output instead of a redundant pass.
            return imported
        return await _run_process_script(
            binary_sha256, script_name, script_args, effective_timeout,
        )


class GhidraAnalysisCache:
    """Cache for full-binary Ghidra analysis results.

    Runs Ghidra once per binary via AnalyzeBinary.java, stores all extracted
    data in the analysis_cache table, and serves subsequent queries from DB.

    Includes a concurrency guard: if two requests hit the same binary
    simultaneously, only one runs Ghidra and the other waits.
    """

    def __init__(self) -> None:
        # Concurrency guard: binary_sha256 → asyncio.Event
        self._analysis_locks: dict[str, asyncio.Event] = {}
        self._lock = asyncio.Lock()

    async def _get_binary_sha256(self, binary_path: str) -> str:
        """Compute SHA256 in a thread."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _compute_sha256, binary_path)

    async def get_binary_sha256(self, binary_path: str) -> str:
        """Public wrapper: compute SHA256 in a thread."""
        return await self._get_binary_sha256(binary_path)

    async def _is_analysis_complete(
        self,
        firmware_id: uuid.UUID,
        binary_sha256: str,
        db: AsyncSession,
    ) -> bool:
        """Check if full analysis has been completed for this binary."""
        stmt = select(AnalysisCache.id).where(
            AnalysisCache.firmware_id == firmware_id,
            AnalysisCache.binary_sha256 == binary_sha256,
            AnalysisCache.operation == "ghidra_full_analysis",
        )
        result = await db.execute(stmt)
        return result.scalar_one_or_none() is not None

    async def get_cached(
        self,
        firmware_id: uuid.UUID,
        binary_sha256: str,
        operation: str,
        db: AsyncSession,
    ) -> dict | None:
        """Get a cached result by operation key (public API)."""
        return await self._get_cached(firmware_id, binary_sha256, operation, db)

    async def _get_cached(
        self,
        firmware_id: uuid.UUID,
        binary_sha256: str,
        operation: str,
        db: AsyncSession,
    ) -> dict | None:
        """Get a cached result by operation key."""
        stmt = select(AnalysisCache.result).where(
            AnalysisCache.firmware_id == firmware_id,
            AnalysisCache.binary_sha256 == binary_sha256,
            AnalysisCache.operation == operation,
        )
        result = await db.execute(stmt)
        row = result.scalars().first()
        if row is not None and isinstance(row, dict):
            return row
        return None

    async def store_cached(
        self,
        firmware_id: uuid.UUID,
        binary_path: str,
        binary_sha256: str,
        operation: str,
        result_data: dict,
        db: AsyncSession,
    ) -> None:
        """Store a result in the cache (public API)."""
        await self._store_cached(
            firmware_id, binary_path, binary_sha256, operation, result_data, db,
        )

    async def _store_cached(
        self,
        firmware_id: uuid.UUID,
        binary_path: str,
        binary_sha256: str,
        operation: str,
        result_data: dict,
        db: AsyncSession,
    ) -> None:
        """Store a result in the cache.

        Deletes any existing entries with the same composite key first
        to prevent duplicate rows.
        """
        from sqlalchemy import delete

        await db.execute(
            delete(AnalysisCache).where(
                AnalysisCache.firmware_id == firmware_id,
                AnalysisCache.binary_sha256 == binary_sha256,
                AnalysisCache.operation == operation,
            )
        )
        cache_entry = AnalysisCache(
            firmware_id=firmware_id,
            binary_path=binary_path,
            binary_sha256=binary_sha256,
            operation=operation,
            result=result_data,
        )
        db.add(cache_entry)
        await db.flush()

    async def _run_full_analysis(
        self,
        binary_path: str,
        firmware_id: uuid.UUID,
        binary_sha256: str,
        db: AsyncSession,
        timeout: int | None = None,
    ) -> None:
        """Run AnalyzeBinary.java and store all results in DB.

        timeout: passed through to run_ghidra_subprocess. None means use
        the global ghidra_timeout (suitable for synchronous MCP-bounded
        calls). Background workers pass a much larger value.

        Callers (ensure_analysis, the background worker) already hold
        _cross_process_analysis_lock(binary_sha256), so this uses the UNLOCKED
        project internals directly to avoid re-entering the flock.
        """
        effective_timeout = (
            timeout if timeout is not None else get_settings().ghidra_timeout
        )
        # Import + analyze into the persistent project if needed (returns the
        # AnalyzeBinary output); otherwise re-extract from the saved project.
        imported = await _ensure_project_imported(
            binary_path, binary_sha256, effective_timeout,
        )
        if imported is not None:
            raw_output = imported
        else:
            raw_output = await _run_process_script(
                binary_sha256, "AnalyzeBinary.java", None, effective_timeout,
            )

        data = _parse_analysis_output(raw_output)
        if data is None:
            raise RuntimeError(
                "Ghidra full analysis produced no parseable output. "
                "Check Ghidra installation and binary compatibility."
            )

        # Store each section as a separate cache entry
        sections = [
            ("functions", "functions"),
            ("imports", "imports"),
            ("exports", "exports"),
            ("binary_info", "binary_info"),
            ("xrefs", "xrefs"),
            ("main_detection", "main_detection"),
        ]

        for key, operation in sections:
            if key in data:
                await self._store_cached(
                    firmware_id, binary_path, binary_sha256,
                    operation, {key: data[key]}, db,
                )

        # Store disassembly per function
        disassembly = data.get("disassembly", {})
        for func_name, disasm_text in disassembly.items():
            await self._store_cached(
                firmware_id, binary_path, binary_sha256,
                f"disasm:{func_name}",
                {"disassembly": disasm_text},
                db,
            )

        # Store decompilation per function
        decompilation = data.get("decompilation", {})
        for func_name, code in decompilation.items():
            await self._store_cached(
                firmware_id, binary_path, binary_sha256,
                f"decompile:{func_name}",
                {"decompiled_code": code},
                db,
            )

        # Store sentinel marking analysis as complete
        function_count = len(data.get("functions", []))
        decompile_count = len(decompilation)
        await self._store_cached(
            firmware_id, binary_path, binary_sha256,
            "ghidra_full_analysis",
            {
                "status": "complete",
                "function_count": function_count,
                "decompiled_count": decompile_count,
            },
            db,
        )

        logger.info(
            "Ghidra full analysis complete for %s: %d functions, %d decompiled",
            os.path.basename(binary_path),
            function_count,
            decompile_count,
        )

    async def ensure_analysis(
        self,
        binary_path: str,
        firmware_id: uuid.UUID,
        db: AsyncSession,
    ) -> str:
        """Ensure full analysis has been run for this binary. Returns binary_sha256.

        Uses a concurrency guard so only one Ghidra process runs per binary.
        """
        if not os.path.isfile(binary_path):
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        binary_sha256 = await self._get_binary_sha256(binary_path)

        # Fast path: already analyzed
        if await self._is_analysis_complete(firmware_id, binary_sha256, db):
            return binary_sha256

        # Concurrency guard
        async with self._lock:
            if binary_sha256 in self._analysis_locks:
                # Another coroutine is already analyzing this binary
                event = self._analysis_locks[binary_sha256]
            else:
                event = asyncio.Event()
                self._analysis_locks[binary_sha256] = event
                event = None  # We're the one who will do the analysis

        if event is not None:
            # Wait for the other coroutine to finish
            await event.wait()
            return binary_sha256

        # We're responsible for running the analysis
        try:
            async with _cross_process_analysis_lock(binary_sha256):
                # Re-check under the cross-process lock: another wairz-mcp
                # process may have just finished while we were waiting.
                # Use a fresh session so we see the latest committed state
                # rather than the caller's transaction snapshot.
                async with async_session_factory() as recheck_db:
                    if await self._is_analysis_complete(
                        firmware_id, binary_sha256, recheck_db,
                    ):
                        return binary_sha256

                # Run the analysis on its own session and commit while
                # still holding the flock. If we released the lock with
                # rows only flushed (not committed), a sibling process
                # would re-check, see no rows, and spawn another Ghidra.
                async with async_session_factory() as analysis_db:
                    await self._run_full_analysis(
                        binary_path, firmware_id, binary_sha256, analysis_db,
                    )
                    await analysis_db.commit()
        finally:
            async with self._lock:
                ev = self._analysis_locks.pop(binary_sha256, None)
                if ev is not None:
                    ev.set()

        return binary_sha256

    async def get_run_status(
        self,
        firmware_id: uuid.UUID,
        binary_sha256: str,
        db: AsyncSession,
    ) -> dict | None:
        """Read the most recent background-analysis run row.

        Returned dict has keys: status ("running"|"complete"|"failed"),
        started_at (epoch seconds), optional finished_at, optional pid,
        optional error. None means no run has been kicked off via
        start_binary_analysis (the binary may still be cached if it was
        analyzed synchronously through a different code path).
        """
        return await self._get_cached(
            firmware_id, binary_sha256, "ghidra_analysis_run", db,
        )

    async def mark_run_started(
        self,
        firmware_id: uuid.UUID,
        binary_path: str,
        binary_sha256: str,
        pid: int,
        db: AsyncSession,
    ) -> None:
        await self._store_cached(
            firmware_id, binary_path, binary_sha256, "ghidra_analysis_run",
            {"status": "running", "started_at": time.time(), "pid": pid},
            db,
        )

    async def mark_run_complete(
        self,
        firmware_id: uuid.UUID,
        binary_path: str,
        binary_sha256: str,
        db: AsyncSession,
    ) -> None:
        await self._store_cached(
            firmware_id, binary_path, binary_sha256, "ghidra_analysis_run",
            {"status": "complete", "finished_at": time.time()},
            db,
        )

    async def mark_run_failed(
        self,
        firmware_id: uuid.UUID,
        binary_path: str,
        binary_sha256: str,
        error: str,
        db: AsyncSession,
    ) -> None:
        await self._store_cached(
            firmware_id, binary_path, binary_sha256, "ghidra_analysis_run",
            {
                "status": "failed",
                "finished_at": time.time(),
                "error": error[:2000],
            },
            db,
        )

    async def get_function_run_status(
        self,
        firmware_id: uuid.UUID,
        binary_sha256: str,
        function_name: str,
        db: AsyncSession,
    ) -> dict | None:
        """Read the most recent per-function decompile run row."""
        return await self._get_cached(
            firmware_id, binary_sha256,
            f"function_decompile_run:{function_name}", db,
        )

    async def mark_function_run_started(
        self,
        firmware_id: uuid.UUID,
        binary_path: str,
        binary_sha256: str,
        function_name: str,
        pid: int,
        db: AsyncSession,
    ) -> None:
        await self._store_cached(
            firmware_id, binary_path, binary_sha256,
            f"function_decompile_run:{function_name}",
            {"status": "running", "started_at": time.time(), "pid": pid},
            db,
        )

    async def mark_function_run_complete(
        self,
        firmware_id: uuid.UUID,
        binary_path: str,
        binary_sha256: str,
        function_name: str,
        db: AsyncSession,
    ) -> None:
        await self._store_cached(
            firmware_id, binary_path, binary_sha256,
            f"function_decompile_run:{function_name}",
            {"status": "complete", "finished_at": time.time()},
            db,
        )

    async def mark_function_run_failed(
        self,
        firmware_id: uuid.UUID,
        binary_path: str,
        binary_sha256: str,
        function_name: str,
        error: str,
        db: AsyncSession,
    ) -> None:
        await self._store_cached(
            firmware_id, binary_path, binary_sha256,
            f"function_decompile_run:{function_name}",
            {
                "status": "failed",
                "finished_at": time.time(),
                "error": error[:2000],
            },
            db,
        )

    async def get_functions_if_cached(
        self,
        binary_path: str,
        firmware_id: uuid.UUID,
        db: AsyncSession,
    ) -> list[dict]:
        """Like get_functions but never triggers Ghidra analysis.

        Use this when function metadata is a nice-to-have annotation (e.g.
        mapping byte-scan offsets to enclosing functions) rather than the
        primary product of the call. Returns [] if the binary has not been
        analyzed yet.
        """
        if not os.path.isfile(binary_path):
            return []
        binary_sha256 = await self._get_binary_sha256(binary_path)
        if not await self._is_analysis_complete(firmware_id, binary_sha256, db):
            return []
        cached = await self._get_cached(firmware_id, binary_sha256, "functions", db)
        return cached.get("functions", []) if cached else []

    async def get_functions(
        self,
        binary_path: str,
        firmware_id: uuid.UUID,
        db: AsyncSession,
    ) -> list[dict]:
        """Get function list for a binary (sorted by size desc)."""
        binary_sha256 = await self.ensure_analysis(binary_path, firmware_id, db)

        cached = await self._get_cached(firmware_id, binary_sha256, "functions", db)
        if cached:
            functions = cached.get("functions", [])
            # Apply main detection: if main was detected, update the list
            main_cached = await self._get_cached(
                firmware_id, binary_sha256, "main_detection", db,
            )
            if main_cached:
                main_info = main_cached.get("main_detection", {})
                if main_info.get("found") and main_info.get("method") == "libc_start_main_arg":
                    main_addr = main_info.get("address")
                    for func in functions:
                        if func.get("address") == main_addr and func["name"].startswith("FUN_"):
                            func["name"] = "main"
                            break
            return functions
        return []

    async def get_disassembly(
        self,
        binary_path: str,
        function_name: str,
        firmware_id: uuid.UUID,
        db: AsyncSession,
        max_instructions: int = 200,
    ) -> str:
        """Get disassembly for a function."""
        binary_sha256 = await self.ensure_analysis(binary_path, firmware_id, db)

        cached = await self._get_cached(
            firmware_id, binary_sha256, f"disasm:{function_name}", db,
        )
        if cached:
            disasm = cached.get("disassembly", "")
            # Apply max_instructions limit
            lines = disasm.split("\n")
            if len(lines) > max_instructions:
                lines = lines[:max_instructions]
                lines.append(f"... (truncated at {max_instructions} instructions)")
            return "\n".join(lines)

        return f"No disassembly found for function '{function_name}'. Use list_functions to see available function names."

    async def get_imports(
        self,
        binary_path: str,
        firmware_id: uuid.UUID,
        db: AsyncSession,
    ) -> list[dict]:
        """Get import list for a binary."""
        binary_sha256 = await self.ensure_analysis(binary_path, firmware_id, db)

        cached = await self._get_cached(firmware_id, binary_sha256, "imports", db)
        if cached:
            return cached.get("imports", [])
        return []

    async def get_exports(
        self,
        binary_path: str,
        firmware_id: uuid.UUID,
        db: AsyncSession,
    ) -> list[dict]:
        """Get export list for a binary."""
        binary_sha256 = await self.ensure_analysis(binary_path, firmware_id, db)

        cached = await self._get_cached(firmware_id, binary_sha256, "exports", db)
        if cached:
            return cached.get("exports", [])
        return []

    async def get_xrefs_to(
        self,
        binary_path: str,
        target: str,
        firmware_id: uuid.UUID,
        db: AsyncSession,
    ) -> list[dict]:
        """Get cross-references to a function/symbol.

        First checks for direct 'to' xrefs under the target name. If none
        found (common for imported symbols like doSystemCmd, system, etc.),
        performs a reverse scan of all functions' outgoing ('from') xrefs to
        find callers whose 'to_func' matches the target.
        """
        binary_sha256 = await self.ensure_analysis(binary_path, firmware_id, db)

        cached = await self._get_cached(firmware_id, binary_sha256, "xrefs", db)
        if not cached:
            return []

        xrefs = cached.get("xrefs", {})

        # Direct lookup
        func_xrefs = xrefs.get(target, {})
        direct_results = func_xrefs.get("to", [])
        if direct_results:
            return direct_results

        # Reverse scan: check all functions' outgoing xrefs for calls to target
        reverse_results: list[dict] = []
        for func_name, func_data in xrefs.items():
            for ref in func_data.get("from", []):
                if ref.get("to_func") == target:
                    reverse_results.append({
                        "from": ref.get("from", ref.get("address", "unknown")),
                        "type": ref.get("type", "CALL"),
                        "from_func": func_name,
                    })
        return reverse_results

    async def get_xrefs_from(
        self,
        binary_path: str,
        target: str,
        firmware_id: uuid.UUID,
        db: AsyncSession,
    ) -> list[dict]:
        """Get cross-references from a function/symbol."""
        binary_sha256 = await self.ensure_analysis(binary_path, firmware_id, db)

        cached = await self._get_cached(firmware_id, binary_sha256, "xrefs", db)
        if cached:
            xrefs = cached.get("xrefs", {})
            func_xrefs = xrefs.get(target, {})
            return func_xrefs.get("from", [])
        return []

    async def get_binary_info(
        self,
        binary_path: str,
        firmware_id: uuid.UUID,
        db: AsyncSession,
    ) -> dict:
        """Get binary metadata in r2-compatible shape for frontend compatibility.

        Returns a dict shaped like: {"core": {}, "bin": {"arch": ..., "libs": [...]}}
        """
        binary_sha256 = await self.ensure_analysis(binary_path, firmware_id, db)

        cached = await self._get_cached(firmware_id, binary_sha256, "binary_info", db)
        if not cached:
            return {}

        info = cached.get("binary_info", {})

        # Map to r2-compatible shape
        arch = _map_architecture(info.get("arch", "unknown"))
        bits = info.get("bits", 0)
        endian = info.get("endian", "unknown")
        fmt = info.get("format", "unknown")
        libs = info.get("libraries", [])
        entry = info.get("entry_point", "unknown")
        compiler = info.get("compiler", "unknown")
        image_base = info.get("image_base", "unknown")

        return {
            "core": {
                "format": fmt,
                "file": binary_path,
            },
            "bin": {
                "file": binary_path,
                "bintype": "elf" if "elf" in fmt.lower() else fmt.lower(),
                "arch": arch,
                "bits": bits,
                "endian": endian,
                "os": "linux",
                "machine": info.get("arch", "unknown"),
                "class": f"ELF{bits}" if "elf" in fmt.lower() else fmt,
                "lang": compiler if compiler != "unknown" else "c",
                "stripped": False,  # Ghidra doesn't report this directly; pyelftools handles it
                "static": len(libs) == 0,
                "libs": libs,
                "entry_point": entry,
                "image_base": image_base,
            },
        }

    async def decompile_function(
        self,
        binary_path: str,
        function_name: str,
        firmware_id: uuid.UUID,
        db: AsyncSession,
    ) -> str:
        """Decompile a function, using cached results or falling back to single-function Ghidra.

        First tries the full-analysis cache. If the function wasn't in the top 200
        decompiled, falls back to running DecompileFunction.java for that specific function.
        """
        if not os.path.isfile(binary_path):
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        binary_sha256 = await self._get_binary_sha256(binary_path)
        operation = f"decompile:{function_name}"

        # Check cache (works for both full-analysis and single-function cache entries)
        cached = await self._get_cached(firmware_id, binary_sha256, operation, db)
        if cached:
            code = cached.get("decompiled_code")
            if code:
                logger.info(
                    "Cache hit for %s:%s",
                    os.path.basename(binary_path),
                    function_name,
                )
                return code

        # If full analysis was done but this function wasn't decompiled,
        # fall back to single-function decompilation. Big handler functions
        # (the kind you actually want to look at in a daemon) can take
        # several minutes; bump well past the default 300s but stay under
        # the MCP transport timeout (~600s) so the agent gets a real
        # result instead of a transport-level "user doesn't want to
        # proceed" rejection. If a function needs longer than this, the
        # agent should fall back to start_function_decompile /
        # check_function_decompile_status which runs in a detached
        # worker with a 30-minute timeout.
        raw_output = await run_ghidra_subprocess(
            binary_path,
            "DecompileFunction.java",
            script_args=[function_name],
            timeout=580,
            binary_sha256=binary_sha256,
        )

        decompiled = _parse_decompile_output(raw_output)
        if decompiled is None:
            if "ERROR: Function" in raw_output and "not found" in raw_output:
                lines = raw_output.split("\n")
                func_lines = [
                    line.strip()
                    for line in lines
                    if line.strip().startswith("  ") and "@" in line
                ]
                suggestion = ""
                if func_lines:
                    suggestion = "\n\nAvailable functions:\n" + "\n".join(func_lines[:20])
                return f"Function '{function_name}' not found in binary.{suggestion}"
            return "Decompilation produced no output. The function may be too small or a thunk."

        # Store in cache for future use
        await self._store_cached(
            firmware_id, binary_path, binary_sha256, operation,
            {"decompiled_code": decompiled}, db,
        )

        return decompiled


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_analysis_cache = GhidraAnalysisCache()


def get_analysis_cache() -> GhidraAnalysisCache:
    """Get the module-level GhidraAnalysisCache singleton."""
    return _analysis_cache


# ---------------------------------------------------------------------------
# Legacy wrapper — maintains backward compatibility
# ---------------------------------------------------------------------------


async def decompile_function(
    binary_path: str,
    function_name: str,
    firmware_id: uuid.UUID,
    db: AsyncSession,
) -> str:
    """Decompile a function using Ghidra headless, with caching.

    This is a convenience wrapper around GhidraAnalysisCache.decompile_function().
    """
    cache = get_analysis_cache()
    return await cache.decompile_function(binary_path, function_name, firmware_id, db)
