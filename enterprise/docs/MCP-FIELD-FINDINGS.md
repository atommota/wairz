# MCP Field Findings — first real cloud agent session (2026-06-12)

Triaged notes from the **first end-to-end agent run** against the cloud Wairz MCP
(`wairz.digitalandrew.io/mcp`), reverse-engineering a router firmware
(`/sbin/httpd` `pingTest` command-injection question). Captured here so they
don't get lost; status reflects what was fixed during that session vs. what's
still open.

Two buckets:

- **Cloud transport / UX** — specific to the enterprise (Streamable HTTP +
  CloudFront) deploy. Tracked as **`enterprise/PLAN.md` Phase 6**; summarized
  below for completeness.
- **Core tool bugs** — reproduce on a **local** install too (not cloud-specific).
  These are the focus of this doc; they belong against `main` / the product.

---

## Already fixed in this session (won't recur)

| Symptom the agent saw | Real cause | Status |
|---|---|---|
| Origin fully unreachable mid-session; every call (even `get_project_info`) returns CloudFront HTML | The MCP sidecar's event loop hung on a synchronous boto3 Batch call with **no `batch` VPC endpoint** (no route) → `/healthz` timed out → ECS reaped the task. Plus operator redeploys during debugging. | **Fixed** — `batch` VPC endpoint added; tolerant health check; task resized. |
| `batch:TagResource` `AccessDenied` that "persisted ~1 min" | IAM propagation lag after the grant. | **Fixed** — grant is permanent; one-off lag only. |
| Ghidra jobs never completed | 6-bug Batch-dispatch chain (endpoint, ListJobs API, IAM revision-pinning, TagResource, system-vs-venv python, stale "running" row). | **Fixed** — see PLAN.md §4 batch commits; validated `start_binary_analysis → SUCCEEDED`. |

---

## Open — cloud transport / UX (→ PLAN.md Phase 6)

1. **CloudFront returns HTML error pages for `/mcp`**, so the client gets
   `Unexpected content type: text/html` instead of a typed/retryable error. The
   single highest-leverage fix.
2. **Heavy sync RE tools (`decompile_function`/`list_functions`) 504 at the 60s
   edge** on cold cache; should return a job handle like `start_binary_analysis`.
   `check_binary_analysis_status` itself 504'd during cold start (it should be
   lightweight — it does a synchronous boto3 `describe_jobs` + sha recompute).
3. **`/mcp` reconnect clears the active project** — re-bind server-side.

Details + proposed fixes: `enterprise/PLAN.md` Phase 6.

---

## Fix status (updated 2026-06-12)

| Item | Status |
|---|---|
| Core #1 PLT/import-stub blindness | ✅ **fixed** (`3f44b89`) — detect thunk/import → route to resolve_import; live-validated (0.9s vs 600s hang) |
| Core #2 resolve_import false negative | ✅ **fixed** (`3f44b89`) — whole-rootfs lib search + precise "why" diagnostics; live-validated (found pingTest in libsml.so) |
| Core #3 no decompile/disassemble by address | ✅ **fixed** (`a110bed`) — decompile_function accepts `0x…` (now incl. getFunctionContaining), documented |
| Core #4 hexdump_data unimplemented | ✅ **fixed** (`a110bed`) — implemented as a real tool |
| Core #5 search_strings param naming | ✅ **fixed** (`a110bed`) — accepts `query` alias |
| Core #6 warm_analysis_worker not coupled to readiness | ⏳ open (low) |
| Cloud #2 sync tools 504 on cold cache | ✅ **fixed** (`3f44b89`) — async "analyzing — poll" handle |
| Cloud #2c decompile_function 504s on cache-miss (uncached/by-address) | ✅ **fixed** (`5c9b72a`) — cache hit served direct, else routed to async decompile worker; live-validated (0.8s handle vs 60s timeout) |
| Cloud #2b status-poll / dispatch blocks event loop | ✅ **mitigated** (`a110bed`) — boto3 wrapped in `asyncio.to_thread` |
| Cloud #1 CloudFront HTML error pages | ⏳ open — largely subsumed (fewer 504s); residual is CloudFront's own page on origin-down |
| Cloud #3 persist active project across reconnect | ⏳ open — needs token-identity plumbing through the transport |

The per-item detail below is retained for the open items + as a record.

---

## Open — core tool bugs (reproduce locally; against `main`/product)

### 1. PLT/import-stub blindness in `decompile_function` / `disassemble_function` — HIGH
- **Repro:** `pingTest` in `/sbin/httpd` is a **PLT import thunk** (real impl is
  in `libsml.so`). `decompile_function pingTest` **hung the full 600 s timeout —
  twice**; `disassemble_function pingTest` returned **empty** (no error).
- **Impact:** two ~10-minute dead-ends before the analyst manually found the real
  implementation. Worst single time-sink of the session.
- **Fix:** detect that the target is a thunk/PLT stub and **short-circuit** with a
  pointer to `resolve_import` (and the resolved library), rather than feeding a
  stub to the decompiler. `disassemble_function` should **error**, not return
  empty, on a non-decodable/stub target.

### 2. `resolve_import` false negative — HIGH
- **Repro:** reported `pingTest` "not found in any linked library" while listing
  `libsml.so` among those searched — but `pingTest` **is** exported by
  `libsml.so`. Appears to require the target library to be **pre-analyzed** and
  **fails closed** without saying so.
- **Fix:** distinguish **"not exported anywhere"** from **"library not yet
  analyzed"**; ideally trigger/queue analysis of the candidate lib, or at least
  return an actionable "analyze `libsml.so` first" message instead of a flat
  not-found.

### 3. No decompile/disassemble **by address** — MEDIUM
- When a symbol resolves to a stub (or is stripped), there's no fallback to point
  the decompiler/disassembler at a raw address. `disassemble_function` takes only
  a function name.
- **Fix:** accept an `address` argument on `disassemble_function` /
  `decompile_function` (or add `disassemble_at`/`decompile_at`).

### 4. `hexdump_data` advertised but unimplemented — LOW
- Listed in the deferred tool set; calling it returns **`No such tool
  available`**. Stale registration or missing handler — implement or de-list.

### 5. `search_strings` param naming inconsistency — LOW
- Requires `pattern`, but the analyst (reasonably) passed `query` and got
  `'pattern' is a required property`. Other string tools
  (`search_binary_content`, `find_string_refs`) use different conventions.
- **Fix:** align the parameter name across the string-search tools (or accept an
  alias) for a consistent surface.

### 6. `warm_analysis_worker` doesn't guarantee warmth — LOW
- Returned "starting ~1–3 min", but the **very next** `decompile_function` still
  timed out at 600 s. The warm signal isn't coupled to the decompiler's actual
  readiness.
- **Fix:** make `warm_analysis_worker` block until (or report) genuine readiness,
  or have the decompile path consume the warmed worker.

---

## Highest-leverage, across both buckets
1. Typed/retryable errors instead of CloudFront HTML (cloud #1).
2. PLT/import-stub detection → route to `resolve_import`; make `resolve_import`
   work without manual pre-analysis (core #1 + #2).
3. Persist active project across reconnect (cloud #3).
4. Job handle for sync RE tools on cold cache (cloud #2).
