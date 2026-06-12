# Wairz Enterprise Deployment — Build Plan for Agents

**Audience:** AI agents (and humans) implementing the elastic AWS deployment on
the `wairz_enterprise` branch.
**Goal:** an operator can `git clone`, `cd enterprise/terraform`, set variables,
`terraform apply`, and get a running Wairz that costs ~$35–75/mo at rest and
bursts Ghidra decompilation onto scale-to-zero AWS Batch workers.

Read this top to bottom before touching anything. The **Codebase Ground Truth**
section is non-negotiable context — getting it wrong will send you down the
wrong path.

---

## 0. Live apply-test (2026-05-29) — full stack validated on real AWS

A real `terraform apply` in us-east-1 (account 767303321530) stood up all
modules and validated the end-to-end paths, then was torn down. **Validated:**
76→79-resource apply clean; backend Fargate healthy behind the ALB; the API
served through both the ALB and CloudFront, backed by Aurora (migrations ran,
`/api/v1/projects`→`[]`); and the **Batch scale-from-zero compute path** — a
Spot `c6i.xlarge` provisioned, pulled the image from ECR, mounted both EFS
access points read-write (the shared project store wrote OK), received the
`DATABASE_URL` secret + env, and had Ghidra + boto3/redis present (job
SUCCEEDED, exit 0).

**Four real bugs found and fixed (deployment code, not test hacks):**
1. The image's default CMD uses `uv run`, which re-resolves against pypi.org at
   startup and times out in a no-egress private subnet → backend module runs the
   prebuilt venv binaries directly (`/app/.venv/bin/{alembic,uvicorn}`).
2. The app's `origin_host_guard` hardcoded a localhost-only allowlist → made
   configurable via `allowed_hosts`/`allowed_origins` settings (empty = original
   local behavior; `*` for behind-proxy), and `/health` is now guard-exempt so
   ELB probes pass.
3. **Missing `ecs`/`ecs-agent`/`ecs-telemetry` VPC interface endpoints** — EC2
   Batch instances ran the ECS agent but couldn't reach the control plane to
   register (no NAT), so jobs hung in RUNNABLE. Added to the network module.
   (Fargate was unaffected — AWS manages its control-plane link.)
4. Aurora engine `16.4` no longer offered → default bumped to `16.9`.

Also added: ECS service `health_check_grace_period_seconds = 120` (lets
migrations + uvicorn boot before ELB checks count). All fixes keep the local
suite green (216 passed) and the local docker-compose deploy unchanged.

## 1. Architecture (agreed)

```
            ALWAYS ON (cheap)                          ON DEMAND (Spot, scales 0→N)
┌──────────────────────────────────────┐      ┌──────────────────────────────────────┐
│ CloudFront ──┬─→ S3 (static SPA)      │      │  AWS Batch managed compute env (EC2)   │
│              └─→ ALB → ECS Fargate     │      │   • Ghidra job  (CPU/RAM-opt, Spot)    │
│                    (FastAPI, 1..N)     │─────▶│   submit → run → write cache row → exit│
│ Cognito (auth)                         │ Submit└──────────────────────────────────────┘
│ Aurora Serverless v2 (PostgreSQL)      │ Job          │  scales to 0 vCPU at rest
│ ElastiCache Redis (locks/coordination) │◀──────┐      │
└──────────────────────────────────────┘  poll  │      │
                    │                       cache row    │
                    └────────────── EFS (shared firmware) ┘
```

- **Frontend:** built SPA in S3, served via CloudFront. `/api/*` and websockets
  route to the ALB origin (see §6 Frontend for the nginx-proxy translation).
- **Backend:** FastAPI on ECS Fargate behind an internal/public ALB. Stateless;
  autoscales on CPU/request count. All state in Aurora/Redis/EFS.
- **Database:** Aurora Serverless v2 (PostgreSQL-compatible), `min_capacity`
  low (0.5 ACU, or 0 ACU auto-pause if acceptable).
- **Cache/locks:** ElastiCache Redis (smallest node, or Serverless).
- **Firmware storage:** EFS access point mounted at `STORAGE_ROOT` on both the
  Fargate backend and the Batch jobs. **This is the shared-state linchpin.**
- **Heavy compute:** Ghidra runs as an AWS Batch job. The backend submits the
  job and polls the existing `ghidra_analysis_run` cache row — the async
  protocol and frontend polling are unchanged.
- **Auth:** Cognito, because this is a shared multi-user instance.

**Explicitly out of scope for the MVP:** fuzzing, emulation, carving (the
`docker.sock` features). See §8 for how they slot in later.

---

## 2. Codebase Ground Truth (verified — do not re-derive)

These facts were confirmed by reading the source. Trust them; re-verify only if
the code has changed.

1. **Unpacking is in-process, not a container.** `app/workers/unpack.py` +
   `app/workers/fs_extractors.py` run binwalk/sasquatch/jefferson/etc. directly.
   The full extraction toolchain is **baked into the backend image**
   (`backend/Dockerfile`). → Unpacking works on Fargate with **no code change**.

2. **`docker.sock` is used by exactly three features, all on-demand/optional:**
   - `app/services/carving_service.py` (carve sandbox — MCP `tools/carving.py`)
   - `app/services/fuzzing_service.py`
   - `app/services/emulation_service.py`
   None are on the core upload→unpack→browse→decompile→report path. → The MVP
   needs **no `docker.sock`** and Fargate (which has none) is fine.

3. **Ghidra runs IN the backend process.** `app/services/ghidra_service.py`
   invokes `analyzeHeadless` via `asyncio.create_subprocess_exec` /
   `run_in_executor`. There is already a **detached worker**
   (`app/workers/run_ghidra_analysis.py`, invoked
   `python -m app.workers.run_ghidra_analysis --firmware-id ... --binary-path ...
   --sha256 ...`) spawned with `start_new_session=True`. This is the seam: the
   worker already runs to completion independently and writes results to the DB.
   **The enterprise change replaces "spawn local subprocess" with "submit a
   Batch job that runs the same worker."**

4. **Job coordination already exists via the DB.** `start_binary_analysis` →
   `check_binary_analysis_status` is coordinated through the
   `ghidra_analysis_run` cache row + an `analysis_cache` table keyed by binary
   sha256 + a cross-process lock (`_cross_process_analysis_lock` in
   `ghidra_service.py`). The frontend polls. → Keep this protocol; only change
   *where* the work runs and *what backs the lock*.

5. **The cross-process lock is currently local** (process/host scoped). In a
   distributed setup it MUST move to Redis (already in the stack) so two Batch
   jobs / backend tasks don't double-analyze the same binary.

6. **Caching is keyed by binary sha256 + function name** in `analysis_cache`.
   This makes Ghidra jobs **idempotent** → Spot interruption is safe (re-run
   recomputes the same cache row; partial work is just discarded).

7. **Config is pydantic-settings** (`app/config.py`), reads from `.env` OR
   environment variables (env vars override). Every setting is env-overridable.
   → Inject ECS task config via `environment` / `secrets`. New settings added
   for the cloud must have **local-compatible defaults** so `docker-compose`
   keeps working.

8. **Sandbox path checks use `os.path.realpath` against the extracted root**
   (`app/utils/sandbox.py`, via `ToolContext.resolve_path`). → Storage MUST stay
   a real POSIX filesystem path. **Use EFS, not S3, for firmware.** S3 would
   require rewriting every `resolve_path`; do not.

9. **Backend image bundles Ghidra (16G heap tuning) + JDK 21.** In the cloud the
   backend no longer *runs* Ghidra (Batch does), so a **slim backend image**
   (drop Ghidra + JDK, keep the extraction toolchain for unpack) is a worthwhile
   optimization — but it is **optional** and should not block the MVP. Track as
   §6 Backend optional task.

10. **Frontend is nginx** serving static `dist` + proxying `/api/` (with
    websocket upgrade) to `backend:8000` (`frontend/nginx.conf.template`,
    `client_max_body_size ${MAX_UPLOAD_SIZE_MB}M`). The reverse-proxy behavior
    must be reproduced in the cloud (CloudFront origins, or keep nginx as a
    small Fargate task — see §6 Frontend).

11. **DB migrations auto-run on backend start** (`alembic upgrade head` in the
    backend `CMD`). → No separate migration step needed, but be aware multiple
    Fargate tasks may race on first boot; run migrations as a one-off ECS task
    or guard with a startup lock if you scale initial `desired_count > 1`.

---

## 3. App-code changes required (on this branch)

All gated behind config so local `docker-compose` is unaffected. Add a single
discriminator setting, e.g. `compute_backend: Literal["local", "aws_batch"] =
"local"` in `app/config.py`.

| # | Change | File(s) | Notes |
|---|--------|---------|-------|
| C1 | Add `compute_backend` + AWS settings (`aws_region`, `batch_job_queue`, `batch_job_definition`, `s3_*` if needed) | `app/config.py` | Defaults keep `local` behavior |
| C2 | Abstract Ghidra dispatch behind a strategy: `local` spawns the existing detached worker; `aws_batch` calls `batch:SubmitJob`. **Done (Phase 0):** seam lives in `app/services/compute_dispatch.py`; `local` path unchanged | `app/ai/tools/binary.py`, `app/services/compute_dispatch.py` | The Batch job runs the **same** `python -m app.workers.run_ghidra_analysis ...` command |
| C3 | Move `_cross_process_analysis_lock` to a Redis-backed lock when `compute_backend != "local"` | `app/services/ghidra_service.py` | Use the existing `redis_url`; `SET NX PX` lease + renewal. Guards the **import/write** (§3.1) |
| C4 | Ensure `STORAGE_ROOT` works on EFS (no behavior change expected; verify no host-path assumptions) | `app/utils/sandbox.py`, storage paths | Mostly a verification task |
| C5 | Status mapping: `check_binary_analysis_status` should also reflect Batch job states (e.g. `SUBMITTED/RUNNABLE/STARTING` → "queued/starting") so a cold-start (1–3 min) reads correctly in the UI | `ghidra_service.py`, status tool | Cache row remains source of truth on completion |
| C6 | Feature-flag the `docker.sock` features off in the cloud profile with a clear "run locally" message | `tools/{carving,fuzzing,emulation}.py` registration / capability gate | Avoids confusing errors on Fargate |
| **C7** | **Persistent Ghidra project store** — import once, reuse forever (§3.1). The single biggest Phase 2 change; **also benefits local mode** | `app/services/ghidra_service.py` (`_build_analyze_command`, `run_ghidra_subprocess`, `ensure_analysis`) | Replaces import-and-`-deleteProject`-every-call with `-import` once + `-process -readOnly` reuse |
| **C8** | **Warm RE worker** (explicit opt-in) — session-scoped hot compute for reuse runs (§3.2) | new `app/services/re_worker_service.py`, new MCP tool `warm_analysis_worker`, `tools/binary.py` reuse-dispatch | Long-lived Batch job draining a Redis queue; idle-timeout to zero |

**Acceptance for the app-code layer:** with `compute_backend=local`, behavior is
byte-for-byte the current behavior except reuse is **faster** (C7 removes
per-call re-analysis) — run the existing test suite. With
`compute_backend=aws_batch` + EFS + Batch, the flows in §3.1/§3.2 hold.

### 3.1 Persistent Ghidra project store (C7) — the core of Phase 2

**Problem found in Phase 0:** `_build_analyze_command` always uses
`-import <binary> … -postScript … -deleteProject`, so **every** synchronous
Ghidra call (the 5 query scripts: `DecompileFunction`, `FindStringRefs`,
`StackLayout`, `GlobalLayout`, `TaintAnalysis` — plus `ensure_analysis` for the
Class-A read tools) re-imports and re-runs the heavy auto-analysis in a
throwaway project. There is **no Ghidra-level curation write-back today** — the
5 query scripts are read-only emitters; only `AnalyzeBinary.java` writes. So the
reusable asset is the **analyzed program** itself.

**Design — one persistent project per binary, keyed by `sha256`:**

- **Store location:** EFS in cloud (`GHIDRA_PROJECT_ROOT`, mounted by backend +
  all Batch jobs); a new `ghidra_projects` Docker volume locally. Path includes
  the Ghidra version: `<root>/<ghidra_ver>/<sha256>/` (so a Ghidra upgrade never
  opens an incompatible project).
- **Import once (write, heavy):** first touch runs `-import … -postScript
  AnalyzeBinary.java` and **keeps** the project (drop `-deleteProject`). Guarded
  by the **Redis lock (C3)** keyed by sha256 so concurrent first-touches dedupe.
  In cloud this is a **Batch** job; locally it's the detached worker / inline.
- **Reuse forever (read, light):** all 5 query scripts run
  `analyzeHeadless <project> -process -noanalysis -readOnly -postScript <script>`
  — no re-import, no re-analysis (minutes → seconds). `-noanalysis` skips the
  expensive auto-analysis (done at import); `-readOnly` never writes back.
- **Concurrency (corrected):** a *local* Ghidra project (.gpr/.rep) permits only
  **one** headless process at a time, even read-only. So access per binary is
  **serialized** via the existing `fcntl` flock keyed by sha256 (the import path
  and every reuse run share it). Different binaries run fully in parallel —
  which is the common case (users/agents on different binaries). True
  *concurrent same-binary* reuse needs either per-run project **copies**
  (copy-on-read to a temp dir → parallel readers, at a copy cost) or a **Ghidra
  Server**; deferred to 2c/cloud where it actually matters. For local + typical
  shared-team use, per-binary serialization is correct and sufficient.
- **Program naming:** import so the program is addressable by `sha256` for
  `-process` (import a path/symlink named `<sha256>`, or store the basename↔sha
  mapping). Implementation detail — make it deterministic.
- **Cross-firmware dedup (bonus):** content-hash key ⇒ a binary shipped in many
  firmwares (e.g. busybox) is analyzed once, reused everywhere.
- **GC:** projects accumulate on disk → LRU/size-cap eviction by last-access;
  `log()` evictions (never silent).
- **Future upgrade path (NOT now):** persisting *interactive curation*
  (renames/comments/types shared across users) would need a **Ghidra Server**
  (multi-writer check-in/out). Out of scope until Wairz writes curation back;
  the file-project store is forward-compatible with that move.

### 3.2 Warm RE worker (C8) — interactive reuse without a big always-on box

Reuse runs are **frequent and interactive** (agent answering questions about a
binary). Heavy initial analysis always goes to **scale-to-zero Batch**. Reuse
runs execute as follows:

- **Default (rest = $0):** each reuse run is a **one-shot Batch job** (`-process
  -readOnly` against the EFS project). Works; ~1–3 min cold start per call.
- **Warm mode (explicit opt-in):** a tool `warm_analysis_worker(ttl_minutes=N)`
  starts a **long-lived Batch job** that drains a **Redis work-queue**: backend
  pushes `{sha256, script, args}`, the worker pops, runs `-process -readOnly`,
  writes the result to a Redis key, backend polls it (sub-second). Each reuse
  call **resets the idle timer**; after `ttl` minutes idle (empty queue) the
  worker exits → back to zero. So it stays hot during an active RE session and
  tears down afterward. Pay the cold start **once per session**, not per call.
- **Spot policy:** warm worker runs **on-demand** (no mid-session death); heavy
  initial-analysis jobs stay on **Spot** (idempotent).
- **Same mechanism** as the future emulation on-demand worker (§8) — build once.

Because no inline Ghidra runs on the backend, the **slim backend image becomes
achievable** (drop Ghidra + JDK; keep the unpack toolchain). Promoted from
"optional" to a real Phase 2/4 outcome.

> **Retracted:** the earlier "keep Ghidra in the backend and run inline" option
> is rejected — it would require a ~16 GB always-on Fargate task doing heavy
> analysis on the request path, reintroducing the oversized always-on instance
> this whole effort exists to eliminate.

---

## 4. Terraform layout & conventions

- **Terraform >= 1.6**, AWS provider v5. Pin in `terraform/versions.tf`.
- **Remote state:** support an S3 backend + DynamoDB lock; ship a
  `backend.tf.example` (commented) so first-run can use local state, then
  migrate. Document in README.
- **One root module** in `terraform/` composing the modules in
  `terraform/modules/`. Modules are **black boxes with typed variables and
  outputs** — no cross-module resource references except via outputs.
- **Naming:** prefix everything with `var.name_prefix` (default `wairz`) +
  `var.environment` (default `prod`). Tag every resource with
  `{ Project = "wairz", Environment = var.environment, ManagedBy = "terraform" }`
  via provider `default_tags`.
- **Secrets:** never plaintext in tfvars. DB password, NVD API key, etc. in AWS
  Secrets Manager; reference ARNs. ECS task pulls via `secrets` block.
- **Images:** build + push to ECR as part of apply (use the
  `terraform-aws-modules`-style `docker_build` via the `kreuzwerker/docker`
  provider, or a `null_resource` + `aws ecr get-login` + `docker buildx`).
  Pin image tags to a content hash, not `latest`, so applies are deterministic.
- **`terraform.tfvars.example`** must enumerate every variable an operator sets,
  with comments and safe defaults. This file IS the operator contract.

### Module responsibilities

| Module | Provisions | Key outputs |
|--------|-----------|-------------|
| `network` | VPC, public+private subnets across 2+ AZs, NAT (or VPC endpoints to avoid NAT cost), SGs, VPC endpoints (ECR, S3, Secrets, Logs) | `vpc_id`, subnet ids, sg ids |
| `storage` | EFS file system + access point + mount targets (private subnets); S3 buckets (SPA, optional uploads) | `efs_id`, `efs_access_point_arn`, bucket names |
| `database` | Aurora Serverless v2 PostgreSQL cluster, subnet group, secret | `db_endpoint`, `db_secret_arn` |
| `cache` | ElastiCache Redis (node or Serverless), subnet group, SG | `redis_endpoint` |
| `backend` | ECR repo, ECS cluster, Fargate service + task def (EFS mount, env, secrets), ALB, target group, autoscaling | `alb_dns_name`, `service_name` |
| `frontend` | S3 (static), CloudFront distribution (S3 + ALB origins, behaviors for `/api/*` and `/`), ACM cert wiring | `cloudfront_domain` |
| `batch` | ECR repo (Ghidra image), Batch compute env (EC2, `minvCpus=0`, Spot), job queue, job definition (EFS volume, env), IAM roles | `job_queue_arn`, `job_definition_arn` |
| `auth` | Cognito user pool + app client, ALB/CloudFront integration | `user_pool_id`, `client_id` |

---

## 5. Environment / variable contract

The backend reads these (pydantic settings names in parentheses). Terraform
wires them into the ECS task definition and the Batch job definition.

| Env var (setting) | Source | Notes |
|---|---|---|
| `DATABASE_URL` (`database_url`) | `database` module → secret | asyncpg URL to Aurora |
| `REDIS_URL` (`redis_url`) | `cache` module | locks + coordination |
| `STORAGE_ROOT` (`storage_root`) | fixed `/data/firmware` | EFS mount point in both backend + Batch |
| `GHIDRA_PROJECT_ROOT` (`ghidra_project_root`) | EFS path (cloud) / `ghidra_projects` volume (local) | persistent project store (C7); mounted by backend + Batch |
| `COMPUTE_BACKEND` (`compute_backend`) | `aws_batch` in cloud | new setting (C1) |
| `AWS_REGION` | provider region | |
| `BATCH_JOB_QUEUE` / `BATCH_JOB_DEFINITION` | `batch` module outputs | C2 (heavy import) |
| `BATCH_REUSE_JOB_DEFINITION` (`batch_reuse_job_definition`) | `batch` module output | C8 warm/one-shot reuse worker (`-process -readOnly`) |
| `RE_WORKER_IDLE_TTL_MINUTES` (`re_worker_idle_ttl_minutes`) | tfvar, default 20 | warm worker idle teardown (C8) |
| `NVD_API_KEY` (`nvd_api_key`) | Secrets Manager | optional |
| `MAX_UPLOAD_SIZE_MB` (`max_upload_size_mb`) | tfvar | also sets ALB/CloudFront body limits + nginx |
| `LOG_LEVEL` (`log_level`) | tfvar | |

Document the full list in `terraform.tfvars.example` and a table in the README.

---

## 6. Phased work breakdown

Each phase is independently shippable; the app keeps working throughout. Do them
in order. **Definition of done** is listed per phase — an agent should not mark
a phase complete without meeting it.

### Phase 0 — Foundations (no AWS yet) — ✅ DONE
- Write `terraform/versions.tf`, root `main.tf`/`variables.tf`/`outputs.tf`
  skeleton, `terraform.tfvars.example`, `backend.tf.example`.
- Implement app-code changes **C1** (settings) and the strategy *seam* for **C2**
  (no Batch call yet — just the indirection, `local` path unchanged).
- **DoD:** `terraform validate` passes on the skeleton; local `docker-compose`
  still works; existing backend tests green with `compute_backend=local`.
- **Outcome:** `terraform validate` + `fmt` clean. Backend suite run inside the
  container with the edited files overlaid: **216 passed, 12 skipped**, no new
  failures vs. baseline. (3 pre-existing failures in
  `test_mcp_firmware_selection.py` are unrelated — a stale `_FakeFirmware`
  fixture missing `firmware_kind`; they fail on the baked image too.) C2 seam:
  `app/services/compute_dispatch.py` (`get_dispatcher()` → `LocalDispatcher`
  by default), wired into `binary.py`.

### Phase 1 — State backbone (network, storage, db, cache) — ✅ code DONE, apply pending
- Implement `network`, `storage` (EFS + S3), `database` (Aurora SLv2), `cache`
  (Redis) modules.
- App-code **C3** (Redis lock) and **C4** (EFS path verification).
- **Implemented:** four Terraform modules + root wiring (`terraform validate` +
  `fmt` clean). C3: `_cross_process_analysis_lock` dispatches on
  `compute_backend` — `fcntl.flock` for `local` (unchanged), a renewing Redis
  lock (`_redis_analysis_lock`, lazy `redis` import) otherwise; `redis>=5` added
  to `pyproject` (cloud-only path). C4: `STORAGE_ROOT`/`GHIDRA_PROJECT_ROOT`
  stay POSIX paths backed by EFS access points — verified no host-path
  assumptions. New setting `redis_lock_ttl_seconds`.
- **Verified:** suite 216 passed (local unchanged); Redis lock mutual-exclusion
  + renewal proven against the running redis container (holder kept the lock
  across a hold longer than the TTL; waiter blocked until release).
- **DoD — apply pending an operator AWS account.** `terraform apply` (VPC + EFS
  + Aurora + Redis) and the wired `_redis_analysis_lock` integration test both
  need real AWS / a rebuilt image with `redis-py`; not runnable from the dev
  environment. Code is review-ready.

### Phase 2 — Ghidra on Batch + persistent project store + warm worker
This is the heaviest phase. Sub-steps, in order:

**2a — Persistent project store (C7), local-first. ✅ DONE.** Land `-import`-once
+ `-process -noanalysis -readOnly`-reuse against a per-`sha256` project store,
behind a `ghidra_projects` volume, in **local mode**. Pure speed win locally,
de-risks the cloud work. Includes version-keyed paths and LRU GC.
- **Implemented:** `ghidra_service.py` — `_project_dir` (`<root>/<ghidra_ver>/
  <sha256>/`), `_build_import_command` (persist, no `-deleteProject`) /
  `_build_process_command` (`-process -noanalysis -readOnly`), `_exec_headless`,
  `_ensure_project_imported` + `_run_process_script` (unlocked internals so
  callers already holding the sha256 flock don't deadlock), `run_ghidra_subprocess`
  rewritten to import-once-then-reuse under the flock, LRU GC
  (`_gc_project_store`, lock-guarded eviction). New settings
  `ghidra_project_root` / `ghidra_project_cache_max`; `ghidra_projects` volume in
  compose.
- **Verified in container:** call 1 logged `Importing + analyzing` (8.0s) and
  persisted `wairz.gpr`/`wairz.rep`/`.wairz_analyzed`; call 2 logged `Reusing
  project … (-process, no re-analysis)` (3.6s). GC test: 5 projects, cap 2 →
  3 oldest evicted, 2 newest kept. Suite: 216 passed (baseline unchanged).
- **DoD(2a): met.**

**2b — Batch module + heavy import on Batch (C2 real `SubmitJob`, C3, C5). ✅ code
DONE, apply pending.** `batch` module (EC2 Spot compute env `minVcpus=0`,
`maxVcpus` ceiling; job queue; import job definition mounting EFS at
`STORAGE_ROOT` + `GHIDRA_PROJECT_ROOT`, secrets, awslogs; IAM
instance/spot-fleet/execution/job roles; ECR repo). Redis lock (C3) guards the
import.
- **Implemented:** `modules/batch/` (validated + wired into root). C2:
  `BatchDispatcher` in `compute_dispatch.py` (`boto3 submit_job` with per-binary
  command override; `boto3` added to `pyproject`, lazily imported). C5:
  `mark_run_started` stores a `job_ref`; `check_binary_analysis_status` branches
  on `compute_backend` — Batch path maps job state via `describe_batch_job_state`
  (queued/starting/running/failed), cache row still the completion source of
  truth. Local path byte-identical.
- **Reuse the backend image** as the Batch image (it bundles Ghidra + the worker
  code); push it to the module's ECR repo (`ghidra_ecr_repository_url` output).
  A dedicated `enterprise/docker/` slim image is optional later.
- **Verified here:** Terraform validate/fmt clean; module imports without boto3
  (lazy); suite 216 passed (local unchanged).
- **DoD(2b): apply pending an AWS account** — submit→scale-0→1→import→persist→
  cache→scale-0 and Spot-interruption-retry need a real Batch env.
- **Known gap (follow-up):** the *function*-decompile status
  (`check_function_decompile_status`) still uses the local pid-liveness branch;
  in cloud mode it should mirror C5's Batch-state mapping. The decompile itself
  works (job runs, writes cache); only intermediate polling may misreport. Low
  risk (re-submit is idempotent). Tracked for 2c.

**2c — Reuse dispatch + warm worker (C8). ✅ DONE, validated on AWS.** In cloud
mode `run_ghidra_subprocess` delegates query scripts to a warm reuse worker over
Redis instead of running Ghidra in the backend; `ensure_analysis` auto-dispatches
the heavy import to Batch (never runs Ghidra in-backend). `warm_analysis_worker`
(explicit opt-in) pre-starts a long-lived Batch worker that drains a Redis queue;
activity resets its idle timer; empty-queue idle past `ttl` → exits.
- **Implemented:** `app/workers/run_reuse_worker.py`; `_run_ghidra_local` /
  `_run_ghidra_remote` / `ensure_reuse_worker` in `ghidra_service`;
  `BatchDispatcher.dispatch_reuse_worker`; `warm_analysis_worker` MCP tool;
  C5 fn-status Batch mapping. Reuse worker runs on the existing Batch queue via
  a command override (no new infra). Local mode byte-identical.
- **Validated on AWS (2026-05-29):** a driver exercised the full data path —
  Redis queue (ElastiCache) → `_run_ghidra_local` import+persist on a Batch
  instance (EFS) → result round-trip → `-process` reuse (22.5s import → 10.2s
  reuse), EFS project persisted; the C3 Redis lock ran against ElastiCache. The
  `run_reuse_worker` lifecycle was confirmed: boot → blocking drain → idle
  self-exit (exit 0).
- **Two bugs fixed during 2c live test:** (a) the Ghidra **scripts** weren't in
  the image (`/opt/ghidra_scripts` empty in cloud → every `-postScript` failed)
  → baked in via a `ghidra_scripts` build context; (b) redis-py's blocking
  `BLPOP` read-times-out on an empty queue unless `socket_timeout` exceeds the
  BLPOP timeout → set explicitly in the worker and `_run_ghidra_remote`.

### Phase 3 — Serving layer (backend, frontend, auth) — ✅ code DONE, apply pending
- Implement `backend` (ECR + Fargate + ALB + autoscaling), `frontend` (S3 +
  CloudFront), `auth` (Cognito) modules.
- App-code **C6** (gate `docker.sock` features off in cloud profile).
- **Implemented + validated:** `modules/backend` (ECR, ECS cluster, Fargate task
  with EFS mounts + DATABASE_URL secret + COMPUTE_BACKEND/BATCH_* env, ALB +
  target group + HTTP listener (+ optional HTTPS when `alb_certificate_arn`
  set), CPU autoscaling, IAM exec + task role with `batch:SubmitJob/DescribeJobs`),
  `modules/frontend` (CloudFront: S3/OAC origin for the SPA + ALB origin for
  `/api/*` with AllViewer/CachingDisabled for websockets, SPA 403/404→index.html
  fallback, OAC bucket policy), `modules/auth` (Cognito user pool + app client +
  hosted-UI domain, invite-only). Root wires all three; `terraform validate` +
  `fmt` clean. C6: `create_tool_registry` registers emulation/fuzzing/carving/
  uart only when `compute_backend == "local"`.
- **Verified here:** C6 gating — local exposes 100 tools (incl. emulation/fuzzing/
  uart), aws_batch exposes 67 (33 host-only tools hidden); suite 216 passed.
- **Frontend routing:** chose **option A** (CloudFront multi-origin) per §6.
- **Apply pending an AWS account.** Also note image build/push to ECR + SPA sync
  to S3 + CloudFront invalidation are operator/CI steps (a `null_resource`/CI
  hook can automate; see Phase 4).
- **Auth wiring note:** the Cognito pool is created; enforcing it at the ALB
  (authenticate-cognito action) needs the HTTPS listener (`alb_certificate_arn`)
  — documented, not auto-enabled, so the stack deploys without a domain/cert.
- **Frontend routing decision (pick and document):**
  - **(A) CloudFront multi-origin (recommended):** S3 origin for static assets,
    ALB origin for `/api/*` + websockets. Translate `nginx.conf.template`
    behaviors into CloudFront cache behaviors; set body-size via ALB. SPA
    fully static, cheapest at rest.
  - **(B) Keep nginx as a tiny Fargate task** behind the same ALB (least code
    change — reuses `frontend/Dockerfile` and `nginx.conf.template`). Slightly
    higher idle cost, zero routing rework.
  Default to (A) unless websocket/proxy behavior proves fiddly; fall back to (B).
- **DoD:** `terraform apply` from clean state yields a CloudFront URL serving the
  SPA; login via Cognito; upload + unpack + browse + decompile (via Batch) +
  findings + reports all work end-to-end. MCP server connects.

### Phase 4 — Hardening & polish

**4a — Image & SPA delivery automation. ✅ DONE.** `terraform apply` now builds
the backend image once and pushes it to **both** ECR repos (backend + ghidra;
kept as two repos, image pushed twice), then publishes the SPA (S3 sync +
CloudFront invalidation). No more manual ECR push / S3 sync.
- **Implemented:** `enterprise/scripts/{image-tag,build-and-push-backend,deploy-spa}.sh`
  + `terraform/deploy.tf` (`data.external.image_tag`, `null_resource.backend_image`,
  `null_resource.spa`); `image_tag`/`auto_deploy_images` vars wired into the
  backend + batch modules; `null`/`external` providers pinned. The backend build
  reproduces compose's named contexts (`kernels`, `ghidra_scripts`) and forces
  `--platform linux/amd64`; the SPA needs no build-time config (relative `/api/v1`).
- **Tag:** git 12-char SHA, `+<dirty8>` for uncommitted edits → deterministic,
  content-addressed, re-pushes only when source changes.
- **Out-of-band escape hatch:** `auto_deploy_images=false` + explicit `image_tag`
  for CI-driven builds. `terraform validate`/infra-only flows need no Docker/Node.
- **Validated on AWS (2026-06-10, acct 767303321530):** a full `terraform apply`
  (81 resources) ran the automation end-to-end — backend image built (named
  contexts `kernels`/`ghidra_scripts` OK), pushed identically to **both** repos
  @ `12d318cc899e-ba9f9813` (1.55 GB each), SPA synced (7 objects) + CloudFront
  invalidated. The deployed stack served live: SPA root → 200, `/api/v1/projects`
  via CloudFront → 200 `[]`, ECS 1/1 `COMPLETED` (cold-start race self-resolved
  as designed). Torn down clean.
- **One bug found + fixed during teardown:** the SPA `aws_s3_bucket` lacked
  `force_destroy`, so once the bucket was populated by the new SPA sync,
  `terraform destroy` failed with `BucketNotEmpty` (it slipped through before
  because the bucket was always empty). Added `force_destroy = true` to
  `modules/storage` (derived artifacts, not user data).
- Cold-start race (push vs. ECS service create) is documented (service doesn't
  wait for steady state; ECS retries the pull) — not a hard dependency because
  both repos live inside their modules (repo→push→service would cycle).
- **Remaining Phase 4 (below) untouched.**

**4b — Migration-on-boot race guard (fact #11). ✅ DONE + live-tested 2026-06-11.**
Chose the **startup advisory lock** over a one-off ECS migration task: it also
covers *autoscale-up* races at any time (not just first apply) and adds no
apply-time DB/image ordering dependency. `backend/alembic/env.py`
`do_run_migrations` now takes a PostgreSQL session-level lock
(`pg_advisory_lock(MIGRATION_LOCK_KEY)`) before migrating and releases it in
`finally` (also auto-released on disconnect, so a crashed migrator never wedges
it). The implicit txn the acquire opens is committed before alembic begins its
own transaction; the session lock survives the commit. First booting task
migrates; concurrent tasks block then run a no-op `upgrade head`. Transparent
for a single local migrator (instant acquire) — docker-compose path unchanged.
- **Local proof (real Postgres):** holding the lock externally made a concurrent
  `alembic upgrade head` block ~7s, then proceed the instant it released.
- **Live proof (Aurora, acct 767303321530, 2026-06-11):** applied with
  `desired_count=2` (test-only) so two backend tasks booted at once. Task A won
  the lock and ran the full 26-migration chain on the fresh DB; task B blocked,
  then logged **zero `Running upgrade` lines** (DB already at head) and went
  straight to uvicorn. Both reached ALB-healthy 2/2; SPA 200, `/api/v1/projects`
  200 `[]` via CloudFront and ALB. Torn down clean. (`desired_count=2` reverted;
  default floor stays 1.)

**4c — Per-firmware Batch concurrency cap. ✅ DONE 2026-06-11.** Shared-instance
fairness guardrail (§7): the backend rejects a Ghidra dispatch when the target
firmware already has `batch_max_jobs_per_firmware` (default 8) jobs in flight,
bounding a runaway agent so one analyst's firmware can't saturate the queue
under `batch_max_vcpus`. Enforced in `BatchDispatcher` (cloud path only — local
subprocess mode untouched): `_enforce_firmware_cap` counts active jobs by
`JOB_NAME` prefix (`wairz-<fw12>-*`) across all active statuses via `list_jobs`
(authoritative queue count, no drifting local counter), and raises
`ConcurrencyLimitError` *before* submit/mark-started (no phantom 'running' row);
the MCP tools surface it as `rejected - …`. Jobs are tagged `wairz:firmware` for
console/cost visibility. **Key = firmware** (the one identity available at every
dispatch site, incl. `ghidra_service.ensure_analysis` which only has
`firmware_id`); a firmware belongs to one project/analyst, so this realizes the
per-project/per-user fairness goal. A stricter per-*user* cap needs the
authenticated identity from the deferred ALB-Cognito work. Plumbed end-to-end:
`config.batch_max_jobs_per_firmware` → `BATCH_MAX_JOBS_PER_FIRMWARE` env →
backend module → root `batch_max_jobs_per_firmware` var + tfvars.example.
`batch:ListJobs` was already in the task role. 6 unit tests
(`tests/test_compute_dispatch.py`, fake Batch client); suite green.

**4d — CloudWatch observability. ✅ DONE 2026-06-11.** New `modules/observability`:
an SNS alarm topic (optional `alarm_email` subscription), 8 alarms — ECS CPU +
no-running-tasks (ContainerInsights `RunningTaskCount`), ALB unhealthy-hosts /
target-5XX / latency, Aurora CPU, Redis memory, and a backend-log
`ERROR/CRITICAL/Traceback` metric-filter error-rate alarm — plus a single
dashboard (ECS CPU/mem + tasks, ALB requests/5xx/latency/healthy-hosts, Aurora
CPU/ACU/connections, Redis CPU/mem/connections). Wired from new module outputs
(ALB+TG arn_suffix, Aurora `cluster_identifier`, Redis member `cache_cluster_id`,
backend log group). Root `alarm_email` var + `dashboard_name`/`alarm_topic_arn`
outputs. Batch has no native CloudWatch metrics → observed via its job log group,
documented, not alarmed. `terraform validate` + `plan` clean (92 resources, +11).

**4e — Slim backend image (fact #9). ✅ DONE + locally validated 2026-06-11.**
`backend/Dockerfile` is now multi-stage with two runnable targets sharing a
`base` stage: **`backend`** (slim, no Ghidra/JDK — the Fargate serving image,
which dispatches Ghidra to Batch and never runs it) and **`ghidra`** (full;
the DEFAULT/last stage, so a bare `docker build`/docker-compose and the Batch
worker get Ghidra unchanged). `build-and-push-backend.sh` now builds
`--target backend` → backend repo and `--target ghidra` → ghidra repo (the
shared `base` is cached between them) — replacing 4a's build-once-push-twice.
**Measured: slim 1.35 GB vs full 3.07 GB (−1.72 GB, −56%)** → much faster ECS
cold-start pulls. Validated: both targets build; slim has no `/opt/ghidra`,
imports `app.main` under `COMPUTE_BACKEND=aws_batch`, keeps the extraction
toolchain (binwalk/sasquatch/7z) for unpack; default (no-target) build still has
Ghidra + `analyzeHeadless` (compose path unchanged).

**4f — Runbook + cost estimate (DoD). ✅ DONE 2026-06-11.** `docs/RUNBOOK.md`
(prereqs, deploy incl. the 4a/4e build automation, first-user creation, operate,
troubleshoot table, teardown incl. the BucketNotEmpty recovery) and
`docs/COST.md`. Cost finding: the early ~$35–75/mo figure under-counted — the **8
interface VPC endpoints dominate at-rest (~$117/mo, billed per-AZ × 2)** and
always-warm Aurora is ~$45, so defaults are **~$220/mo at rest**; documented
levers (`create_nat_gateway=true` −~$84, `aurora_min_capacity=0` −~$45) reach
~$90/mo. Batch stays usage-based (~$0.01–0.10/job, $0 at rest). Cold-start
(~1–3 min first decompile from Batch scale-from-0) documented in the runbook.
Teardown verified clean in the 4b apply (81 destroyed, nothing billable left).

**4g — Custom domain + OIDC auth (SSO-ready). ✅ DONE + live-validated
2026-06-11.** Optional, flag-gated (`domain_name`/`route53_zone_id`,
`auth_enabled`; empty = today's open, CloudFront-domain behavior). Chosen
**app-level OIDC/JWT over ALB `authenticate-cognito`** because the latter does
302 full-page redirects that fight a SPA's XHR API calls, and app-level is
IdP-agnostic + needs no topology change (CloudFront stays the front door).
- **Backend:** `app/auth/oidc.py` — a JWKS-cached RS256 verifier (PyJWT) gating
  the HTTP API via middleware when `auth_enabled`; off by default so compose +
  the suite stay open. Audience matched against `aud` *or* (Cognito) `client_id`,
  so it's IdP-neutral. MCP unaffected (direct service calls); WS (out-of-scope
  emulation/uart) not gated — documented. 12 unit tests.
- **Frontend:** runtime `/config.json` (built-once SPA reads OIDC settings at
  startup; default `authEnabled:false`); `oidc-client-ts` Authorization Code +
  PKCE login via the Cognito hosted UI; Bearer attached in the axios interceptor;
  401 → re-login.
- **Terraform:** `domain.tf` — ACM cert (us-east-1 provider) DNS-validated in the
  operator's zone + Route53 alias to CloudFront; frontend `aliases`+cert wired.
  Cognito client switched to a **public PKCE client (no secret)**; callbacks keyed
  off the input `domain_name` (a localhost dev fallback) to avoid a
  backend→auth→frontend→backend cycle; `auth_enabled` requires `domain_name`
  (precondition). Backend gets `AUTH_ENABLED`/`OIDC_ISSUER`/`OIDC_AUDIENCE`;
  `deploy-spa.sh` emits the real `config.json`.
- **SSO:** Cognito is the federation broker — an operator adds a SAML/OIDC IdP
  (JumpCloud/Okta) to the pool and lists it in the auth module's
  `identity_providers`; the SPA login flow is unchanged. See
  [[wairz-enterprise-sso-requirement]].
- **Bug found + fixed live:** the private-subnet backend (no NAT) couldn't reach
  the Cognito JWKS (`cognito-idp.<region>.amazonaws.com`), so a valid token hung
  → CloudFront 504. Fix: add a **`cognito-idp` interface VPC endpoint** when auth
  is on and no NAT (AZ-filtered — the service isn't in every AZ; private DNS still
  serves the VPC) + a 5 s JWKS-fetch timeout so failures are a fast 401, not 504.
- **Live-validated on `wairz.digitalandrew.io`:** cert issued, DNS resolved, SPA
  200 on the custom domain, `config.json` correct, API no-token → 401, garbage
  token → 401, **real Cognito access token → 200** (JWKS fetched via the
  endpoint, RS256 + iss + audience validated). Torn down clean.

**Phase 4 is complete** (4a image/SPA delivery, 4b migration guard, 4c
concurrency cap, 4d observability, 4e slim image, 4f docs, 4g custom domain +
OIDC auth). Putting the pool behind a *specific* external IdP (the actual
JumpCloud/Okta federation config) is the only remaining auth follow-up — the
seam is in place (`identity_providers`).

### Phase 5 — Remote MCP (cloud-usable AI path) — ✅ DONE + LIVE-VALIDATED

**Status (2026-06-12):** app layer (5a/5b/5c) **code-complete + unit-tested**
(`backend/tests/test_mcp_http.py`, 7 tests) AND infra wired + **live-validated on
`wairz.digitalandrew.io/mcp` then torn down clean**. The cloud deploy is now
genuinely usable by Claude over HTTP — `mcp_http_enabled = true` runs the
Streamable HTTP MCP server as a sidecar and routes `/mcp` to it, Cognito-gated.
See "Progress" + "Live validation" below.

**The gap.** Phases 1–4 made the *web SPA* cloud-native and Cognito-gated, but
they did **not** make the **MCP path** — the actual way Claude drives Wairz —
work in the cloud. The MCP server is **stdio-only** (`mcp_server.py:30,941`) and
connects **directly to Aurora** (`create_async_engine`/`async_sessionmaker`,
`mcp_server.py:424`) and **directly to the firmware files** (sandbox-validated
against `extracted_path`), *not* through the HTTP API. In the cloud, Aurora is in
a **private subnet** and the extracted firmware lives on **EFS**, so a laptop
running `wairz-mcp` against `wairz.example.com` can reach **neither**. CloudFront
+ Cognito gate the SPA; they do nothing for MCP, because MCP never traverses that
front door. The auth work deliberately left it alone ("MCP unaffected — direct
service calls", §6/Phase 4g).

**Consequence today.** The only way to drive a cloud instance with Claude is to
run the stdio MCP **inside the VPC** — `aws ecs execute-command` into the backend
task (it already mounts EFS and holds the DB URL) and run `wairz-mcp` there. That
"SSH-in" model is a single process with a single project context and no clean
multi-user story. **The cloud deployment is therefore not genuinely usable via
MCP yet** — this is the most important remaining gap for the cloud version.

**Target design.** Co-locate an MCP endpoint **with the backend** (already in the
VPC with EFS + Aurora) and expose it as a **Streamable HTTP MCP transport**,
routed through CloudFront/ALB at `/mcp`, gated by the **same Cognito JWT
verifier** that guards the REST API (`app/auth/oidc.py`). Claude Code/Desktop
then connects to a URL with a bearer token — no SSH, no VPN, riding the existing
auth and front door. No data-plane change: the in-VPC process keeps its direct
DB + EFS access; only the *transport* and *session model* change.

**Work items (each a genuine change — not just flipping a flag):**

| # | Item | Where | Notes |
|---|---|---|---|
| **5a** | **HTTP transport** — serve the existing `ToolRegistry` over the MCP SDK's Streamable HTTP server instead of `stdio_server()`. Run it in/alongside the backend task (sidecar container or an `/mcp` route on the FastAPI app). | `app/mcp_server.py`, `app/main.py`, `modules/backend` (task def + ALB/CloudFront `/mcp` behavior) | Keep stdio as the default for local/Desktop; HTTP is the cloud opt-in. |
| **5b** | **Per-session `ProjectState`** — today `switch_project` mutates a **process-global** singleton (`mcp_server.py`). Fine for one stdio process per user; with one HTTP endpoint serving many users it lets them stomp each other's active project. Key state off the MCP session id (`Mcp-Session-Id`). | `app/mcp_server.py` (`ProjectState` lifecycle), tool dispatch | The empty-state + `switch_project` model was built for many users on one server (§7) — this completes it for the HTTP transport. |
| **5c** | **Client-auth wiring** — map Claude Code's remote-MCP OAuth (or a static bearer) to a Cognito token; reuse the RS256 JWKS verifier. Reject unauthenticated `/mcp` exactly as the REST middleware does. | `app/auth/oidc.py` (reuse), `/mcp` guard, docs/RUNBOOK | Same IdP-agnostic posture; SSO federation (`identity_providers`) carries over for free. |

**Seams already friendly to this:** the JWT verifier exists and is transport-
agnostic; the backend task already has DB + EFS; the registry is a plain object
servable over any transport; `switch_project` + empty-state were designed for
multi-user. The work is real but contained to 5a–5c.

**Progress (2026-06-12) — application layer:**

- **5a HTTP transport — DONE (code).** `app/mcp_server.py` refactored: the build
  is split into `build_mcp_server()` (transport-agnostic — all tools/resources/
  prompts) + `run_server()` (stdio, unchanged behavior) + `build_http_app()`
  (Streamable HTTP via the SDK's `StreamableHTTPSessionManager`, stateful
  sessions). New CLI: `wairz-mcp --transport http [--host --port --path]`;
  stdio stays the default. **Decision: run HTTP as its own ASGI app (sidecar),
  not mounted into the FastAPI app** — the REST app's two `BaseHTTPMiddleware`
  guards (`origin_host_guard`, `auth_guard`) buffer responses and would stall
  MCP's SSE streams. A sidecar in the same ECS task shares the EFS mount, DB, and
  OIDC env, and ALB/CloudFront path-routes `/mcp` to its port. (Alternative —
  convert those guards to pure-ASGI middleware and mount in-process — left as a
  future option; the sidecar avoids touching reviewed REST code.)
- **5b Per-session `ProjectState` — DONE (code).** stdio keeps one shared
  preloaded state (byte-identical); HTTP keys a `ProjectState` off the
  per-session `ServerSession` via a `WeakKeyDictionary` (auto-evicted on
  disconnect — no leak). `switch_project`'s `send_tool_list_changed` targets
  only the calling session. Test proves two concurrent sessions hold distinct
  states and the map empties after both close.
- **5c Client-auth — DONE (code).** `build_http_app` gates the endpoint with the
  *same* `OIDCVerifier` (`app/auth/oidc.py`) as the REST API, via a pure-ASGI
  bearer check (no buffering): no/invalid token → 401, valid Cognito token →
  through. Off when `auth_enabled` is false (logs a loud warning). Tests cover
  all four cases.

**Infra wiring — DONE (2026-06-12).** All flag-gated behind `mcp_http_enabled`
(default false; the existing deploy is unchanged unless set):

1. **Sidecar** — second container `mcp` in the ECS task def runs `wairz-mcp
   --transport http` from the *same* image, sharing the EFS mounts + DB/Redis/
   OIDC env (env DRY'd into a `container_environment` local).
   `essential=false` so an MCP fault can't take down the REST API.
   `modules/backend`.
2. **Routing** — `aws_lb_target_group.mcp` (health-checks the sidecar's
   unauthenticated `/healthz`) + an ALB listener rule forwarding `/mcp`,`/mcp/*`
   to it; a second ECS-service `load_balancer` block registers the sidecar.
   CloudFront `/mcp*` behavior (uncached, all-viewer, `compress=false` for SSE).
   `modules/backend` + `modules/frontend`. `mcp_url` output.
3. **Client auth UX** — `docs/RUNBOOK.md` "Remote MCP" section: `.mcp.json`
   `type:http` + `Authorization: Bearer <cognito-token>`; copy the SPA's token
   or mint via the hosted UI/IdP.

**Bug found + fixed during validation:** `Mount("/mcp", …)` serves only `/mcp/`
and **307-redirects bare `/mcp` → `/mcp/`**; over the network the client drops
its `Authorization` header on that hop → 401. Fixed by routing in pure ASGI
(`Mount("/", dispatch)` + exact-path match) so `/mcp` is served directly, no
redirect — clients use the natural `…/mcp` URL.

**Live validation (2026-06-12, `wairz.digitalandrew.io/mcp`, torn down clean):**
auth gate (no token → 401, garbage → 401); authenticated `initialize` +
`list_tools` (67 kind-filtered tools) + `list_projects` (DB reached from the
sidecar) round-trip with a real Cognito access token; **two concurrent sessions
independent**. MCP TG `/healthz` healthy; SPA + REST API unaffected.

**Acceptance — met.** Local stdio MCP + the suite stay unchanged (HTTP is opt-in).

> Note the related but distinct **WebSocket** gap: emulation/terminal WS were
> hardened in the security review (§11) to require a token, but they remain
> out-of-scope features in the cloud build (no `docker.sock`/privileged worker in
> Fargate). Remote MCP does **not** depend on them.

---

## 7. Shared-team-instance requirements (don't forget)

This is a **multi-user** deployment (Cognito-fronted). Therefore:
- Backend is stateless and autoscaled (1..N) — all state in Aurora/Redis/EFS.
- The MCP empty-state + `switch_project` model already supports many users on
  one server; preserve it. **Caveat:** that holds per-*process* (one stdio MCP
  per user). The remote HTTP transport must move `ProjectState` to per-session —
  see Phase 5b — or concurrent users stomp each other's active project.
- **Job concurrency cap** at the `SubmitJob` site so one analyst can't saturate
  the Batch queue — ✅ DONE as a **per-firmware** cap (§4c), the identity
  available at every dispatch site; jobs tagged `wairz:firmware`. Per-*user*
  proper awaits the deferred ALB-Cognito identity.
- **Batch `maxvCpus` ceiling** so a runaway agent can't spin unbounded Spot —
  present (`batch_max_vcpus`, default 16).

---

## 8. Deferred features (leave clean seams)

| Feature | Why deferred | How it returns |
|---|---|---|
| **Fuzzing** | `docker.sock`; rare in cloud | Another Batch queue (Spot or on-demand). Reuses Phase 2 submit/poll/terminate machinery. Persist AFL++ sync dir to EFS for resume. `stop`→`TerminateJob`. |
| **Emulation** | `docker.sock`, privileged, **interactive** (multi-call live session) | On-demand EC2 worker the backend talks to over the private network instead of `docker exec`. One-time `binfmt_misc` registration at instance boot removes the per-session privileged need. Idle timeout (`emulation_timeout_minutes`) stops the instance. |
| **Carving** | `docker.sock`; on-demand | Either in-process in the backend (toolchain already present) or a short Batch job. |

Do **not** build these in the MVP. Just ensure C6 gates them off gracefully and
nothing in the IaC hard-codes their absence in a way that blocks adding them.

---

## 9. Guardrails for agents

- **Never break local `docker-compose`.** Every app-code change is config-gated
  with a `local` default. Run the existing suite with defaults before pushing.
- **Firmware storage stays a POSIX path (EFS).** Do not migrate `STORAGE_ROOT`
  to an S3-only abstraction (fact #8).
- **Keep the existing async job protocol.** Don't invent a new status pipeline;
  reuse `analysis_cache` / `ghidra_analysis_run` + the poll tools.
- **Secrets via Secrets Manager**, never in tfvars or task-def plaintext.
- **Everything scales to ~zero at rest.** If a design keeps EC2 running idle,
  justify it or make it a documented, opt-in tradeoff (e.g. `minvCpus=1`).
- **Each Terraform module is a black box** with typed vars/outputs; wire only
  through outputs.
- Work phase-by-phase; meet the DoD before advancing. Prefer small, reviewable
  commits scoped to one module or one app-code change.

## 10. Open decisions (resolve with the maintainer if blocked)

1. **Aurora min capacity:** 0.5 ACU (always-warm, ~$43/mo) vs 0 ACU auto-pause
   ($0 idle, ~15s cold resume). Default: **0.5 ACU** unless cost pressure.
2. **Frontend routing:** CloudFront multi-origin (A) vs nginx-on-Fargate (B).
   Default: **A**.
3. **NAT vs VPC endpoints:** NAT gateway (~$32/mo) vs interface/gateway endpoints
   for ECR/S3/Secrets/Logs (cheaper at rest). Default: **VPC endpoints** to hold
   the at-rest cost down.
4. **Remote state bootstrap:** ship local-state default + documented migration,
   or a bootstrap module for the S3/DynamoDB backend. Default: **documented
   migration**.

---

## 11. Security review (2026-06-11)

Reviewed the auth/domain work + serving layer; fixed and **live-validated** the
findings below (then torn down clean). Off-by-default auth means none of this
affects the local docker-compose deploy.

**Fixed:**
- **[CRITICAL] WebSocket auth bypass.** The http auth middleware can't see
  WebSockets, so with `auth_enabled` the terminal (`/api/.../terminal/ws`, which
  `fork`+`execve`'s a shell on the backend task) and the emulation terminal were
  reachable **unauthenticated** — a shell on the Fargate task exposes the
  `DATABASE_URL` env and the ECS task-role credentials. Fix: `authorize_websocket`
  validates a token (query param `access_token`, since browsers can't set WS
  headers) right after `accept()`, closing 4401 if missing/invalid; SPA passes the
  token on the WS URL. Validated live: no/garbage token → 4401, valid token →
  past-auth.
- **[HIGH] ALB open to the internet (CloudFront bypass).** The ALB SG allowed
  `0.0.0.0/0`, so it could be hit directly, bypassing CloudFront (and reaching the
  un-gated WS). Fix: ingress restricted to the `cloudfront.origin-facing` managed
  prefix list. Validated: direct ALB hit times out; via CloudFront → 200.
- **[MED] ID tokens accepted for API access.** The verifier didn't check
  `token_use`; a Cognito ID token would pass. Now rejects `token_use != access`
  (only when present, so still IdP-agnostic).
- **[LOW] Missing security headers / Cognito hardening.** Added a CloudFront
  response-headers policy (HSTS, X-Frame-Options DENY, nosniff, referrer-policy)
  and set the Cognito client `prevent_user_existence_errors=ENABLED` +
  `enable_token_revocation=true`.

**Open (judgement calls — left as-is, see follow-ups):** strict CSP (needs tuning
for Monaco/blob workers + Cognito); Cognito MFA / advanced-security (vs relying on
the federated IdP for MFA); SPA token storage in `localStorage` (XSS-exposed) vs
in-memory; Redis transit encryption + AUTH token (VPC-internal today); whether the
powerful in-firmware **terminal** (a real shell on the backend task, usable by any
authenticated team member) belongs in the cloud build at all.
