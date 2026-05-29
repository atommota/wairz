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
| C2 | Abstract Ghidra dispatch behind a strategy: `local` spawns the existing detached worker; `aws_batch` calls `batch:SubmitJob` | `app/services/ghidra_service.py` (dispatch site of `run_ghidra_analysis`) | The Batch job runs the **same** `python -m app.workers.run_ghidra_analysis ...` command in the backend/ghidra image |
| C3 | Move `_cross_process_analysis_lock` to a Redis-backed lock when `compute_backend != "local"` | `app/services/ghidra_service.py` | Use the existing `redis_url`; a simple `SET NX PX` lease + renewal is enough |
| C4 | Ensure `STORAGE_ROOT` works on EFS (no behavior change expected; verify no host-path assumptions) | `app/utils/sandbox.py`, storage paths | Mostly a verification task |
| C5 | Status mapping: `check_binary_analysis_status` should also reflect Batch job states (e.g. `SUBMITTED/RUNNABLE/STARTING` → "queued/starting") so a cold-start (1–3 min) reads correctly in the UI | `ghidra_service.py`, status tool | Optional polish; cache row remains source of truth on completion |
| C6 | Feature-flag the `docker.sock` features off in the cloud profile with a clear "run locally" message | `tools/{carving,fuzzing,emulation}.py` registration / capability gate | Avoids confusing errors on Fargate |

**Acceptance for the app-code layer:** with `compute_backend=local`, behavior is
byte-for-byte the current behavior (run the existing test suite). With
`compute_backend=aws_batch` + env pointing at a Batch queue + EFS, a
`start_binary_analysis` submits a Batch job, the job runs the worker, writes the
cache row, and `check_binary_analysis_status` transitions to complete.

> **Phase 2 finding (recorded during Phase 0 — do not miss this).** C2 as
> scoped only covers the **detached-worker** dispatch (`start_binary_analysis`
> / `start_function_decompile`, now routed through
> `app/services/compute_dispatch.py`). There is a **second, synchronous Ghidra
> path**: `run_ghidra_subprocess` in `ghidra_service.py`, called *inline*
> (MCP-bounded, `ghidra_timeout`) by `decompile_function`, `find_string_refs`,
> `get_stack_layout`, `get_global_layout`, and similar tools in `binary.py`.
> Those run Ghidra **in the backend process** and would (a) defeat the point of
> moving heavy compute off the backend and (b) hard-fail on a slim backend
> image that ships without Ghidra. Phase 2 must decide one of:
> 1. **Keep Ghidra in the backend image** for the synchronous fallback (simplest;
>    skip the slim-image optimization).
> 2. **Cache-only in cloud mode:** synchronous tools return "run
>    `start_binary_analysis` first" instead of analyzing inline when
>    `compute_backend != "local"` (forces the async/Batch path; cleanest split).
> 3. Route synchronous calls to Batch too (hard — they're interactive/bounded).
> Recommended default: **option 1** for the MVP, revisit option 2 with the
> slim-image work in Phase 4.

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
| `COMPUTE_BACKEND` (`compute_backend`) | `aws_batch` in cloud | new setting (C1) |
| `AWS_REGION` | provider region | |
| `BATCH_JOB_QUEUE` / `BATCH_JOB_DEFINITION` | `batch` module outputs | C2 |
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

### Phase 1 — State backbone (network, storage, db, cache)
- Implement `network`, `storage` (EFS + S3), `database` (Aurora SLv2), `cache`
  (Redis) modules.
- App-code **C3** (Redis lock) and **C4** (EFS path verification).
- **DoD:** `terraform apply` stands up VPC + EFS + Aurora + Redis; a throwaway
  EC2/ECS task can mount the EFS access point and connect to Aurora + Redis.

### Phase 2 — Ghidra on Batch
- Implement `batch` module (compute env `minvCpus=0`, Spot; job queue; job
  definition mounting EFS, running the Ghidra worker command).
- Build the Batch Ghidra image in `enterprise/docker/` (reuse `ghidra/` or the
  backend image; entrypoint = `python -m app.workers.run_ghidra_analysis`).
- Complete app-code **C2** (real `SubmitJob`) and **C5** (status mapping).
- **DoD:** with `compute_backend=aws_batch`, `start_binary_analysis` submits a
  job, Batch scales 0→1, the job decompiles a test binary, writes the cache row,
  scales back to 0, and `check_binary_analysis_status` reports complete. Verify
  Spot interruption mid-job → re-run completes (idempotency, fact #6).

### Phase 3 — Serving layer (backend, frontend, auth)
- Implement `backend` (ECR + Fargate + ALB + autoscaling), `frontend` (S3 +
  CloudFront), `auth` (Cognito) modules.
- App-code **C6** (gate `docker.sock` features off in cloud profile).
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
- Migration-on-boot race guard (fact #11): run alembic as a one-off ECS task in
  the apply, or a startup advisory lock.
- CloudWatch logs/dashboards, Batch `maxvCpus` ceiling (cost guardrail),
  per-user job concurrency cap (shared-instance fairness).
- Cold-start mitigation: ECR pull-through cache / slim image; document the
  ~1–3 min first-decompile latency and the `minvCpus=1` tradeoff.
- Optional: slim backend image (fact #9).
- **DoD:** documented runbook in `docs/`, cost estimate, teardown verified
  (`terraform destroy` leaves nothing billable).

---

## 7. Shared-team-instance requirements (don't forget)

This is a **multi-user** deployment (Cognito-fronted). Therefore:
- Backend is stateless and autoscaled (1..N) — all state in Aurora/Redis/EFS.
- The MCP empty-state + `switch_project` model already supports many users on
  one server; preserve it.
- **Per-user / per-project job concurrency cap** at the `SubmitJob` site so one
  analyst can't saturate the Batch queue. Tag jobs with user + project.
- **Batch `maxvCpus` ceiling** so a runaway agent can't spin unbounded Spot.

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
