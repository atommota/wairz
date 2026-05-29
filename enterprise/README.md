# Wairz Enterprise — Elastic AWS Deployment

This directory contains the **enterprise cloud deployment** of Wairz: an
elastic, mostly-serverless AWS architecture that runs the always-on serving
layer cheaply and bursts heavy compute (Ghidra decompilation) onto ephemeral,
scale-to-zero workers via **AWS Batch**.

It is a self-contained deployment target. Clone the repo, `cd enterprise`,
set your variables, and apply the Terraform.

> **Status:** all Terraform modules (network, storage, database, cache, batch,
> backend, frontend, auth) are authored and pass `terraform validate`; the
> backend app-code paths (Batch dispatch, Redis lock, cloud tool-gating) are
> implemented and the local path is verified unchanged. **Not yet apply-tested**
> against a live AWS account, and image build/push + SPA sync are not yet
> automated (Phase 4). See [`PLAN.md`](./PLAN.md) for per-phase status and the
> remaining operator/CI steps.

## Why this exists

The single-EC2 monolith forced an oversized instance: heavy Ghidra
decompilation runs *in the backend process* and contends with the lightweight
web serving. Most of the time Wairz just serves findings, reports, and agent
Q&A — needing almost nothing. This deployment splits the two:

- **Control plane** (always on, cheap): static SPA on S3/CloudFront, FastAPI on
  Fargate, Aurora Serverless v2 (scales toward zero), small ElastiCache, shared
  firmware storage on EFS.
- **Compute plane** (on demand, scales 0→N, Spot): Ghidra runs as an AWS Batch
  job, submitted by the backend and polled through the existing
  `ghidra_analysis_run` cache row. **$0 at rest.**

Fuzzing, emulation, and carving (the `docker.sock` features) are **out of scope
for the cloud MVP** and run in a local Wairz install. The architecture leaves
clean seams to add fuzzing (another Batch queue) and emulation (an on-demand
EC2 worker) later.

## Quickstart (target UX — not yet functional)

```bash
git clone <repo> && cd wairz/enterprise/terraform
cp terraform.tfvars.example terraform.tfvars
$EDITOR terraform.tfvars        # region, domain, sizing, secrets refs
terraform init
terraform apply
```

`terraform apply` builds and pushes the container images to ECR, provisions the
full stack, and outputs the CloudFront URL.

## Layout

```
enterprise/
├── README.md            # this file — operator-facing overview
├── PLAN.md              # detailed, phased build plan for agents (start here if building)
├── docs/                # architecture decision records, runbooks
├── docker/              # enterprise image overrides / entrypoints (Batch Ghidra, slim backend)
└── terraform/
    ├── *.tf             # root module: wires the modules together
    ├── terraform.tfvars.example
    └── modules/
        ├── network/     # VPC, subnets, security groups, VPC endpoints
        ├── storage/     # EFS (firmware), S3 (SPA + uploads)
        ├── database/    # Aurora Serverless v2 (PostgreSQL)
        ├── cache/       # ElastiCache (Redis — locks/coordination)
        ├── backend/     # ECR, ECS Fargate service, ALB
        ├── frontend/    # S3 + CloudFront for the SPA
        ├── batch/       # AWS Batch compute env + Ghidra job queue/definition
        └── auth/        # Cognito (shared multi-user instance)
```

## Relationship to the main app

This deployment requires a small set of **app-code changes** on the
`wairz_enterprise` branch (dispatching Ghidra to Batch, moving the analysis
lock to Redis, EFS-friendly storage). Those changes are listed in
[`PLAN.md`](./PLAN.md) and are gated behind config so the local
`docker-compose` workflow keeps working unchanged.
