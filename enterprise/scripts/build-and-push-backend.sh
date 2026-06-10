#!/usr/bin/env bash
# Build the backend image once and push it to BOTH ECR repos (the Fargate
# backend repo and the Batch/Ghidra repo) under the same content-addressed tag.
# The image already bundles Ghidra + the worker code, so the two repos hold
# byte-identical images — we just tag and push twice (PLAN.md §4 / Phase 4 #1).
#
# Invoked by Terraform's null_resource.backend_image (local-exec). All inputs
# arrive via environment variables:
#   REPO_ROOT         absolute path to the repo root (contains backend/, ghidra/, emulation/)
#   AWS_REGION        region of the ECR registry
#   BACKEND_REPO_URL  <acct>.dkr.ecr.<region>.amazonaws.com/<name>-backend
#   GHIDRA_REPO_URL   <acct>.dkr.ecr.<region>.amazonaws.com/<name>-ghidra
#   IMAGE_TAG         tag to push (from image-tag.sh / var.image_tag)
set -euo pipefail

: "${REPO_ROOT:?}" "${AWS_REGION:?}" "${BACKEND_REPO_URL:?}" "${GHIDRA_REPO_URL:?}" "${IMAGE_TAG:?}"

# Both repos live in the same registry; one login covers both.
registry="${BACKEND_REPO_URL%%/*}"

echo "==> Logging in to ECR registry ${registry}"
aws ecr get-login-password --region "$AWS_REGION" \
  | docker login --username AWS --password-stdin "$registry"

# Build for linux/amd64 — Fargate tasks and the Batch EC2 fleet are x86_64, even
# when Terraform runs on an arm64 host (e.g. Apple Silicon). The Dockerfile pulls
# the emulation kernels and Ghidra headless scripts in via named build contexts
# (same wiring as docker-compose's additional_contexts); reproduce them here.
echo "==> Building backend image ${IMAGE_TAG} (linux/amd64) and pushing to both repos"
docker buildx build \
  --platform linux/amd64 \
  --build-context kernels="${REPO_ROOT}/emulation/kernels" \
  --build-context ghidra_scripts="${REPO_ROOT}/ghidra/scripts" \
  --tag "${BACKEND_REPO_URL}:${IMAGE_TAG}" \
  --tag "${GHIDRA_REPO_URL}:${IMAGE_TAG}" \
  --push \
  "${REPO_ROOT}/backend"

echo "==> Pushed ${BACKEND_REPO_URL}:${IMAGE_TAG}"
echo "==> Pushed ${GHIDRA_REPO_URL}:${IMAGE_TAG}"
