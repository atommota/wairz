# Multi-stage build with two runnable targets:
#
#   base    — shared: extraction toolchain, Python deps, app code. Not run directly.
#   backend — SLIM serving image (no Ghidra/JDK). Used by the enterprise Fargate
#             backend, which dispatches Ghidra to AWS Batch and never runs it
#             in-process. ~1 GB smaller → faster ECS cold-start image pulls.
#   ghidra  — FULL image: base + OpenJDK 21 + Ghidra. The DEFAULT (last) stage,
#             so `docker build`/docker-compose (local mode runs Ghidra in the
#             backend container) and the enterprise Batch worker get it unchanged.
#
# Enterprise builds target each explicitly (enterprise/scripts/build-and-push-
# backend.sh): `--target backend` → backend ECR repo, `--target ghidra` → ghidra
# ECR repo. A bare build (compose) falls through to the final `ghidra` stage.

FROM python:3.12-slim AS base

# Install system dependencies for firmware analysis
RUN apt-get update && apt-get install -y --no-install-recommends \
    binwalk \
    sleuthkit \
    squashfs-tools \
    cramfsswap \
    util-linux-extra \
    mtd-utils \
    e2fsprogs \
    cpio \
    p7zip-full \
    cabextract \
    lzop \
    srecord \
    file \
    libmagic1 \
    build-essential \
    git \
    zlib1g-dev \
    liblzma-dev \
    liblzo2-dev \
    wget \
    curl \
    unzip \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/* \
    && printf '#!/bin/sh\n# Wrapper: translates cramfsck -x <dir> <file> to fsck.cramfs --extract=<dir> <file>\nif [ "$1" = "-x" ]; then shift; dir="$1"; shift; exec fsck.cramfs --extract="$dir" "$@"; fi\nexec fsck.cramfs "$@"\n' > /usr/local/bin/cramfsck \
    && chmod +x /usr/local/bin/cramfsck

# Install Python-based firmware extraction tools used by binwalk
RUN pip3 install --no-cache-dir --break-system-packages \
    jefferson \
    ubi_reader \
    && pip3 install --no-cache-dir --break-system-packages \
       git+https://github.com/devttys0/yaffshiv.git 2>/dev/null \
    || echo "WARN: yaffshiv install failed — YAFFS extraction won't work"

# Install sasquatch for non-standard SquashFS (vendor-modified)
# Try the devttys0 fork first; patch out -Werror to handle newer compiler warnings
RUN git clone https://github.com/devttys0/sasquatch.git /tmp/sasquatch \
    && cd /tmp/sasquatch \
    && sed -i 's/-Werror//g' squashfs-tools/Makefile patches/*.patch 2>/dev/null \
    && sed -i 's/-Wall -Werror/-Wall/g' squashfs-tools/Makefile 2>/dev/null; \
    cd /tmp/sasquatch && ./build.sh 2>/dev/null \
    && cp /usr/local/bin/sasquatch /usr/local/bin/sasquatch 2>/dev/null; \
    rm -rf /tmp/sasquatch; \
    which sasquatch || echo "WARN: sasquatch build failed — non-standard SquashFS won't extract"

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Create non-root user and add to docker group for emulation container management.
# The docker socket GID from the host is passed via build arg (default 999).
ARG DOCKER_GID=999
RUN useradd -m -s /bin/bash wairz \
    && if getent group ${DOCKER_GID} >/dev/null; then \
         existing_group=$(getent group ${DOCKER_GID} | cut -d: -f1); \
         usermod -aG "${existing_group}" wairz; \
       else \
         groupadd -g ${DOCKER_GID} docker && usermod -aG docker wairz; \
       fi

# Set up working directory
WORKDIR /app

# Copy dependency files first for caching
COPY pyproject.toml uv.lock* ./

# Install dependencies
RUN uv sync --no-dev --no-editable 2>/dev/null || uv sync --no-editable

# Copy application code
COPY . .

# Bake in default emulation kernels so they're available out of the box.
# The docker-compose bind mount (./emulation/kernels:/opt/kernels) overlays
# on top at runtime, allowing users to add custom kernels.
COPY --from=kernels . /opt/kernels/

# Bake in the Ghidra headless scripts (AnalyzeBinary.java, DecompileFunction.java,
# ...). Locally these come via the compose bind mount (./ghidra/scripts:
# /opt/ghidra_scripts), but the cloud (Batch/Fargate) deployment has no bind
# mount — without baking them in, every analyzeHeadless -postScript fails.
COPY --from=ghidra_scripts . /opt/ghidra_scripts/

# Create data and Ghidra project directories.
# /data/ghidra_projects must exist (and be wairz-owned) in the image so that
# when the empty named volume is first mounted there, Docker seeds the volume
# with wairz ownership instead of defaulting the mountpoint to root:root —
# otherwise the backend (uid 1000) can't create the versioned project subdir.
RUN mkdir -p /data/firmware /data/ghidra_projects /tmp/ghidra_projects \
    && chown -R wairz:wairz /data /app /tmp/ghidra_projects /opt/kernels /opt/ghidra_scripts


# --- backend: slim serving image (no Ghidra/JDK), enterprise Fargate ---------
FROM base AS backend

USER wairz
EXPOSE 8000
CMD ["sh", "-c", "uv run alembic upgrade head && uv run uvicorn app.main:app --host 0.0.0.0 --port 8000"]


# --- ghidra: full image (base + OpenJDK 21 + Ghidra). DEFAULT stage. ---------
# Local docker-compose builds this (runs Ghidra in-process); enterprise pushes
# it to the Batch/Ghidra ECR repo.
FROM base AS ghidra

USER root

# Install OpenJDK 21 for Ghidra (JDK 17 not available in Trixie)
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-21-jdk-headless \
    && rm -rf /var/lib/apt/lists/*

# Install Ghidra
ARG GHIDRA_VERSION=11.3.1
ARG GHIDRA_DATE=20250219
RUN wget -q "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" \
        -O /tmp/ghidra.zip \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC /opt/ghidra \
    && rm /tmp/ghidra.zip

# Bump analyzeHeadless JVM tuning for large-binary analysis on modern
# hardware: raise heap from 2G -> 16G and drop the GC/JIT thread caps
# (-XX:ParallelGCThreads=2 -XX:CICompilerCount=2) that throttle Ghidra
# on >2-core hosts. iCamera-class binaries (~7 MB MIPS daemons) stall
# under the defaults; this unblocks them.
RUN sed -i 's/^MAXMEM=2G/MAXMEM=16G/' /opt/ghidra/support/analyzeHeadless \
    && sed -i 's/^VMARG_LIST="-XX:ParallelGCThreads=2 -XX:CICompilerCount=2 -Djava.awt.headless=true "/VMARG_LIST="-Djava.awt.headless=true "/' /opt/ghidra/support/analyzeHeadless \
    && grep -E '^MAXMEM=|^VMARG_LIST=' /opt/ghidra/support/analyzeHeadless

# Build Ghidra native components on ARM64 (decompiler, sleigh, demangler).
# The pre-built Ghidra release only ships x86_64 Linux binaries. On ARM64
# (e.g. Apple Silicon Macs running Docker), the decompiler is missing,
# breaking decompilation, dataflow tracing, and string ref resolution.
# The Gradle build system included in the distribution handles this.
RUN if [ "$(uname -m)" = "aarch64" ]; then \
        echo "ARM64 detected — building Ghidra native components..." \
        && apt-get update && apt-get install -y --no-install-recommends flex bison \
        && rm -rf /var/lib/apt/lists/* \
        && cd /opt/ghidra/support/gradle \
        && chmod +x gradlew \
        && JAVA_HOME=/usr/lib/jvm/java-21-openjdk-arm64 \
           ./gradlew buildNatives \
        && echo "Ghidra native build complete for ARM64"; \
    else \
        echo "x86_64 detected — using pre-built Ghidra natives"; \
    fi

RUN chown -R wairz:wairz /opt/ghidra

USER wairz

ENV GHIDRA_INSTALL_DIR=/opt/ghidra

EXPOSE 8000

CMD ["sh", "-c", "uv run alembic upgrade head && uv run uvicorn app.main:app --host 0.0.0.0 --port 8000"]
