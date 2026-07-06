# ==========================================
# Stage 1: Builder
# ==========================================
FROM ghcr.io/astral-sh/uv:python3.12-alpine AS builder

WORKDIR /build

# Copy only dependency metadata to maximize layer caching
COPY pyproject.toml README.md ./
COPY src/ ./src/

# Build the standard Python wheel using uv
RUN uv build --wheel

# ==========================================
# Stage 2: Runtime
# ==========================================
FROM python:3.12-alpine

# OCI labels for GHCR automatic linking
LABEL org.opencontainers.image.source="https://github.com/aleaz/wgpl"
LABEL org.opencontainers.image.description="WireGuard Peer Lite (WGPL)"

# Install wireguard-tools and essential networking utilities (iproute2)
RUN apk add --no-cache wireguard-tools iproute2

# Create an unprivileged runtime user.
RUN addgroup -S wgpl && adduser -S -G wgpl -h /home/wgpl wgpl

WORKDIR /app

# Copy ONLY the built wheel from the builder stage
COPY --from=builder /build/dist/*.whl ./

# Install the wheel directly and remove it to keep the layer small
RUN pip install --no-cache-dir *.whl && rm *.whl

# Configure the persistent data volume
VOLUME ["/data"]
ENV WGPL_DB_PATH=/data/wgpl.db
RUN chown -R wgpl:wgpl /app /data

USER wgpl

# Expose the CLI natively
ENTRYPOINT ["wgpl"]
