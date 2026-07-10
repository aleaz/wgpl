# ==========================================
# Stage 1: Builder
# ==========================================
FROM ghcr.io/astral-sh/uv:python3.12-alpine AS builder

WORKDIR /build

COPY pyproject.toml README.md uv.lock ./
COPY src/ ./src/

RUN uv sync --frozen --no-dev \
 && uv build --wheel \
 && uv export --frozen --no-dev --no-emit-project -o requirements.txt

# ==========================================
# Stage 2: Runtime
# ==========================================
FROM python:3.12-alpine

LABEL org.opencontainers.image.source="https://github.com/aleaz/wgpl"
LABEL org.opencontainers.image.description="WireGuard Peer Lite (WGPL)"

RUN apk add --no-cache wireguard-tools iproute2

RUN addgroup -S wgpl && adduser -S -G wgpl -h /home/wgpl wgpl

WORKDIR /app

COPY --from=builder /build/dist/*.whl ./
COPY --from=builder /build/requirements.txt ./

RUN pip install --no-cache-dir --upgrade "pip>=26.1" \
 && pip install --no-cache-dir -r requirements.txt \
 && pip install --no-cache-dir --no-deps *.whl \
 && rm -f *.whl requirements.txt \
 && pip uninstall -y pip

VOLUME ["/data"]
ENV WGPL_DB_PATH=/data/wgpl.db
RUN mkdir -p /data && chown -R wgpl:wgpl /app /data

USER wgpl

ENTRYPOINT ["wgpl"]
