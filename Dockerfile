# syntax=docker/dockerfile:1.7

# The build uses the toolchain pinned in mise.toml (Rust, cargo-leptos, wasm-bindgen), like CI.
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS builder

ARG MISE_VERSION=2026.10.18
ARG TARGETARCH

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN case "$TARGETARCH" in \
        amd64) arch=x64 ;; \
        arm64) arch=arm64 ;; \
        *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && curl -fsSL "https://github.com/jdx/mise/releases/download/v${MISE_VERSION}/mise-v${MISE_VERSION}-linux-${arch}" \
        -o /usr/local/bin/mise \
    && chmod +x /usr/local/bin/mise

ENV MISE_ENV=ci \
    MISE_DATA_DIR=/opt/mise \
    MISE_YES=1 \
    PATH=/opt/mise/shims:$PATH \
    CARGO_HOME=/opt/cargo \
    CARGO_TERM_COLOR=never \
    CARGO_INCREMENTAL=0

WORKDIR /src

# Tools first, so they are cached until mise.toml changes.
COPY mise.toml mise.ci.toml ./
RUN mise trust --all && mise install

COPY . .
RUN --mount=type=cache,target=/opt/cargo/registry \
    --mount=type=cache,target=/opt/cargo/git \
    --mount=type=cache,target=/src/target,id=nanobom-target-${TARGETARCH} \
    mise run build \
    && mkdir -p /out/data \
    && cp target/release/nanobom /out/nanobom \
    && cp -r target/site /out/site

# The release archive's contents, exported with `--target artifact --output type=local`.
FROM scratch AS artifact
COPY --from=builder /out/nanobom /nanobom
COPY --from=builder /out/site /site

# Distroless: no shell or package manager; the binary runs as an unprivileged user.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f

LABEL org.opencontainers.image.title="nanobom" \
      org.opencontainers.image.description="A lightweight, self-hosted SBOM vulnerability tracker." \
      org.opencontainers.image.source="https://github.com/AlixANNERAUD/nanobom" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=builder /out/nanobom /app/nanobom
COPY --from=builder /out/site /app/site
COPY --from=builder --chown=65532:65532 /out/data /data

ENV NANOBOM_DATABASE_URL=sqlite:///data/nanobom.db \
    NANOBOM_LISTEN_ADDRESS=0.0.0.0:8080 \
    NANOBOM_SITE_ROOT=/app/site

USER 65532:65532
VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=6s --start-period=20s --retries=3 \
    CMD ["/app/nanobom", "healthcheck"]

ENTRYPOINT ["/app/nanobom"]
CMD ["serve"]
