# Container image for supabase-dashboard.
#
# The release workflow builds this on native amd64 and arm64 runners and
# publishes it to ghcr.io/filipnone/supabase-dashboard, so a server only
# has to pull it. See docs/deployment.md.
#
#   docker build -t supabase-dashboard .

# Built on bookworm so the binary in the release tarball runs on glibc 2.36+.
FROM rust:1.98.0-slim-bookworm AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# Static cargo-leptos release binary, checked against the SHA-256 recorded
# here when the version was pinned. Bump all three together. cargo-leptos
# then downloads a matching wasm-bindgen CLI and wasm-opt during the build.
ARG CARGO_LEPTOS_VERSION=0.3.11
ARG CARGO_LEPTOS_SHA256_X86_64=149b88535fd8f44321da0d667fecc445c15af35f62931b2091687445297cc9e0
ARG CARGO_LEPTOS_SHA256_AARCH64=834d34b7bc837ed4bfdc5a26428f7c7b249550a5aecd5e6220b76b702008ab12
RUN set -eu; \
    arch="$(uname -m)"; \
    case "$arch" in \
      x86_64) sum="$CARGO_LEPTOS_SHA256_X86_64" ;; \
      aarch64) sum="$CARGO_LEPTOS_SHA256_AARCH64" ;; \
      *) echo "no cargo-leptos binary for $arch" >&2; exit 1 ;; \
    esac; \
    name="cargo-leptos-$arch-unknown-linux-musl"; \
    curl -fsSLo /tmp/cargo-leptos.tar.gz \
      "https://github.com/leptos-rs/cargo-leptos/releases/download/v${CARGO_LEPTOS_VERSION}/$name.tar.gz"; \
    echo "$sum  /tmp/cargo-leptos.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/cargo-leptos.tar.gz -C /tmp; \
    install -m 0755 "/tmp/$name/cargo-leptos" /usr/local/cargo/bin/cargo-leptos; \
    rm -rf /tmp/cargo-leptos.tar.gz "/tmp/$name"; \
    cargo leptos --version

WORKDIR /src
COPY rust-toolchain.toml ./
# Installs the pinned toolchain plus the wasm32 target it lists.
RUN rustup toolchain install

COPY . .
RUN cargo leptos build --release \
    && mkdir -p /out/site \
    && cp target/release/supabase-dashboard-server /out/ \
    && cp -r target/site/. /out/site/ \
    && cp LICENSE-MIT LICENSE-APACHE README.md /out/

# `docker build --target dist --output type=local,dest=dist .` exports the
# binary and site for the Linux release tarball.
FROM scratch AS dist
COPY --from=build /out/ /

FROM debian:trixie-slim AS runtime

# curl is only for the container health check.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 dashboard \
    && useradd --system --uid 10001 --gid dashboard --home-dir /app --no-create-home dashboard

WORKDIR /app
COPY --from=build /out/supabase-dashboard-server /usr/local/bin/supabase-dashboard-server
COPY --from=build /out/site /app/site
COPY --from=build /out/LICENSE-MIT /out/LICENSE-APACHE /app/

ENV LEPTOS_OUTPUT_NAME=supabase-dashboard \
    LEPTOS_SITE_ROOT=/app/site \
    LEPTOS_SITE_PKG_DIR=pkg \
    LEPTOS_SITE_ADDR=0.0.0.0:3000 \
    LEPTOS_ENV=PROD \
    LEPTOS_HASH_FILES=false

USER 10001:10001
EXPOSE 3000

HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
    CMD ["curl", "-fsS", "-o", "/dev/null", "http://127.0.0.1:3000/readyz"]

ENTRYPOINT ["supabase-dashboard-server"]
