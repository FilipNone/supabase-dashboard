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
# here when the version was pinned. Bump all three together. wasm-bindgen
# and wasm-opt are installed below so cargo-leptos does not download them
# during the build.
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
    curl -fsSL --retry 5 --retry-all-errors --retry-delay 5 -o /tmp/cargo-leptos.tar.gz \
      "https://github.com/leptos-rs/cargo-leptos/releases/download/v${CARGO_LEPTOS_VERSION}/$name.tar.gz"; \
    echo "$sum  /tmp/cargo-leptos.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/cargo-leptos.tar.gz -C /tmp; \
    install -m 0755 "/tmp/$name/cargo-leptos" /usr/local/cargo/bin/cargo-leptos; \
    rm -rf /tmp/cargo-leptos.tar.gz "/tmp/$name"; \
    cargo leptos --version

# cargo-leptos uses a wasm-bindgen found on PATH before downloading its own.
# Its own download for aarch64 needs glibc 2.38, newer than bookworm has, so
# install the static musl build instead. The version must match Cargo.lock;
# the build step below checks that.
ARG WASM_BINDGEN_VERSION=0.2.130
ARG WASM_BINDGEN_SHA256_X86_64=9687f3bb551b9f66f37ed32a40d7913a00f7962db653054e56857bc306c3227f
ARG WASM_BINDGEN_SHA256_AARCH64=99ffc93ce80081b91632e2b539b782821a8f3439ab0fddc645287462b2f55d3d
RUN set -eu; \
    arch="$(uname -m)"; \
    case "$arch" in \
      x86_64) sum="$WASM_BINDGEN_SHA256_X86_64" ;; \
      aarch64) sum="$WASM_BINDGEN_SHA256_AARCH64" ;; \
      *) echo "no wasm-bindgen binary for $arch" >&2; exit 1 ;; \
    esac; \
    name="wasm-bindgen-${WASM_BINDGEN_VERSION}-$arch-unknown-linux-musl"; \
    curl -fsSL --retry 5 --retry-all-errors --retry-delay 5 -o /tmp/wasm-bindgen.tar.gz \
      "https://github.com/wasm-bindgen/wasm-bindgen/releases/download/${WASM_BINDGEN_VERSION}/$name.tar.gz"; \
    echo "$sum  /tmp/wasm-bindgen.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/wasm-bindgen.tar.gz -C /tmp; \
    install -m 0755 "/tmp/$name/wasm-bindgen" /usr/local/cargo/bin/wasm-bindgen; \
    rm -rf /tmp/wasm-bindgen.tar.gz "/tmp/$name"; \
    wasm-bindgen --version

# wasm-opt from Binaryen, also used from PATH when present. Without it,
# cargo-leptos downloads Binaryen from GitHub on every release build, and
# a failed download fails the build. Checksums come from the .sha256 files
# published with the Binaryen release.
ARG BINARYEN_VERSION=123
ARG BINARYEN_SHA256_X86_64=e959f2170af4c20c552e9de3a0253704d6a9d2766e8fdb88e4d6ac4bae9388fe
ARG BINARYEN_SHA256_AARCH64=4b6bd61ba6cd3b18c993b4657d93426c782f9b91b74be0d38018cd8be1319376
RUN set -eu; \
    arch="$(uname -m)"; \
    case "$arch" in \
      x86_64) sum="$BINARYEN_SHA256_X86_64" ;; \
      aarch64) sum="$BINARYEN_SHA256_AARCH64" ;; \
      *) echo "no Binaryen build for $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL --retry 5 --retry-all-errors --retry-delay 5 -o /tmp/binaryen.tar.gz \
      "https://github.com/WebAssembly/binaryen/releases/download/version_${BINARYEN_VERSION}/binaryen-version_${BINARYEN_VERSION}-$arch-linux.tar.gz"; \
    echo "$sum  /tmp/binaryen.tar.gz" | sha256sum -c -; \
    mkdir -p /opt/binaryen; \
    tar -xzf /tmp/binaryen.tar.gz -C /opt/binaryen --strip-components=1; \
    ln -s /opt/binaryen/bin/wasm-opt /usr/local/cargo/bin/wasm-opt; \
    rm /tmp/binaryen.tar.gz; \
    wasm-opt --version

WORKDIR /src
COPY rust-toolchain.toml ./
# Installs the pinned toolchain plus the wasm32 target it lists.
RUN rustup toolchain install

COPY . .
RUN locked="$(grep -A1 '^name = "wasm-bindgen"$' Cargo.lock | sed -n 's/^version = "\(.*\)"$/\1/p')" \
    && if [ "$locked" != "$WASM_BINDGEN_VERSION" ]; then \
         echo "Cargo.lock has wasm-bindgen $locked; update WASM_BINDGEN_VERSION and its checksums" >&2; \
         exit 1; \
       fi \
    && cargo leptos build --release \
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
