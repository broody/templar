# Templar prover server image. Build from server/: docker build -f deploy/Dockerfile -t templar-prover .
# CPU sets the proving target: x86-64-v3 (portable, default) or native (~1.7x faster, host-bound).
ARG CPU=x86-64-v3

FROM rust:1.95-bookworm AS stable
ARG CPU
RUN apt-get update && apt-get install -y --no-install-recommends python3-venv clang pkg-config libssl-dev \
 && python3 -m venv /opt/cairo-lang && /opt/cairo-lang/bin/pip install --no-cache-dir cairo-lang==0.14.3a3
# The OS-program crate compiles the Cairo 0 virtual OS at build time with cairo-lang; the result
# must match the program hash the adapters pin (checked by templar-prover at startup).
ENV PATH=/opt/cairo-lang/bin:$PATH
WORKDIR /src
COPY os-runner os-runner
COPY prover prover
RUN cd os-runner && RUSTFLAGS="-C target-cpu=$CPU" cargo build --release --locked
RUN cd prover && cargo build --release --locked

FROM rust:1.95-bookworm AS nightly
ARG CPU
RUN rustup toolchain install nightly-2026-01-15 --profile minimal
WORKDIR /src
COPY prove prove
RUN cd prove && RUSTFLAGS="-C target-cpu=$CPU" cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates util-linux curl xz-utils \
 && curl -fsSL https://github.com/software-mansion/scarb/releases/download/v2.18.0/scarb-v2.18.0-x86_64-unknown-linux-gnu.tar.gz \
    | tar -xz -C /opt && ln -s /opt/scarb-v2.18.0-x86_64-unknown-linux-gnu/bin/scarb /usr/local/bin/scarb \
 && apt-get purge -y curl xz-utils && apt-get autoremove -y && rm -rf /var/lib/apt/lists/* \
 && useradd --system --home /var/lib/templar-prover --create-home templar
COPY --from=stable /src/os-runner/target/release/templar-os-runner /usr/local/bin/
COPY --from=stable /src/prover/target/release/templar-prover /usr/local/bin/
COPY --from=nightly /src/prove/target/release/templar-prove /usr/local/bin/
COPY deploy/entrypoint.sh /usr/local/bin/templar-entrypoint
EXPOSE 8480
ENTRYPOINT ["/usr/local/bin/templar-entrypoint"]
