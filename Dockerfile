## Multi-stage build for pygrove-node.
##
## Stage 1: compile the node binary (+ cli) inside rust:slim with build deps.
## Stage 2: debian:trixie-slim runtime, copy just the binaries + genesis.toml.

# ---- build ------------------------------------------------------------------
FROM rust:1 AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang libclang-dev llvm-dev pkg-config build-essential \
    libfontconfig1-dev libxkbcommon-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# Build only what the container actually runs (node daemon + cli).
RUN cargo build --release --bin pygrove-node --bin pygrove-cli

# ---- runtime ----------------------------------------------------------------
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --home /var/lib/pygrove --create-home pygrove

COPY --from=build /src/target/release/pygrove-node /usr/local/bin/pygrove-node
COPY --from=build /src/target/release/pygrove-cli  /usr/local/bin/pygrove-cli
COPY --from=build /src/genesis.toml                /etc/pygrove/genesis.toml

VOLUME ["/var/lib/pygrove"]
EXPOSE 8545

USER pygrove
WORKDIR /var/lib/pygrove

# First boot inits if the data dir is empty, then runs with self-mine by default so the
# container keeps producing blocks until external miners attach.
ENTRYPOINT ["/bin/sh", "-c", "\
  if [ ! -s /var/lib/pygrove/chain.log ]; then \
    pygrove-node init --genesis /etc/pygrove/genesis.toml --data-dir /var/lib/pygrove; \
  fi; \
  exec pygrove-node run --mine \
    --genesis /etc/pygrove/genesis.toml \
    --data-dir /var/lib/pygrove \
    --rpc-bind 0.0.0.0:8545 \
"]
