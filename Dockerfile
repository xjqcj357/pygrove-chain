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

# First boot inits if the data dir is empty. Self-mining is OFF by default — external
# miners (your laptop / GPU boxes) drive the chain forward. Set PYGROVE_SELF_MINE=1 on
# the container if you want the node to also mine (useful for solo dev loops, not for
# multi-miner devnets where node self-mining races external submissions).
ENTRYPOINT ["/bin/sh", "-c", "\
  if [ ! -s /var/lib/pygrove/chain.log ]; then \
    pygrove-node init --genesis /etc/pygrove/genesis.toml --data-dir /var/lib/pygrove; \
  fi; \
  if [ \"${PYGROVE_SELF_MINE:-0}\" = \"1\" ]; then \
    MINE_FLAG=--mine; \
  else \
    MINE_FLAG=; \
  fi; \
  exec pygrove-node run $MINE_FLAG \
    --genesis /etc/pygrove/genesis.toml \
    --data-dir /var/lib/pygrove \
    --rpc-bind 0.0.0.0:8545 \
"]
