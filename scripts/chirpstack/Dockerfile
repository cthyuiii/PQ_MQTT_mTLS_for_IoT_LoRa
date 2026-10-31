# ChirpStack built from our fork (network/chirpstack), for the Mac's Docker (linux/arm64; a Pi 5 the same way):
#   docker build -f scripts/chirpstack/Dockerfile -t iot-pqc/chirpstack:4.19.2-pq network/chirpstack
# The AES-128 one (the fork before AES-256: PQ TLS only), from a worktree at that commit:
#   git -C network/chirpstack worktree add --detach ../../build/chirpstack-aes128 b4d894d1
#   docker build -f scripts/chirpstack/Dockerfile -t iot-pqc/chirpstack:4.19.2-pq-aes128 build/chirpstack-aes128
# The stock image copies binaries cross-compiled outside Docker; this one builds the UI and the server inside it.
# Same runtime as the stock image: /usr/bin/chirpstack as nobody, configured with -c <dir>.

# Node 22: 25+ no longer ships corepack (26 fails at `corepack enable`, exit 127), and the UI needs it for pnpm
FROM node:22-bookworm AS ui
ARG TARGETARCH
# the UI's API client generator (ChirpStack's Nix shell provides it): grpc-web 2.0.2, as the UI's own grpc-web
RUN a=$([ "$TARGETARCH" = arm64 ] && echo aarch64 || echo x86_64) \
    && u=https://github.com/grpc/grpc-web/releases/download/2.0.2/protoc-gen-grpc-web-2.0.2-linux-$a \
    && curl -fsSL -o /usr/local/bin/protoc-gen-grpc-web $u \
    && echo "$(curl -fsSL $u.sha256 | cut -d' ' -f1)  /usr/local/bin/protoc-gen-grpc-web" | sha256sum -c \
    && chmod +x /usr/local/bin/protoc-gen-grpc-web
RUN corepack enable
WORKDIR /src
COPY api/proto api/proto
COPY api/grpc-web api/grpc-web
COPY ui ui
# grpc-tools downloads its own protoc while installing, and that download sometimes stalls: up to three tries
RUN cd api/grpc-web && (make || make || make) && cd ../../ui && make build

FROM rust:1.99-bookworm AS build
# cmake + clang: aws-lc-sys and librdkafka's C code; protoc: the API crates
RUN apt-get update && apt-get install -y --no-install-recommends cmake clang protobuf-compiler libprotobuf-dev
WORKDIR /src
COPY . .
COPY --from=ui /src/ui/build ui/build
RUN --mount=type=cache,target=/usr/local/cargo/registry --mount=type=cache,target=/src/target \
    cargo build --release -p chirpstack --no-default-features --features postgres \
    && cp target/release/chirpstack /chirpstack

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates
COPY --from=build /chirpstack /usr/bin/chirpstack
USER nobody:nogroup
ENTRYPOINT ["/usr/bin/chirpstack"]
