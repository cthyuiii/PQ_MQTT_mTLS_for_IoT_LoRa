# The ChirpStack Gateway Bridge, unchanged, built with Go 1.27 (ML-DSA in crypto/tls and crypto/x509; finding 129):
#   docker build -t iot-pqc/gateway-bridge:4.1.2-go1.27 scripts/gateway-bridge
# The stock image is built with Go 1.26.5: X25519MLKEM768, but no ML-DSA. Go 1.27 reads ML-DSA private keys only in
# seed-only form (chirpstack_pq_setup.sh writes gateway.seed.key). Same runtime as the stock image.

FROM golang:1.27-alpine AS build
ARG VERSION=v4.1.2
RUN apk add --no-cache git
RUN git clone --depth 1 -b $VERSION https://github.com/chirpstack/chirpstack-gateway-bridge.git /src
WORKDIR /src
RUN CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$VERSION" -o /gwb cmd/chirpstack-gateway-bridge/main.go

FROM alpine:3.24.1
RUN apk --no-cache add ca-certificates
COPY --from=build /gwb /usr/bin/chirpstack-gateway-bridge
USER nobody:nogroup
ENTRYPOINT ["/usr/bin/chirpstack-gateway-bridge"]
