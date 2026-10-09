# stunnel on Alpine 3.23: OpenSSL 3.5 does ML-DSA certificates and X25519MLKEM768 natively. The PQ TLS proxy in front
# of ChirpStack (scripts/chirpstack_pq_setup.sh) and of the Gateway Bridge (PQ=... scripts/setup_gateway_pi.sh).
FROM alpine:3.23
RUN apk add --no-cache stunnel
ENTRYPOINT ["stunnel"]
CMD ["/etc/stunnel/stunnel.conf"]
