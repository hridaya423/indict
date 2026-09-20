# Self-contained: build context is the snare clone; the wrapper script
# and config are inlined (printf) so nothing outside the context is
# COPYed. Built via: docker build -f service/templates/snare/Dockerfile \
#   -t crs-svc-snare targets/snare
FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo "fn main() {}" > src/main.rs && \
    cargo build --release 2>/dev/null || true
COPY . .
RUN touch src/main.rs && cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/snare /usr/local/bin/snare
# per-repo "program" snare runs on valid webhooks — logs exec to /shared
RUN printf '#!/bin/sh\necho "executed event=$1 owner=$2 repo=$3 $(date -u +%%s)" >> /shared/ran.txt\n' \
        > /usr/local/bin/prp.sh && chmod +x /usr/local/bin/prp.sh
# harness config: known template secret so probes can exercise the HMAC
# gate; snare refuses to run as root without a user to drop to
RUN printf 'listen = "0.0.0.0:8011";\nuser = "nobody";\n\ngithub {\n  match ".*" {\n    cmd = "/usr/local/bin/prp.sh %%e %%o %%r";\n    secret = "crsknownsecret";\n  }\n}\n' \
        > /etc/snare.conf
EXPOSE 8011
ENTRYPOINT ["/usr/local/bin/snare", "-c", "/etc/snare.conf", "-d"]
