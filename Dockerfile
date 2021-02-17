FROM aquasec/trivy:latest as trivy
FROM containrrr/shoutrrr:latest as shoutrrr

FROM ekidd/rust-musl-builder:stable as builder


# Build a dummy app to cache cargo dependencies

RUN USER=rust cargo new --bin trivy-scheduler
WORKDIR ./trivy-scheduler

COPY Cargo.toml Cargo.lock ./
RUN cargo build --release

RUN rm src/*.rs


# Build the real application
COPY --chown=rust:rust . ./
RUN rm ./target/x86_64-unknown-linux-musl/release/deps/trivy_scheduler*

RUN cargo build --release


# Create the image
FROM scratch

COPY --from=trivy \
    /usr/local/bin/trivy /usr/local/bin/trivy

COPY --from=shoutrrr \
    /shoutrrr /usr/local/bin/shoutrrr

COPY --from=shoutrrr \
    /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

COPY --from=builder \
    /home/rust/src/trivy-scheduler/target/x86_64-unknown-linux-musl/release/trivy-scheduler \
    /usr/local/bin/trivy-scheduler

COPY templates/*.tpl /templates/


ENTRYPOINT ["trivy-scheduler"]
