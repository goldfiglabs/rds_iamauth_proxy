FROM clux/muslrust:1.82.0-stable AS chef
USER root
RUN cargo install cargo-chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --target "$(arch)-unknown-linux-musl" --recipe-path recipe.json
COPY . .
RUN cargo build --release --target "$(arch)-unknown-linux-musl" --bin rds_proxy && \
    mv "target/$(arch)-unknown-linux-musl/release/rds_proxy" /rds_proxy

FROM alpine:3.18.5 AS runtime
RUN addgroup -S rdsproxy && adduser -S rdsproxy -G rdsproxy
COPY --from=builder /rds_proxy /usr/local/bin/
USER rdsproxy
CMD ["/usr/local/bin/rds_proxy", "--config", "/etc/rds_proxy/config.json", "--listen", "0.0.0.0:5435"]
