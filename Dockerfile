FROM clux/muslrust:1.74.0 AS chef
USER root
RUN cargo install cargo-chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --target x86_64-unknown-linux-musl --recipe-path recipe.json
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl --bin rds_proxy

FROM alpine:3.18.5 AS runtime
RUN addgroup -S rdsproxy && adduser -S rdsproxy -G rdsproxy
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/rds_proxy /usr/local/bin/
USER rdsproxy
CMD ["/usr/local/bin/rds_proxy", "--config", "/etc/rds_proxy/config.json", "--listen", "0.0.0.0:5435"]
