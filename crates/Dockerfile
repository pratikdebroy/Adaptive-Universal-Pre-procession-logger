FROM rust:1.85-slim as builder

WORKDIR /usr/src/aegislog
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

RUN cargo build --release -p aegislog-server

FROM debian:bookworm-slim
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates sqlite3 curl && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/aegislog/target/release/aegislog-server /app/aegislog-server

EXPOSE 8080 5140/udp

ENV RUST_LOG=info
CMD ["/app/aegislog-server"]
