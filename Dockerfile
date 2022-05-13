FROM rust:1.60.0 as builder
WORKDIR /usr/src/app
COPY ./  /usr/src/app

RUN cargo install --path .

FROM fedora:latest

COPY --from=builder /usr/local/cargo/bin/vault-sync /usr/local/bin/vault-sync
ENTRYPOINT ["/usr/local/bin/vault-sync"]
