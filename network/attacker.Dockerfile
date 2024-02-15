FROM rust:alpine as builder

RUN apk update && apk add --no-cache musl-dev 

COPY src src

COPY Cargo.toml Cargo.toml

RUN cargo build

FROM debian:latest

# install bash nmap and ettercap
RUN apt-get update && apt-get install -y bash nmap ettercap-text-only lftp

#COPY --from=builder /target/release/inquisitor /usr/local/bin/inquisitor
COPY --from=builder /target/debug/inquisitor /usr/local/bin/inquisitor
CMD [ "tail", "-f", "/dev/null" ]