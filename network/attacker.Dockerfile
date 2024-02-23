FROM rust:alpine as builder

RUN apk update && apk add --no-cache musl-dev 

COPY src src

COPY Cargo.toml Cargo.toml

RUN cargo build

FROM debian:latest

# install bash nmap and ettercap
RUN apt-get update && apt-get install -y bash nmap ettercap-text-only lftp

# create an alian for inquisitor
RUN echo "alias inquisitest='inquisitor 192.168.1.3 02:42:C0:A8:01:03 192.168.1.2 02:42:C0:A8:01:02 eth0'" >> ~/.bashrc

#COPY --from=builder /target/release/inquisitor /usr/local/bin/inquisitor
COPY --from=builder /target/debug/inquisitor /usr/local/bin/inquisitor
CMD [ "tail", "-f", "/dev/null" ]