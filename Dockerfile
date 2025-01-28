# Multistage docker build, requires docker 17.05
# based on: https://github.com/mwcproject/mwc/blob/master/etc/Dockerfile

# Builder stage
FROM rust:latest as builder

RUN set -ex && \
    apt-get update && \
    apt-get --no-install-recommends --yes install \
    clang \
    libclang-dev \
    llvm-dev \
    libncurses5 \
    libncursesw5 \
    cmake \
    git

WORKDIR /usr/src

# Generate project placeholder
RUN USER=root cargo new --bin wallet713

WORKDIR /usr/src/wallet713

# Copy source
COPY ./src ./src

# Copy manifest
COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml

# Build dependencies
RUN cargo build --release
RUN rm ./src/*.rs
RUN rm -f ./target/release/deps/wallet713*

# Copy src
COPY ./src ./src

# Build
RUN cargo build --release

# Runtime stage
FROM debian:latest

RUN apt-get update && DEBIAN_FRONTEND=noninteractive \
	apt-get install -y ca-certificates locales openssl tor vim

RUN sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && \
    dpkg-reconfigure --frontend=noninteractive locales && \
    update-locale LANG=en_US.UTF-8

ENV LANG en_US.UTF-8

COPY --from=builder /usr/src/wallet713/target/release/mwc713 /usr/local/bin/wallet713

EXPOSE 3415 3420 13415 13420

ENTRYPOINT ["wallet713"]
