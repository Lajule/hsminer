FROM debian:latest@sha256:00cd074b40c4d99ff0c24540bdde0533ca3791edcdac0de36d6b9fb3260d89e2
RUN apt update \
    && apt install -y wget xz-utils softhsm2 libssl-dev opensc \
    && wget -O /usr/local/zig-linux-x86_64-0.14.0.tar.xz https://ziglang.org/download/0.14.0/zig-linux-x86_64-0.14.0.tar.xz \
    && tar -C /usr/local -xf /usr/local/zig-linux-x86_64-0.14.0.tar.xz
ENV PATH="/usr/local/zig-linux-x86_64-0.14.0:$PATH"
