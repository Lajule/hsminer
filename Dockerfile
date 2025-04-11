FROM debian
RUN apt update \
    && apt install -y wget xz-utils softhsm2 libssl-dev opensc \
    && wget -O /usr/local/zig-linux-x86_64-0.14.0.tar.xz https://ziglang.org/download/0.14.0/zig-linux-x86_64-0.14.0.tar.xz \
    && tar -C /usr/local -xf /usr/local/zig-linux-x86_64-0.14.0.tar.xz
ENV PATH="/usr/local/zig-linux-x86_64-0.14.0:$PATH"
