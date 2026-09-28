# syntax=docker/dockerfile:1
#
# cpuminer-multi in a container.
#
#   docker build -t cpuminer-multi .
#   docker run --rm cpuminer-multi -a sha256d -o stratum+tcp://POOL:PORT -u USER -p PASS
#
# The binary is built for the platform the image is built for (amd64 or
# arm64, e.g. with docker buildx --platform). For the fastest code on one
# machine, build there with: --build-arg CFLAGS="-O2 -march=native"

FROM ubuntu:24.04 AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        autoconf automake make gcc g++ libc6-dev pkg-config \
        libcurl4-openssl-dev libjansson-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
ARG CFLAGS="-O2"
RUN ./autogen.sh \
 && ./configure CFLAGS="$CFLAGS" CXXFLAGS="$CFLAGS" \
 && make -j"$(nproc)" \
 && make check \
 && strip minerd

FROM ubuntu:24.04
RUN apt-get update \
 && apt-get install -y --no-install-recommends libcurl4t64 libjansson4 libstdc++6 ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/minerd /usr/local/bin/minerd
USER nobody
ENTRYPOINT ["minerd"]
CMD ["--help"]
