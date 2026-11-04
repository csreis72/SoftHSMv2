# Multi - stage build : OpenSSL 3.5.7 + liboqs 0.15.0 + oqs-provider 0.11.0

# Stage 1 - deps de build compartilhadas
FROM ubuntu:24.04 AS builder-base

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential \
      cmake \
      ninja-build \
      perl \
      pkg-config \
      wget \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Stage 2 - compilar OpenSSL
FROM builder-base AS builder-openssl

ARG OPENSSL_VERSION=3.5.7

WORKDIR /build

RUN wget -q https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz

RUN tar xzf openssl-${OPENSSL_VERSION}.tar.gz && \
    cd openssl-${OPENSSL_VERSION} && \
    ./config \
      --prefix=/opt/openssl \
      --openssldir=/opt/openssl/etc/ssl \
      shared \
      no-tests \
    && make -j$(nproc) \
    && make install_sw install_ssldirs

# Stage 3 - compilar liboqs
FROM builder-base AS builder-liboqs

ARG LIBOQS_VERSION=0.15.0

COPY --from=builder-openssl /opt/openssl /opt/openssl

WORKDIR /build

RUN wget -q https://github.com/open-quantum-safe/liboqs/archive/refs/tags/${LIBOQS_VERSION}.tar.gz \
      -O liboqs-${LIBOQS_VERSION}.tar.gz

RUN tar xzf liboqs-${LIBOQS_VERSION}.tar.gz && \
    cmake -S liboqs-${LIBOQS_VERSION} -B liboqs-build \
      -GNinja \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=/opt/liboqs \
      -DBUILD_SHARED_LIBS=ON \
      -DOPENSSL_ROOT_DIR=/opt/openssl \
      -DOQS_ALGS_ENABLED=STD \
      -DOQS_DIST_BUILD=ON \
      -DOQS_BUILD_ONLY_LIB=ON \
    && cmake --build liboqs-build \
    && cmake --install liboqs-build

# Stage 4 - compilar oqs-provider
FROM builder-base AS builder-oqs

ARG OQSPROVIDER_VERSION=0.11.0

COPY --from=builder-openssl /opt/openssl /opt/openssl
COPY --from=builder-liboqs  /opt/liboqs  /opt/liboqs

WORKDIR /build

RUN wget -q https://github.com/open-quantum-safe/oqs-provider/archive/refs/tags/${OQSPROVIDER_VERSION}.tar.gz \
      -O oqs-provider-${OQSPROVIDER_VERSION}.tar.gz

RUN tar xzf oqs-provider-${OQSPROVIDER_VERSION}.tar.gz && \
    cmake -S oqs-provider-${OQSPROVIDER_VERSION} -B oqs-provider-build \
      -GNinja \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=/opt/openssl \
      -DOPENSSL_ROOT_DIR=/opt/openssl \
      -Dliboqs_DIR=/opt/liboqs/lib/cmake/liboqs \
      -DOQS_KEM_ENCODERS=ON \
    && cmake --build oqs-provider-build \
    && cmake --install oqs-provider-build

# Registra o oqs-provider no openssl.cnf
RUN printf '\n[provider_sect]\ndefault = default_sect\noqsprovider = oqsprovider_sect\n\n[oqsprovider_sect]\nactivate = 1\nmodule = /opt/openssl/lib64/ossl-modules/oqsprovider.so\n\n[default_sect]\nactivate = 1\n' \
      >> /opt/openssl/etc/ssl/openssl.cnf

RUN echo "/opt/openssl/lib64" > /etc/ld.so.conf.d/openssl.conf && \
    echo "/opt/liboqs/lib"    > /etc/ld.so.conf.d/liboqs.conf  && \
    ldconfig

ENV OPENSSL_CONF=/opt/openssl/etc/ssl/openssl.cnf

RUN /opt/openssl/bin/openssl version && \
    /opt/openssl/bin/openssl list -providers | grep -q oqsprovider && \
    echo "oqs-provider OK"

# Stage final - imagem de desenvolvimento
FROM builder-base AS dev

RUN apt-get update && apt-get install -y --no-install-recommends \
      libsqlite3-dev \
      sqlite3 \
      libcppunit-dev \
      gdb \
      opensc \
      autoconf \
      automake \
      libtool \
      libtool-bin \
      openjdk-21-jdk-headless \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder-oqs /opt/openssl /opt/openssl
COPY --from=builder-oqs /opt/liboqs  /opt/liboqs

RUN echo "/opt/openssl/lib64" > /etc/ld.so.conf.d/openssl.conf && \
    echo "/opt/liboqs/lib"    > /etc/ld.so.conf.d/liboqs.conf  && \
    ldconfig

RUN echo "directories.tokendir = /var/lib/softhsm/tokens" > /etc/softhsm2.conf && \
    echo "objectstore.backend = file" >> /etc/softhsm2.conf && \
    echo "log.level = INFO" >> /etc/softhsm2.conf

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENV LD_LIBRARY_PATH="/opt/openssl/lib64:/opt/liboqs/lib"
ENV PATH="/opt/softhsm2/bin:/opt/openssl/bin:${PATH}"
ENV OPENSSL_CONF="/opt/openssl/etc/ssl/openssl.cnf"
ENV SSL_CERT_FILE="/etc/ssl/certs/ca-certificates.crt"
ENV SSL_CERT_DIR="/etc/ssl/certs"
ENV OPENSSL_ROOT_DIR="/opt/openssl"
ENV PKG_CONFIG_PATH="/opt/openssl/lib64/pkgconfig:/opt/liboqs/lib/pkgconfig"
ENV SOFTHSM2_CONF="/etc/softhsm2.conf"

WORKDIR /src

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["/bin/bash"]
