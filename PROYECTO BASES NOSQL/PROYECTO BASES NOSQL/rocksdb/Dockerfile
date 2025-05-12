FROM ubuntu:20.04

# Evitar interacción al configurar el entorno
ENV DEBIAN_FRONTEND=noninteractive

# Instalar dependencias necesarias para compilar RocksDB
RUN apt-get update && apt-get install -y \
    git \
    build-essential \
    g++ \
    cmake \
    libsnappy-dev \
    zlib1g-dev \
    libbz2-dev \
    libgflags-dev \
    liblz4-dev \
    libzstd-dev \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Descargar y compilar RocksDB desde la fuente
RUN wget https://github.com/facebook/rocksdb/archive/refs/tags/v6.20.3.tar.gz && \
    tar -xzf v6.20.3.tar.gz && \
    cd rocksdb-6.20.3 && \
    CXXFLAGS="-fPIC" make static_lib && \
    CXXFLAGS="-fPIC" make install-shared && \
    make install && \
    ldconfig && \
    cd .. && \
    rm -rf rocksdb-6.20.3 v6.20.3.tar.gz

# Exponer el puerto (si se usa para algún servicio)
EXPOSE 8080

CMD ["sleep", "infinity"]
