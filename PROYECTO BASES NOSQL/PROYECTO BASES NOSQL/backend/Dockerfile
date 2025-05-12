FROM python:3.8-slim

# Establecer el modo no interactivo
ENV DEBIAN_FRONTEND=noninteractive

# Instalar dependencias necesarias
RUN apt-get update && apt-get install -y \
    git \
    build-essential \
    g++ \
    cmake \
    libleveldb-dev \
    libsnappy-dev \
    zlib1g-dev \
    libbz2-dev \
    libgflags-dev \
    liblz4-dev \
    libzstd-dev \
    python3-dev \
    libboost-dev \
    libjemalloc-dev \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Crear el directorio para la base de datos
RUN mkdir -p /data/leveldb

WORKDIR /app

COPY requirements.txt .

# Actualizar pip e instalar dependencias
RUN pip install --upgrade pip setuptools wheel \
    && pip install --no-cache-dir -r requirements.txt

COPY . .

# Comando para iniciar el servidor
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
