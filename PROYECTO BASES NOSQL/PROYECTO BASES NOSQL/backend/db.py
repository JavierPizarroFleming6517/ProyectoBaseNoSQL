import plyvel
import os

# Asegurarse de que el directorio exista
os.makedirs('/data/leveldb', exist_ok=True)

# Crear o abrir la base de datos en modo de escritura
rocksdb_client = plyvel.DB('/data/leveldb', create_if_missing=True)
