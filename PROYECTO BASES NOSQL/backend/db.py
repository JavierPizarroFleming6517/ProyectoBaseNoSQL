import plyvel

# Crear o abrir la base de datos
db = plyvel.DB('/data/leveldb', create_if_missing=True)

def put(key, value):
    db.put(key.encode(), value.encode())

def get(key):
    result = db.get(key.encode())
    return result.decode() if result else None
