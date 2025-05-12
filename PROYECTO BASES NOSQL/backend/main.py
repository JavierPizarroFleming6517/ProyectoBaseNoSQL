from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
import uuid
import json
import bcrypt
import rocksdb
from db import rocksdb_client  # Asegúrate de tener RocksDB configurado en db.py

app = FastAPI()

# Modelo de datos de usuario
class Usuario(BaseModel):
    username: str
    password: str  # La contraseña será almacenada de forma segura, es decir, en formato de hash

# Función para encriptar las contraseñas
def hash_password(password: str) -> str:
    """Genera un hash de la contraseña."""
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password.decode()

# Función para verificar el hash de la contraseña
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifica si la contraseña es válida comparando el hash."""
    return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())

# Endpoint para registrar un usuario
@app.post("/register/")
async def registrar_usuario(usuario: Usuario):
    """Registrar un nuevo usuario en la base de datos clave-valor (RocksDB)"""
    # Verificar si el usuario ya existe en RocksDB
    user_key = f"user:{usuario.username}"
    if rocksdb_client.get(user_key.encode()):
        raise HTTPException(status_code=400, detail="Usuario ya existe")
    
    # Hashear la contraseña antes de almacenarla
    hashed_password = hash_password(usuario.password)
    
    # Guardar usuario y contraseña en RocksDB
    user_data = {
        "username": usuario.username,
        "password": hashed_password
    }
    rocksdb_client.put(user_key.encode(), json.dumps(user_data).encode())

    return {"message": "Usuario registrado correctamente"}

# Endpoint para autenticar un usuario
@app.post("/login/")
async def login_usuario(usuario: Usuario):
    """Autenticar un usuario usando su nombre de usuario y contraseña"""
    user_key = f"user:{usuario.username}"
    
    # Obtener los datos del usuario desde RocksDB
    stored_data = rocksdb_client.get(user_key.encode())
    if not stored_data:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    user_data = json.loads(stored_data.decode())
    
    # Verificar si la contraseña es correcta
    if verify_password(usuario.password, user_data["password"]):
        return {"message": "Autenticación exitosa"}
    else:
        raise HTTPException(status_code=400, detail="Contraseña incorrecta")

# Endpoint para eliminar un usuario
@app.delete("/delete/{username}")
async def eliminar_usuario(username: str):
    """Eliminar un usuario de la base de datos"""
    user_key = f"user:{username}"
    
    # Verificar si el usuario existe
    if not rocksdb_client.get(user_key.encode()):
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    # Eliminar el usuario
    rocksdb_client.delete(user_key.encode())
    
    return {"message": "Usuario eliminado correctamente"}

# Endpoint para obtener los detalles de un usuario (opcional)
@app.get("/getUser/{username}")
async def obtener_usuario(username: str):
    """Obtener los detalles de un usuario almacenado"""
    user_key = f"user:{username}"
    
    # Obtener los datos del usuario
    stored_data = rocksdb_client.get(user_key.encode())
    if not stored_data:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    user_data = json.loads(stored_data.decode())
    return user_data
