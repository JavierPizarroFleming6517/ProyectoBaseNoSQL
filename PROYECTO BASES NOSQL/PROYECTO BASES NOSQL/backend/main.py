from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
import json
import bcrypt
from db import rocksdb_client

app = FastAPI()

# Ruta raíz para verificar el estado del servidor
@app.get("/")
async def root():
    return {"message": "Servidor FastAPI funcionando correctamente"}

# Modelo de datos de usuario
class Usuario(BaseModel):
    username: str
    password: str

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
    """Registrar un nuevo usuario en la base de datos clave-valor (Plyvel)"""
    user_key = f"user:{usuario.username}"
    if rocksdb_client.get(user_key.encode()):
        raise HTTPException(status_code=400, detail="Usuario ya existe")
    
    # Hashear la contraseña antes de almacenarla
    hashed_password = hash_password(usuario.password)
    user_data = {
        "username": usuario.username,
        "password": hashed_password
    }

    # Guardar usuario en la base de datos
    rocksdb_client.put(user_key.encode(), json.dumps(user_data).encode())
    return {"message": f"Usuario {usuario.username} registrado correctamente"}

# Endpoint para autenticar un usuario
@app.post("/login/")
async def login_usuario(usuario: Usuario):
    """Autenticar un usuario usando su nombre de usuario y contraseña"""
    user_key = f"user:{usuario.username}"
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
    if not rocksdb_client.get(user_key.encode()):
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    # Eliminar el usuario
    rocksdb_client.delete(user_key.encode())
    return {"message": f"Usuario {username} eliminado correctamente"}

# Endpoint para obtener los detalles de un usuario
@app.get("/getUser/{username}")
async def obtener_usuario(username: str):
    """Obtener los detalles de un usuario almacenado"""
    user_key = f"user:{username}"
    stored_data = rocksdb_client.get(user_key.encode())
    if not stored_data:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    user_data = json.loads(stored_data.decode())
    return user_data
