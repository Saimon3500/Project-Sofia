import os
from datetime import datetime, timedelta
from functools import lru_cache
from typing import Optional

import bcrypt
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field

load_dotenv()


class Settings(BaseModel):
    mongodb_uri: str = Field(..., alias="MONGODB_URI")
    database_name: str = Field("Sofia_App", alias="MONGODB_DB")
    jwt_secret: str = Field(..., alias="JWT_SECRET")
    jwt_algorithm: str = Field("HS256", alias="JWT_ALGORITHM")
    jwt_expiration_minutes: int = Field(60, alias="JWT_EXP_MINUTES")
    default_admin_user: str = Field("Admin", alias="DEFAULT_ADMIN_USER")
    default_admin_password: str = Field("Admin123", alias="DEFAULT_ADMIN_PASSWORD")


@lru_cache
def get_settings() -> Settings:
    try:
        return Settings(
            MONGODB_URI=os.getenv("MONGODB_URI"),
            MONGODB_DB=os.getenv("MONGODB_DB", "Sofia_App"),
            JWT_SECRET=os.getenv("JWT_SECRET"),
            JWT_ALGORITHM=os.getenv("JWT_ALGORITHM", "HS256"),
            JWT_EXP_MINUTES=int(os.getenv("JWT_EXP_MINUTES", "60")),
            DEFAULT_ADMIN_USER=os.getenv("DEFAULT_ADMIN_USER", "Admin"),
            DEFAULT_ADMIN_PASSWORD=os.getenv("DEFAULT_ADMIN_PASSWORD", "Admin123"),
        )
    except Exception as exc:
        raise RuntimeError("Configura las variables MONGODB_URI y MONGODB_DB") from exc


class MongoClientWrapper:
    def __init__(self, settings: Settings):
        self._client = AsyncIOMotorClient(settings.mongodb_uri)
        self._db = self._client[settings.database_name]

    @property
    def db(self):
        return self._db

    async def ping(self):
        await self._client.admin.command("ping")


def get_mongo_client(
    settings: Settings = Depends(get_settings),
) -> MongoClientWrapper:
    return MongoClientWrapper(settings)


class Registro(BaseModel):
    nombre: str
    codigo: str


class LoginRequest(BaseModel):
    usuario: str
    contrasena: str


class LoginResponse(BaseModel):
    rol: str
    access_token: str
    token_type: str = "bearer"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifica una contraseña contra su hash bcrypt."""
    if not hashed_password:
        return False
    try:
        # Asegurarse de que ambos sean bytes
        password_bytes = plain_password.encode('utf-8')
        if isinstance(hashed_password, str):
            hash_bytes = hashed_password.encode('utf-8')
        else:
            hash_bytes = hashed_password
        
        return bcrypt.checkpw(password_bytes, hash_bytes)
    except Exception as e:
        import logging
        logging.error(f"Error verificando contraseña: {e}")
        return False


def hash_password(password: str) -> str:
    """Genera un hash bcrypt de la contraseña."""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')


def create_access_token(data: dict, settings: Settings) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=settings.jwt_expiration_minutes)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.jwt_secret, algorithm=settings.jwt_algorithm)


app = FastAPI(title="Sofía API", version="0.1.0")

# Configurar CORS para permitir peticiones desde el frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # En producción, especifica los orígenes permitidos
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup_event():
    settings = get_settings()
    client = MongoClientWrapper(settings)
    try:
        await client.ping()
    except Exception as exc:
        raise RuntimeError("No se pudo conectar a MongoDB Atlas") from exc
    
    # Intentar crear el admin por defecto, pero no fallar si hay un error
    try:
        await ensure_default_admin(client, settings)
    except Exception as exc:
        import logging
        logging.warning(f"No se pudo crear el usuario admin por defecto: {exc}")


@app.get("/health")
async def health_check(client: MongoClientWrapper = Depends(get_mongo_client)):
    await client.ping()
    return {"status": "ok"}


@app.get("/registros", response_model=list[Registro])
async def list_registros(client: MongoClientWrapper = Depends(get_mongo_client)):
    cursor = client.db["registros"].find({})
    registros: list[Registro] = []
    async for item in cursor:
        registros.append(Registro(nombre=item.get("nombre", ""), codigo=item.get("codigo", "")))
    if not registros:
        registros.append(Registro(nombre="Trazabilidad", codigo="PO-PP-33"))
    return registros


@app.post("/registros", response_model=Registro, status_code=status.HTTP_201_CREATED)
async def create_registro(
    registro: Registro, client: MongoClientWrapper = Depends(get_mongo_client)
):
    existing = await client.db["registros"].find_one({"codigo": registro.codigo})
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Ya existe un registro con ese código",
        )
    await client.db["registros"].insert_one(registro.model_dump())
    return registro


async def ensure_default_admin(client: MongoClientWrapper, settings: Settings):
    """Crea el usuario administrador por defecto si no existe, o actualiza su hash si es necesario."""
    usuarios = client.db["usuarios"]
    existing = await usuarios.find_one({"usuario": settings.default_admin_user})
    
    if existing:
        # Verificar si el hash actual funciona, si no, actualizarlo
        stored_hash = existing.get("passwordHash", "")
        if stored_hash:
            # Intentar verificar con la contraseña por defecto
            if not verify_password(settings.default_admin_password, stored_hash):
                # El hash no funciona, regenerarlo
                new_hash = hash_password(settings.default_admin_password)
                await usuarios.update_one(
                    {"usuario": settings.default_admin_user},
                    {"$set": {"passwordHash": new_hash}}
                )
        return
    
    # El usuario no existe, crearlo
    try:
        hashed_password = hash_password(settings.default_admin_password)
        await usuarios.insert_one(
            {
                "usuario": settings.default_admin_user,
                "passwordHash": hashed_password,
                "rol": "administrador",
            }
        )
    except Exception as exc:
        # Si el usuario ya existe (duplicado) o hay otro error, simplemente ignorarlo
        # El usuario puede haber sido creado entre la verificación y la inserción
        pass


@app.post("/auth/login", response_model=LoginResponse)
async def login(
    credentials: LoginRequest, client: MongoClientWrapper = Depends(get_mongo_client)
):
    user = await client.db["usuarios"].find_one({"usuario": credentials.usuario})
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas.",
        )
    
    stored_hash = user.get("passwordHash", "")
    if not stored_hash:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas.",
        )
    
    # Verificar la contraseña
    password_valid = verify_password(credentials.contrasena, stored_hash)
    
    # Si la verificación falla y es el admin por defecto, intentar actualizar el hash
    if not password_valid and credentials.usuario == "Admin":
        settings = get_settings()
        if credentials.contrasena == settings.default_admin_password:
            # Regenerar el hash con el formato correcto
            new_hash = hash_password(credentials.contrasena)
            await client.db["usuarios"].update_one(
                {"usuario": credentials.usuario},
                {"$set": {"passwordHash": new_hash}}
            )
            password_valid = True
    
    if not password_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas.",
        )

    settings = get_settings()
    access_token = create_access_token(
        {"sub": credentials.usuario, "rol": user.get("rol", "usuario")}, settings
    )
    return LoginResponse(rol=user.get("rol", "usuario"), access_token=access_token)

