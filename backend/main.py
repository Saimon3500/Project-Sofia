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


class Producto(BaseModel):
    nombre: str


@app.get("/productos", response_model=list[Producto])
async def list_productos(client: MongoClientWrapper = Depends(get_mongo_client)):
    cursor = client.db["Productos Prueba"].find({})
    productos: list[Producto] = []
    async for item in cursor:
        # El usuario indicó que el campo se llama "PRODUCTO"
        nombre = item.get("PRODUCTO") or item.get("nombre") or item.get("Nombre") or "Sin Nombre"
        productos.append(Producto(nombre=nombre))
    async for item in cursor:
        # El usuario indicó que el campo se llama "PRODUCTO"
        nombre = item.get("PRODUCTO") or item.get("nombre") or item.get("Nombre") or "Sin Nombre"
        productos.append(Producto(nombre=nombre))
    return productos


class Lote(BaseModel):
    lote: str
    cantidad: float


class ProductoProcesado(BaseModel):
    nombre: str
    lotes: list[Lote]


class TrazabilidadRegistro(BaseModel):
    fechaRegistro: str
    productos: list[ProductoProcesado]
    nombreProductoDestino: str
    loteProductoDestino: str
    cantidadTotal: float
    registroNombre: Optional[str] = None
    registroCodigo: Optional[str] = None


@app.post("/trazabilidad", status_code=status.HTTP_201_CREATED)
async def create_trazabilidad(
    trazabilidad: TrazabilidadRegistro, client: MongoClientWrapper = Depends(get_mongo_client)
):
    # Convertir el modelo a dict
    data = trazabilidad.model_dump()
    # Agregar timestamp de creación
    data["created_at"] = datetime.utcnow()
    
    await client.db["Trazabilidad Guardados"].insert_one(data)
    return {"message": "Registro de trazabilidad guardado exitosamente", "id": str(data.get("_id"))}


@app.get("/trazabilidad")
async def list_trazabilidad(client: MongoClientWrapper = Depends(get_mongo_client)):
    cursor = client.db["Trazabilidad Guardados"].find({}).sort("created_at", -1)
    registros = []
    async for item in cursor:
        # Convertir _id ObjectId a string para el frontend
        item["_id"] = str(item["_id"])
        registros.append(item)
    return registros


class ObservacionItem(BaseModel):
    tipo: str
    cantidad: float


class LiberacionRegistro(BaseModel):
    fecha: str
    producto: str
    lote: str
    fecha_vencimiento: str
    observaciones_list: list[ObservacionItem] = []
    observaciones: str = ""
    # Campos antiguos para compatibilidad
    num_observacion: Optional[str] = None
    cantidad_verificada: Optional[float] = None


@app.post("/liberacion", status_code=status.HTTP_201_CREATED)
async def create_liberacion(
    registro: LiberacionRegistro, client: MongoClientWrapper = Depends(get_mongo_client)
):
    data = registro.model_dump()
    data["created_at"] = datetime.utcnow()
    await client.db["Liberacion Guardados"].insert_one(data)
    return {"message": "Registro de liberación guardado exitosamente", "id": str(data.get("_id"))}


@app.get("/liberacion")
async def list_liberacion(client: MongoClientWrapper = Depends(get_mongo_client)):
    cursor = client.db["Liberacion Guardados"].find({}).sort("created_at", -1)
    registros = []
    async for item in cursor:
        # Convertir _id ObjectId a string para el frontend
        item["_id"] = str(item["_id"])
        registros.append(item)
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


# --- Export Endpoints ---

import io
import pandas as pd
from fastapi.responses import StreamingResponse
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

class ExportRequest(BaseModel):
    ids: list[str]
    format: str  # "excel" or "pdf"


@app.post("/export/trazabilidad")
async def export_trazabilidad(
    request: ExportRequest, client: MongoClientWrapper = Depends(get_mongo_client)
):
    # Fetch records
    from bson import ObjectId
    object_ids = [ObjectId(id_) for id_ in request.ids]
    cursor = client.db["Trazabilidad Guardados"].find({"_id": {"$in": object_ids}})
    registros = []
    async for item in cursor:
        registros.append(item)

    if request.format == "excel":
        # Flatten data for Excel
        data = []
        for reg in registros:
            base_info = {
                "Fecha": reg.get("fechaRegistro"),
                "Producto Destino": reg.get("nombreProductoDestino"),
                "Lote Destino": reg.get("loteProductoDestino"),
                "Cantidad Total": reg.get("cantidadTotal"),
            }
            # Add reprocessed products as a string or multiple rows? 
            # For simplicity, let's create one row per reprocessed lot
            for prod in reg.get("productos", []):
                for lote in prod.get("lotes", []):
                    row = base_info.copy()
                    row.update({
                        "Producto Reprocesado": prod.get("nombre"),
                        "Lote Reprocesado": lote.get("lote"),
                        "Cantidad Reprocesada": lote.get("cantidad"),
                    })
                    data.append(row)
        
        df = pd.DataFrame(data)
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Trazabilidad')
        output.seek(0)
        
        return StreamingResponse(
            output,
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": "attachment; filename=trazabilidad.xlsx"}
        )

    elif request.format == "pdf":
        from reportlab.lib.units import inch
        from reportlab.pdfgen import canvas
        from datetime import datetime
        
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer, 
            pagesize=landscape(letter),
            leftMargin=0.5*inch,
            rightMargin=0.5*inch,
            topMargin=0.5*inch,
            bottomMargin=0.5*inch
        )
        elements = []
        styles = getSampleStyleSheet()
        
        # Estilo personalizado para el encabezado
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.enums import TA_LEFT, TA_RIGHT, TA_CENTER
        
        header_style = ParagraphStyle(
            'CustomHeader',
            parent=styles['Normal'],
            fontSize=10,
            leading=12,
        )
        
        # Crear encabezado SGD una sola vez al inicio
        fecha_hoy = datetime.now().strftime("%d/%m/%Y")
        
        # Usar la fecha del primer registro si existe
        if registros:
            fecha_registro = registros[0].get('fechaRegistro', fecha_hoy)
        else:
            fecha_registro = fecha_hoy
        
        header_data = [
            [
                Paragraph("<b><font size=24>SGD</font></b>", header_style),
                Paragraph("<b>Registro</b><br/>Trazabilidad de reproceso en producto procesado", header_style),
                Paragraph(f"Código: PO-PP-33<br/>rev. 00<br/>Fecha: {fecha_registro}", header_style)
            ]
        ]
        
        header_table = Table(header_data, colWidths=[1.5*inch, 5*inch, 2*inch])
        header_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (0, 0), 'LEFT'),
            ('ALIGN', (1, 0), (1, 0), 'CENTER'),
            ('ALIGN', (2, 0), (2, 0), 'RIGHT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('FONTNAME', (0, 0), (0, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (0, 0), 24),
        ]))
        
        elements.append(header_table)
        elements.append(Spacer(1, 0.2*inch))
        
        
        # Crear UNA SOLA tabla con todos los productos de todos los registros
        table_data = [
            [
                Paragraph("<b>FECHA</b>", header_style),
                Paragraph("<b>NOMBRE DEL PRODUCTO REPROCESADO</b>", header_style),
                Paragraph("<b>CANTIDAD DE PRODUCTO REPROCESADO (KG)</b>", header_style),
                Paragraph("<b>LOTE DEL PRODUCTO REPROCESADO</b>", header_style),
                Paragraph("<b>CANTIDAD TOTAL (KG)</b>", header_style),
                Paragraph("<b>LOTE DEL PRODUCTO (DESTINO)</b>", header_style),
                Paragraph("<b>NOMBRE DEL PRODUCTO (DESTINO)</b>", header_style),
            ]
        ]
        
        # Crear estilo para el contenido de las celdas (para nombres largos)
        cell_style = ParagraphStyle(
            'CellContent',
            parent=styles['Normal'],
            fontSize=9,
            leading=11,
            alignment=TA_LEFT
        )
        
        cell_style_center = ParagraphStyle(
            'CellContentCenter',
            parent=styles['Normal'],
            fontSize=9,
            leading=11,
            alignment=TA_CENTER
        )
        
        # Iterar sobre todos los registros y agregar sus productos a la misma tabla
        for reg in registros:
            productos_list = reg.get("productos", [])
            total_cantidad = reg.get("cantidadTotal", 0)
            lote_destino = reg.get("loteProductoDestino", "")
            nombre_destino = reg.get("nombreProductoDestino", "")
            fecha_registro = reg.get("fechaRegistro", "")
            
            primera_fila_del_registro = True
            for prod in productos_list:
                for lote in prod.get("lotes", []):
                    if primera_fila_del_registro:
                        # Primera fila del registro incluye cantidad total y producto destino
                        table_data.append([
                            Paragraph(fecha_registro, cell_style_center),
                            Paragraph(prod.get("nombre", ""), cell_style),
                            Paragraph(str(lote.get("cantidad", "")), cell_style_center),
                            Paragraph(lote.get("lote", ""), cell_style_center),
                            Paragraph(str(total_cantidad), cell_style_center),
                            Paragraph(lote_destino, cell_style_center),
                            Paragraph(nombre_destino, cell_style)
                        ])
                        primera_fila_del_registro = False
                    else:
                        # Filas subsecuentes solo tienen datos del producto reprocesado
                        table_data.append([
                            Paragraph(fecha_registro, cell_style_center),
                            Paragraph(prod.get("nombre", ""), cell_style),
                            Paragraph(str(lote.get("cantidad", "")), cell_style_center),
                            Paragraph(lote.get("lote", ""), cell_style_center),
                            "",
                            "",
                            ""
                        ])
        
        # Crear la tabla con anchos de columna apropiados (agregada columna de fecha)
        col_widths = [0.8*inch, 1.8*inch, 1.1*inch, 1.3*inch, 1*inch, 1.1*inch, 1.8*inch]
        
        main_table = Table(table_data, colWidths=col_widths)
        main_table.setStyle(TableStyle([
            # Encabezado
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E0E0E0')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 8),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('TOPPADDING', (0, 0), (-1, 0), 8),
            ('VALIGN', (0, 0), (-1, 0), 'MIDDLE'),
            
            # Contenido
            ('ALIGN', (0, 1), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('TOPPADDING', (0, 1), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 4),
            ('VALIGN', (0, 1), (-1, -1), 'MIDDLE'),
            
            # Bordes
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
            ('BOX', (0, 0), (-1, -1), 1, colors.black),
            
            # Alineación de texto en columnas de nombres (izquierda)
            ('ALIGN', (1, 1), (1, -1), 'LEFT'),
            ('ALIGN', (6, 1), (6, -1), 'LEFT'),
            
            # Padding horizontal
            ('LEFTPADDING', (0, 0), (-1, -1), 3),
            ('RIGHTPADDING', (0, 0), (-1, -1), 3),
        ]))
        
        elements.append(main_table)
        
        # Agregar espacio antes de la firma
        elements.append(Spacer(1, 0.4*inch))
        
        # Crear sección de firma
        signature_data = [
            [
                Paragraph("<b>Firma:</b> _______________________________", header_style),
                Paragraph("<b>Nombre:</b> _______________________________", header_style),
                Paragraph("<b>Fecha:</b> _______________________________", header_style)
            ]
        ]
        
        signature_table = Table(signature_data, colWidths=[2.8*inch, 2.8*inch, 2.8*inch])
        signature_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
        ]))
        
        elements.append(signature_table)

        doc.build(elements)
        buffer.seek(0)
        return StreamingResponse(
            buffer,
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=trazabilidad.pdf"}
        )


@app.post("/export/liberacion")
async def export_liberacion(
    request: ExportRequest, client: MongoClientWrapper = Depends(get_mongo_client)
):
    from bson import ObjectId
    object_ids = [ObjectId(id_) for id_ in request.ids]
    cursor = client.db["Liberacion Guardados"].find({"_id": {"$in": object_ids}})
    registros = []
    async for item in cursor:
        registros.append(item)

    if request.format == "excel":
        data = []
        for reg in registros:
            base_info = {
                "Fecha": reg.get("fecha"),
                "Producto": reg.get("producto"),
                "Lote": reg.get("lote"),
                "Vencimiento": reg.get("fecha_vencimiento"),
                "Notas": reg.get("observaciones"),
            }
            
            # Handle new list format
            if "observaciones_list" in reg and reg["observaciones_list"]:
                for obs in reg["observaciones_list"]:
                    row = base_info.copy()
                    row.update({
                        "Tipo Observación": obs.get("tipo"),
                        "Cantidad Verificada": obs.get("cantidad"),
                    })
                    data.append(row)
            # Handle legacy format
            elif "num_observacion" in reg:
                row = base_info.copy()
                row.update({
                    "Tipo Observación": reg.get("num_observacion"),
                    "Cantidad Verificada": reg.get("cantidad_verificada"),
                })
                data.append(row)
            else:
                # No observations
                data.append(base_info)

        df = pd.DataFrame(data)
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Liberacion')
        output.seek(0)
        
        return StreamingResponse(
            output,
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": "attachment; filename=liberacion.xlsx"}
        )

    elif request.format == "pdf":
        from reportlab.lib.units import inch
        from datetime import datetime
        
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer, 
            pagesize=landscape(letter),
            leftMargin=0.5*inch,
            rightMargin=0.5*inch,
            topMargin=0.5*inch,
            bottomMargin=0.5*inch
        )
        elements = []
        styles = getSampleStyleSheet()
        
        # Estilo personalizado para el encabezado
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.enums import TA_LEFT, TA_RIGHT, TA_CENTER
        
        header_style = ParagraphStyle(
            'CustomHeader',
            parent=styles['Normal'],
            fontSize=10,
            leading=12,
        )
        
        # Crear encabezado SGD una sola vez al inicio
        fecha_hoy = datetime.now().strftime("%d/%m/%Y")
        
        # Usar la fecha del primer registro si existe
        if registros:
            fecha_registro = registros[0].get('fecha', fecha_hoy)
        else:
            fecha_registro = fecha_hoy
        
        header_data = [
            [
                Paragraph("<b><font size=24>SGD</font></b>", header_style),
                Paragraph("<b>Registro</b><br/>Liberación de producto", header_style),
                Paragraph(f"Código: PO-PP-33-1<br/>rev. 00<br/>Fecha: {fecha_registro}", header_style)
            ]
        ]
        
        header_table = Table(header_data, colWidths=[1.5*inch, 5*inch, 2*inch])
        header_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (0, 0), 'LEFT'),
            ('ALIGN', (1, 0), (1, 0), 'CENTER'),
            ('ALIGN', (2, 0), (2, 0), 'RIGHT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('FONTNAME', (0, 0), (0, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (0, 0), 24),
        ]))
        
        elements.append(header_table)
        elements.append(Spacer(1, 0.2*inch))
        
        # Crear UNA SOLA tabla con todos los registros
        table_data = [
            [
                Paragraph("<b>FECHA</b>", header_style),
                Paragraph("<b>PRODUCTO</b>", header_style),
                Paragraph("<b>LOTE</b>", header_style),
                Paragraph("<b>VENCIMIENTO</b>", header_style),
                Paragraph("<b>OBSERVACIONES</b>", header_style),
                Paragraph("<b>NOTAS ADICIONALES</b>", header_style),
            ]
        ]
        
        # Crear estilo para el contenido de las celdas
        cell_style = ParagraphStyle(
            'CellContent',
            parent=styles['Normal'],
            fontSize=9,
            leading=11,
            alignment=TA_LEFT
        )
        
        cell_style_center = ParagraphStyle(
            'CellContentCenter',
            parent=styles['Normal'],
            fontSize=9,
            leading=11,
            alignment=TA_CENTER
        )
        
        # Iterar sobre todos los registros y agregar sus datos a la misma tabla
        for reg in registros:
            fecha = reg.get('fecha', '')
            producto = reg.get('producto', '')
            lote = reg.get('lote', '')
            vencimiento = reg.get('fecha_vencimiento', '')
            notas = reg.get('observaciones', '')
            
            # Procesar observaciones
            observaciones_list = reg.get('observaciones_list', [])
            
            if observaciones_list:
                # Si hay múltiples observaciones, crear una fila por cada una
                for idx, obs in enumerate(observaciones_list):
                    tipo_obs = obs.get('tipo', '')
                    cantidad_obs = obs.get('cantidad', '')
                    obs_text = f"{tipo_obs}: {cantidad_obs} kg"
                    
                    if idx == 0:
                        # Primera observación incluye todos los datos del registro
                        table_data.append([
                            Paragraph(fecha, cell_style_center),
                            Paragraph(producto, cell_style),
                            Paragraph(lote, cell_style_center),
                            Paragraph(vencimiento, cell_style_center),
                            Paragraph(obs_text, cell_style),
                            Paragraph(notas, cell_style)
                        ])
                    else:
                        # Observaciones subsecuentes solo muestran la observación
                        table_data.append([
                            "",
                            "",
                            "",
                            "",
                            Paragraph(obs_text, cell_style),
                            ""
                        ])
            elif "num_observacion" in reg:
                # Formato legacy
                tipo_obs = reg.get('num_observacion', '')
                cantidad_obs = reg.get('cantidad_verificada', '')
                obs_text = f"{tipo_obs}: {cantidad_obs} kg"
                
                table_data.append([
                    Paragraph(fecha, cell_style_center),
                    Paragraph(producto, cell_style),
                    Paragraph(lote, cell_style_center),
                    Paragraph(vencimiento, cell_style_center),
                    Paragraph(obs_text, cell_style),
                    Paragraph(notas, cell_style)
                ])
            else:
                # Sin observaciones
                table_data.append([
                    Paragraph(fecha, cell_style_center),
                    Paragraph(producto, cell_style),
                    Paragraph(lote, cell_style_center),
                    Paragraph(vencimiento, cell_style_center),
                    "",
                    Paragraph(notas, cell_style)
                ])
        
        # Crear la tabla con anchos de columna apropiados
        col_widths = [0.9*inch, 2*inch, 1*inch, 1*inch, 1.8*inch, 2.2*inch]
        
        main_table = Table(table_data, colWidths=col_widths)
        main_table.setStyle(TableStyle([
            # Encabezado
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E0E0E0')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 8),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('TOPPADDING', (0, 0), (-1, 0), 8),
            ('VALIGN', (0, 0), (-1, 0), 'MIDDLE'),
            
            # Contenido
            ('ALIGN', (0, 1), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('TOPPADDING', (0, 1), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 4),
            ('VALIGN', (0, 1), (-1, -1), 'MIDDLE'),
            
            # Bordes
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
            ('BOX', (0, 0), (-1, -1), 1, colors.black),
            
            # Alineación de texto en columnas de texto (izquierda)
            ('ALIGN', (1, 1), (1, -1), 'LEFT'),
            ('ALIGN', (4, 1), (4, -1), 'LEFT'),
            ('ALIGN', (5, 1), (5, -1), 'LEFT'),
            
            # Padding horizontal
            ('LEFTPADDING', (0, 0), (-1, -1), 3),
            ('RIGHTPADDING', (0, 0), (-1, -1), 3),
        ]))
        
        elements.append(main_table)
        
        # Agregar espacio antes de las firmas
        elements.append(Spacer(1, 0.4*inch))
        
        # Crear sección de firmas (2 firmas)
        signature_data = [
            [
                Paragraph("<b>Elaborado por:</b>", header_style),
                Paragraph("<b>Revisado por:</b>", header_style)
            ],
            [
                Paragraph("Firma: _______________________________", header_style),
                Paragraph("Firma: _______________________________", header_style)
            ],
            [
                Paragraph("Nombre: _____________________________", header_style),
                Paragraph("Nombre: _____________________________", header_style)
            ],
            [
                Paragraph("Fecha: _______________________________", header_style),
                Paragraph("Fecha: _______________________________", header_style)
            ]
        ]
        
        signature_table = Table(signature_data, colWidths=[4.2*inch, 4.2*inch])
        signature_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        
        elements.append(signature_table)

        doc.build(elements)
        buffer.seek(0)
        return StreamingResponse(
            buffer,
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=liberacion.pdf"}
        )

