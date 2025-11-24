# Backend (FastAPI)

1. Crea un entorno virtual:
   ```bash
   cd backend
   python -m venv .venv
   .venv\Scripts\activate  # PowerShell
   pip install -r requirements.txt
   ```
2. Configura las variables de entorno (por ejemplo en un archivo `.env`):
   ```
   MONGODB_URI=mongodb+srv://a2022112041_db_user:<PASSWORD>@<CLUSTER>/sofia?retryWrites=true&w=majority&appName=sofia
   MONGODB_DB=sofia_app
   JWT_SECRET=<clave-secreta>
   JWT_ALGORITHM=HS256
   JWT_EXP_MINUTES=60
   DEFAULT_ADMIN_USER=Admin
   DEFAULT_ADMIN_PASSWORD=Admin123
   ```
3. Ejecuta el servidor:
   ```bash
   uvicorn main:app --reload --port 8000
   ``` 

Endpoints disponibles:
- `/health`: ping a MongoDB.
- `/auth/login`: autentica usuarios (se crea un administrador por defecto si no existe).
- `/registros`: listado y creación de registros para Formado.

