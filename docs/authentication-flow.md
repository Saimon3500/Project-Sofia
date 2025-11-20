# Flujo de autenticación con MongoDB Atlas

## 1. Preparar la base de datos
1. Abre tu cluster en MongoDB Atlas.
2. Crea una base de datos (por ejemplo `sofia_app`) y dentro una colección `usuarios`.
3. Inserta un documento administrador:
   ```json
   {
     "usuario": "Admin",
     "passwordHash": "<hash-de-Admin123>",
     "rol": "administrador"
   }
   ```
4. (Opcional) Agrega más usuarios con sus roles correspondientes.

> **Nota:** nunca guardes contraseñas en texto plano; usa un hash con `bcrypt` u otra librería.

## 2. Backend (FastAPI)
1. Instala dependencias para hashing/autenticación:
   ```bash
   pip install passlib[bcrypt] python-jose[cryptography]
   ```
2. En `backend/main.py`:
   - Crea modelos `Usuario` y `LoginRequest`.
   - Implementa un servicio que:
     - Busque el usuario en `usuarios`.
     - Compare `passwordHash` usando `passlib`.
     - Genere un JWT simple (opcional; puedes responder solo con el rol).
   - Agrega un endpoint `POST /auth/login` que retorne `{ rol, token? }`.
3. Guarda el secreto para firmar tokens (por ejemplo `JWT_SECRET`) en `.env`.

## 3. Frontend (Expo / React Native)
1. Crea un archivo `.env` en `sofia-app` con la URL del backend:
   ```
   EXPO_PUBLIC_API_URL=http://127.0.0.1:8000
   ```
2. En la pantalla de login:
   - Reemplaza la validación local por una llamada `fetch` a `/auth/login`.
   - Si la respuesta es exitosa, guarda el rol en estado/contexto y navega a `Sectores`.
   - Maneja errores mostrando el mensaje devuelto por el backend.
3. (Opcional) Almacena el token/rol en `SecureStore` o AsyncStorage para mantener la sesión.

## 4. Pruebas
1. Levanta el backend (`uvicorn main:app --reload --port 8000`).
2. Ejecuta la app (`npm run web` o `expo start`).
3. Intenta iniciar sesión:
   - Con credenciales correctas: debería ingresar y mostrar los sectores.
   - Con credenciales incorrectas: debe mostrar el error del backend.
4. Verifica en Atlas que los usuarios existen y que los logs de acceso lucen correctos.

## 5. Seguridad y siguientes pasos
- Implementa HTTPS (por ejemplo, desplegando el backend en un servicio con TLS).
- Usa tokens con expiración y refresco si el proyecto crecerá.
- Crea endpoints protegidos que validen el rol antes de permitir acciones administrativas.

