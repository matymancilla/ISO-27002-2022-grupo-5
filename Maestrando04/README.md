# Laboratorio Maestrando 04

Aplicación académica desarrollada con Flask y SQL Server.

## Funciones

- Autenticación con contraseñas almacenadas como hash.
- Consulta de estudiantes mediante SQL parametrizado.
- Validación de entradas.
- Autorización por rol.
- Registro de eventos de seguridad.

## Preparación

1. Crear y activar un entorno virtual de Python.
2. Instalar dependencias con:
   python -m pip install -r requirements.txt
3. Instalar ODBC Driver 18 for SQL Server.
4. Ejecutar Scripts/01_crear_bd.sql en SQL Server.
5. Crear el archivo .env con:
   DB_SERVER, DB_NAME, DB_USER, DB_PASSWORD y FLASK_SECRET_KEY.
6. Ejecutar Scripts/02_crear_usuarios.py.
7. Iniciar la aplicación con:
   python Aplicacion/app.py
8. Abrir http://127.0.0.1:5000

## Datos

El laboratorio utiliza estudiantes y cuentas simulados. 

## Secretos

El archivo .env y sus valores no se incluyen en el repositorio.