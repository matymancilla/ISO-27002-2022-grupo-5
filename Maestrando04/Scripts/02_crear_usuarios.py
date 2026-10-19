import sys
from pathlib import Path
from getpass import getpass

from werkzeug.security import generate_password_hash

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "Aplicacion")
)

from conexion import conectar


def crear_usuario(cursor, nombre, rol):
    existe = cursor.execute(
        "SELECT 1 FROM dbo.Usuarios WHERE NombreUsuario = ?",
        nombre,
    ).fetchone()

    if existe:
        print(f"{nombre}: ya existe.")
        return

    password = getpass(f"Contraseña para {nombre} (mínimo 12 caracteres): ")

    if len(password) < 12:
        raise ValueError("La contraseña debe tener al menos 12 caracteres.")

    cursor.execute(
        """
        INSERT INTO dbo.Usuarios (NombreUsuario, PasswordHash, Rol)
        VALUES (?, ?, ?)
        """,
        nombre,
        generate_password_hash(password),
        rol,
    )

    print(f"{nombre}: creado.")


with conectar() as conexion:
    cursor = conexion.cursor()
    crear_usuario(cursor, "admin_lab", "administrador")
    crear_usuario(cursor, "consulta_lab", "consulta")
    conexion.commit()