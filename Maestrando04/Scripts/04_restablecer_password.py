import sys
from pathlib import Path
from getpass import getpass
from werkzeug.security import generate_password_hash, check_password_hash

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "Aplicacion")
)

from conexion import conectar

password = getpass("Nueva contraseña de admin_lab: ")
confirmacion = getpass("Repetir contraseña: ")

if len(password) < 12:
    raise ValueError("Debe tener al menos 12 caracteres.")

if password != confirmacion:
    raise ValueError("Las contraseñas no coinciden.")

with conectar() as conexion:
    cursor = conexion.cursor()

    cursor.execute(
        """
        UPDATE dbo.Usuarios
        SET PasswordHash = ?
        WHERE NombreUsuario = ?
        """,
        generate_password_hash(password),
        "consulta_lab",
    )

    if cursor.rowcount != 1:
        conexion.rollback()
        raise ValueError("No se encontró una única cuenta admin_lab.")

    guardado = cursor.execute(
        "SELECT PasswordHash FROM dbo.Usuarios WHERE NombreUsuario = ?",
        "consulta_lab",
    ).fetchone()[0]

    if not check_password_hash(guardado, password):
        conexion.rollback()
        raise ValueError("Falló la validación del hash almacenado.")

    conexion.commit()

print("Contraseña actualizada y validada correctamente.")