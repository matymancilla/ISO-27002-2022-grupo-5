import sys
from pathlib import Path
from getpass import getpass
from werkzeug.security import check_password_hash

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "Aplicacion")
)

from conexion import conectar

with conectar() as conexion:
    cursor = conexion.cursor()

    print("Base conectada:", cursor.execute(
        "SELECT DB_NAME()"
    ).fetchone()[0])

    usuario = cursor.execute(
        """
        SELECT PasswordHash
        FROM dbo.Usuarios
        WHERE NombreUsuario = ? AND Activo = 1
        """,
        "admin_lab",
    ).fetchone()

    if usuario is None:
        print("Usuario no encontrado en esta conexión.")
    else:
        password = getpass("Contraseña de admin_lab: ")
        coincide = check_password_hash(usuario.PasswordHash, password)
        print("Contraseña válida:", coincide)