import sys
from pathlib import Path
from getpass import getpass
from werkzeug.security import generate_password_hash, check_password_hash

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "Aplicacion")
)
from conexion import conectar

password = getpass("Escribe cualquier contraseña de prueba: ")
original = generate_password_hash(password)

with conectar() as conexion:
    cursor = conexion.cursor()
    cursor.execute(
        "CREATE TABLE #PruebaHash (HashGuardado NVARCHAR(255))"
    )
    cursor.execute(
        "INSERT INTO #PruebaHash (HashGuardado) VALUES (?)",
        original,
    )
    recuperado = cursor.execute(
        "SELECT HashGuardado FROM #PruebaHash"
    ).fetchone()[0]

print("Hash idéntico:", original == recuperado)
print("Contraseña válida:", check_password_hash(recuperado, password))