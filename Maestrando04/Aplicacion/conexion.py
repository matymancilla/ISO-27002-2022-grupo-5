import os
import pyodbc
from dotenv import load_dotenv

load_dotenv()


def valor_odbc(valor):
    return "{" + valor.replace("}", "}}") + "}"


def conectar():
    return pyodbc.connect(
        "DRIVER={ODBC Driver 18 for SQL Server};"
        f"SERVER={valor_odbc(os.environ['DB_SERVER'])};"
        f"DATABASE={valor_odbc(os.environ['DB_NAME'])};"
        f"UID={valor_odbc(os.environ['DB_USER'])};"
        f"PWD={valor_odbc(os.environ['DB_PASSWORD'])};"
        "Encrypt=yes;"
        "TrustServerCertificate=yes;",
        timeout=5,
    )


if __name__ == "__main__":
    with conectar() as conexion:
        resultado = conexion.cursor().execute(
            "SELECT DB_NAME()"
        ).fetchone()
        print("Conexión correcta:", resultado[0])