import os
import secrets
from functools import wraps
import logging
from pathlib import Path
from logging.handlers import RotatingFileHandler


from flask import Flask, render_template, request, session, redirect, url_for
from werkzeug.security import check_password_hash

from conexion import conectar

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ["FLASK_SECRET_KEY"],
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

carpeta_logs = Path(__file__).resolve().parent.parent / "Logs"
carpeta_logs.mkdir(exist_ok=True)

logger = logging.getLogger("seguridad")
logger.setLevel(logging.INFO)
logger.propagate = False

if not logger.handlers:
    archivo = RotatingFileHandler(
        carpeta_logs / "seguridad.log",
        maxBytes=1_000_000,
        backupCount=3,
        encoding="utf-8",
    )

    archivo.setFormatter(logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s"
    ))

    logger.addHandler(archivo)

@app.route("/", methods=["GET", "POST"])
def login():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(32)

    error = None

    if request.method == "POST":
        if not secrets.compare_digest(
            session["csrf"], request.form.get("csrf", "")
        ):
            return "Solicitud inválida", 400

        usuario = request.form.get("usuario", "").strip()
        password = request.form.get("password", "")

        with conectar() as conexion:
            registro = conexion.cursor().execute(
                """
                SELECT UsuarioId, NombreUsuario, PasswordHash, Rol
                FROM dbo.Usuarios
                WHERE NombreUsuario = ? AND Activo = 1
                """,
                usuario,
            ).fetchone()

        if registro and check_password_hash(registro.PasswordHash, password):
            session.clear()
            session["usuario_id"] = registro.UsuarioId
            session["usuario"] = registro.NombreUsuario
            session["rol"] = registro.Rol

            logger.info(
                "LOGIN_CORRECTO usuario_id=%s",
                registro.UsuarioId,
            )

            return redirect(url_for("inicio"))
        
        logger.warning("LOGIN_FALLIDO")
        error = "Usuario o contraseña incorrectos."

    return render_template(
        "login.html", error=error, csrf=session["csrf"]
    )


@app.get("/inicio")
def inicio():
    if "usuario_id" not in session:
        return redirect(url_for("login"))

    return render_template(
        "inicio.html",
        usuario=session["usuario"],
        rol=session["rol"],
    )

@app.get("/estudiantes")
def estudiantes():
    if "usuario_id" not in session:
        return redirect(url_for("login"))

    identificador = request.args.get("id", "").strip()
    resultados = []
    error = None

    if identificador:
        if (
            not identificador.isascii()
            or not identificador.isdecimal()
            or len(identificador) > 10
            or not 1 <= int(identificador) <= 2147483647
        ):
            error = "Ingresa un identificador numérico válido."
        else:
            with conectar() as conexion:
                resultados = conexion.cursor().execute(
                    """
                    SELECT EstudianteId, Nombre, Carrera
                    FROM dbo.Estudiantes
                    WHERE EstudianteId = ?
                    """,
                    int(identificador),
                ).fetchall()

    return render_template(
        "estudiantes.html",
        resultados=resultados,
        identificador=identificador,
        error=error,
        busqueda=bool(identificador),
    )

@app.get("/administracion")
def administracion():
    if "usuario_id" not in session:
        logger.warning(
            "ACCESO_DENEGADO ruta=/administracion motivo=sin_sesion"
        )
        return redirect(url_for("login"))

    permitido = session.get("rol") == "administrador"

    if permitido:
        logger.info(
            "ACCESO_AUTORIZADO ruta=/administracion usuario_id=%s",
            session["usuario_id"],
        )
    else:
        logger.warning(
            "ACCESO_DENEGADO ruta=/administracion usuario_id=%s",
            session["usuario_id"],
        )

    return render_template(
        "administracion.html",
        permitido=permitido,
    ), 200 if permitido else 403

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)