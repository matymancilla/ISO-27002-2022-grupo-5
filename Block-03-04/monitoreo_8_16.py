import psycopg

# Configuración de la conexión a la base de datos
DB_NAME = "nube_umg"
DB_USER = "postgres"
# ¡CAMBIA ESTO POR TU CONTRASEÑA REAL DE POSTGRESQL!
DB_PASS = "Admin123" 
DB_HOST = "localhost"
DB_PORT = "5433"

def analizar_logs():
    print("--- INICIANDO MONITOREO DE SEGURIDAD (Control 8.16) ---")
    try:
        # Conectar a la base de datos
        conn = psycopg.connect(
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASS,
            host=DB_HOST,
            port=DB_PORT
        )
        cursor = conn.cursor()

        # Consulta SQL para buscar el patrón: 3 o más accesos DENEGADOS desde la misma IP
        query = """
            SELECT source_ip, COUNT(*) as intentos_fallidos
            FROM access_logs
            WHERE access_decision = 'DENIED'
            GROUP BY source_ip
            HAVING COUNT(*) >= 3;
        """
        
        cursor.execute(query)
        resultados = cursor.fetchall()

        if resultados:
            print("\n[!] ALERTA DE SEGURIDAD DETECTADA:")
            for fila in resultados:
                ip = fila[0]
                intentos = fila[1]
                print(f" -> IP Sospechosa: {ip} | Intentos fallidos: {intentos}")
                print(" -> ACCIÓN RECOMENDADA: Bloquear IP en el Firewall y forzar reseteo de contraseña.")
        else:
            print("\n[OK] No se detectaron patrones anómalos.")

        cursor.close()
        conn.close()

    except Exception as e:
        print(f"Error de conexión: {e}")

if __name__ == "__main__":
    analizar_logs()
