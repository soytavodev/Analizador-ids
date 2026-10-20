"""Simulador de ataques (Red Team): escribe peticiones maliciosas en la tabla de visitas.

Uso:  python3 inyectar.py
"""
import sqlite3

from config import DB_PATH

# IPs de los rangos reservados para documentación (RFC 5737): no pertenecen a nadie real.
ATAQUES = [
    ("198.51.100.23", "/index.php?page=../../../../etc/passwd"),              # Path Traversal
    ("198.51.100.23", "/index.php?page=home' OR '1'='1"),                     # SQL Injection
    ("198.51.100.77", "/buscar.php?q=%27%20UNION%20SELECT%20user,password%20FROM%20users--"),  # SQLi codificada en la URL
    ("198.51.100.45", "/index.php?page=<script>alert('hack')</script>"),     # XSS
    ("198.51.100.90", "/wp-login.php"),                                       # Escaneo de bot (WordPress)
    ("198.51.100.90", "/.env"),                                               # Escaneo de bot (configuración)
    ("198.51.100.90", "/phpmyadmin/"),                                        # Escaneo de bot (panel de BD)
]


def main() -> None:
    # Nos saltamos la web y vamos directos a la base de datos
    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()

    print("💉 Inyectando peticiones maliciosas en la base de datos...")
    for ip, ruta in ATAQUES:
        # Usamos parámetros (?) para que el propio ataque no rompa nuestra consulta
        cursor.execute(
            """
            INSERT INTO visitas (session_id, ip, page, fecha, hora, fecha_hora)
            VALUES ('simulacion_ataque', ?, ?, date('now'), time('now'), datetime('now'))
            """,
            (ip, ruta),
        )

    conexion.commit()
    conexion.close()
    print(f"✅ {len(ATAQUES)} ataques inyectados.")


if __name__ == "__main__":
    main()
