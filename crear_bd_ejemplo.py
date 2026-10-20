"""Crea una base de datos SQLite de ejemplo con visitas normales a una web ficticia.

Sirve para probar el analizador sin depender de ningún servidor real.
Después se pueden añadir ataques simulados con inyectar.py.

Uso:  python3 crear_bd_ejemplo.py
"""
import random
import sqlite3
from datetime import datetime, timedelta

from config import DB_PATH

# Páginas de una tienda online inventada
PAGINAS = [
    "/",
    "/index.php?page=home",
    "/index.php?page=productos",
    "/index.php?page=producto&id=12",
    "/index.php?page=producto&id=47",
    "/index.php?page=carrito",
    "/index.php?page=contacto",
    "/index.php?page=blog",
    "/index.php?page=blog&post=como-elegir-talla",
    "/buscar.php?q=zapatillas+running",
    "/buscar.php?q=camiseta+negra",
    "/img/logo.png",
    "/css/estilos.css",
    "/login.php",
]


def ip_aleatoria(rnd: random.Random) -> str:
    # Rangos privados y de documentación (RFC 1918 y RFC 5737): no son de nadie real.
    if rnd.random() < 0.5:
        return f"192.168.1.{rnd.randint(2, 60)}"
    return f"203.0.113.{rnd.randint(2, 250)}"


def main() -> None:
    rnd = random.Random(42)  # semilla fija: siempre se genera la misma base de datos
    conexion = sqlite3.connect(DB_PATH)
    cursor = conexion.cursor()

    cursor.execute("DROP TABLE IF EXISTS visitas")
    cursor.execute(
        """
        CREATE TABLE visitas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            ip TEXT NOT NULL,
            page TEXT NOT NULL,
            fecha TEXT,
            hora TEXT,
            fecha_hora TEXT
        )
        """
    )

    momento = datetime(2026, 6, 1, 9, 0, 0)
    for _ in range(40):
        momento += timedelta(minutes=rnd.randint(1, 20))
        cursor.execute(
            "INSERT INTO visitas (session_id, ip, page, fecha, hora, fecha_hora) VALUES (?, ?, ?, ?, ?, ?)",
            (
                f"s{rnd.randint(1000, 9999)}",
                ip_aleatoria(rnd),
                rnd.choice(PAGINAS),
                momento.strftime("%Y-%m-%d"),
                momento.strftime("%H:%M:%S"),
                momento.strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )

    conexion.commit()
    conexion.close()
    print(f"✅ Base de datos creada en {DB_PATH} con 40 visitas normales.")


if __name__ == "__main__":
    main()
