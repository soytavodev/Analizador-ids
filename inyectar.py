import sqlite3
from config import DB_PATH

# Nos saltamos la web y vamos directos a la base de datos
conexion = sqlite3.connect(DB_PATH)
cursor = conexion.cursor()

ataques = [
    ("45.33.22.11", "/index.php?page=../../../../etc/passwd"),
    ("8.8.4.4", "/index.php?page=home' OR '1'='1"),
    ("2.2.2.2", "/index.php?page=<script>alert('hack')</script>")
]

print("💉 Inyectando firmas maliciosas en la base de datos...")

for ip, ruta in ataques:
    # Ojo con la inyección aquí, usamos parámetros (?) para evitar romper la propia base de datos
    cursor.execute('''
        INSERT INTO visitas (session_id, ip, page, fecha, hora, fecha_hora)
        VALUES ('simulacion_ataque', ?, ?, date('now'), time('now'), datetime('now'))
    ''', (ip, ruta))

conexion.commit()
conexion.close()

print("✅ 3 ataques inyectados con éxito!")
