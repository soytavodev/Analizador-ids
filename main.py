import sqlite3
import requests
import json
import sys
from config import DB_PATH, OLLAMA_API_URL, MODELO, AI_USER, AI_PASS

def obtener_logs(limite=50):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT id, ip, page, fecha_hora FROM visitas ORDER BY id DESC LIMIT ?", (limite,))
        logs = cursor.fetchall()
        conn.close()
        return logs
    except Exception as e:
        print(f"❌ Error al conectar con la base de datos: {e}")
        return []

def analizar_logs_ia(logs_formateados):
    prompt = f"""Actúa como un analista experto en ciberseguridad (Blue Team). Tu tarea es analizar un fragmento de logs de acceso web y detectar posibles intentos de ataque.

EJEMPLOS DE ENTRENAMIENTO:
- ENTRADA: "IP: 192.168.1.50 | RUTA: /index.php?page=home" -> CLASIFICACIÓN: Normal.
- ENTRADA: "IP: 45.33.22.11 | RUTA: /index.php?page=../../../etc/passwd" -> CLASIFICACIÓN: Ataque (Path Traversal).
- ENTRADA: "IP: 8.8.4.4 | RUTA: /?id=1' OR '1'='1" -> CLASIFICACIÓN: Ataque (SQL Injection).
- ENTRADA: "IP: 10.0.0.5 | RUTA: /wp-login.php" -> CLASIFICACIÓN: Sospechoso (Escaneo de bot buscando WordPress).
- ENTRADA: "IP: 2.2.2.2 | RUTA: /<script>alert(1)</script>" -> CLASIFICACIÓN: Ataque (XSS).

INSTRUCCIONES:
Analiza los siguientes logs reales. Devuelve ÚNICAMENTE un JSON válido con las peticiones peligrosas o sospechosas.
Si todos los logs son tráfico normal, devuelve la lista "amenazas_detectadas" vacía.

ESTRUCTURA JSON ESPERADA:
{{
    "analisis_completado": true,
    "amenazas_detectadas": [
        {{
            "id_log": 123,
            "ip": "1.2.3.4",
            "ruta_atacada": "/ejemplo",
            "tipo_ataque": "SQL Injection",
            "gravedad": "Alta",
            "recomendacion": "Bloquear IP"
        }}
    ]
}}

LOGS A ANALIZAR:
{logs_formateados}
"""

    # Cargamos las credenciales desde el entorno, nunca hardcodeadas
    payload = {
        "user": AI_USER,
        "password": AI_PASS,
        "question": prompt,
        "model": MODELO,
        "stream": False,
        "format": "json",
        "options": {
            "num_ctx": 8192,
            "temperature": 0.1
        }
    }

    print("🤖 Analizando logs en el servidor remoto...")
    
    try:
        respuesta = requests.post(OLLAMA_API_URL, json=payload, timeout=300)
        respuesta.raise_for_status()
        
        datos_respuesta = respuesta.json()
        texto_generado = datos_respuesta.get("answer", "").strip()
        
        print("\n--- 🕵️ DEBUG: RESPUESTA CRUDA DE LA IA ---")
        print(texto_generado)
        print("------------------------------------------\n")
        
        # Limpiamos el texto por si el modelo devuelve markdown fuera del JSON
        inicio = texto_generado.find("{")
        fin = texto_generado.rfind("}") + 1
        
        if inicio != -1 and fin > inicio:
            texto_generado = texto_generado[inicio:fin]
            
        return json.loads(texto_generado)
        
    except requests.exceptions.Timeout:
        print("⏳ Timeout: El servidor IA no respondió a tiempo.")
        return None
    except Exception as e:
        print(f"❌ Error de conexión con la IA: {e}")
        return None

def main():
    print("🛡️ Iniciando Analizador IDS Prototype...")
    
    logs_crudos = obtener_logs(50)
    
    if not logs_crudos:
        print("No hay logs registrados para analizar.")
        sys.exit(0)

    logs_texto = ""
    for log in logs_crudos:
        logs_texto += f"[ID: {log[0]}] IP: {log[1]} | RUTA: {log[2]} | FECHA: {log[3]}\n"
        
    print(f"📊 Se extrajeron {len(logs_crudos)} registros. Evaluando...")
    
    resultado = analizar_logs_ia(logs_texto)
    
    if resultado:
        amenazas = resultado.get("amenazas_detectadas", [])
        print("\n" + "=" * 50)
        print("🚨 REPORTE DE SEGURIDAD")
        print("=" * 50)
        
        if not amenazas:
            print("✅ Tráfico limpio. No se detectaron anomalías.")
        else:
            print(f"⚠️ ¡ATENCIÓN! {len(amenazas)} amenazas detectadas:\n")
            for a in amenazas:
                print(f"🛑 IP Atacante : {a.get('ip')}")
                print(f"📄 Log ID      : {a.get('id_log')}")
                print(f"🎯 Ruta atacada: {a.get('ruta_atacada')}")
                print(f"🔪 Tipo        : {a.get('tipo_ataque')}")
                print(f"🔥 Gravedad    : {a.get('gravedad')}")
                print(f"🛡️ Recomendado : {a.get('recomendacion')}")
                print("-" * 50)
    else:
        print("\n❌ El análisis falló o no se obtuvo respuesta.")

if __name__ == "__main__":
    main()
