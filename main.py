"""Analizador IDS: revisa los últimos accesos web guardados en SQLite y detecta posibles ataques.

Uso:
  python3 main.py                 # modo por reglas (no necesita IA ni librerías externas)
  python3 main.py --modo ia       # modo IA con Ollama en local
  python3 main.py --modo ambos    # los dos, y compara qué detecta cada uno
"""
import argparse
import json
import sqlite3
import sys

from config import DB_PATH, MODELO, OLLAMA_URL
from reglas import analizar_logs_reglas


def obtener_logs(limite=50):
    try:
        conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)  # solo lectura
        cursor = conn.cursor()
        cursor.execute("SELECT id, ip, page, fecha_hora FROM visitas ORDER BY id DESC LIMIT ?", (limite,))
        logs = cursor.fetchall()
        conn.close()
        return logs
    except sqlite3.Error as e:
        print(f"❌ Error al leer la base de datos {DB_PATH}: {e}")
        print("   ¿Has creado la base de datos de ejemplo con: python3 crear_bd_ejemplo.py?")
        return []


def analizar_logs_ia(logs_formateados, debug=False):
    # requests solo hace falta en el modo IA
    import requests

    prompt = f"""Actúa como un analista experto en ciberseguridad (Blue Team). Tu tarea es analizar un fragmento de logs de acceso web y detectar posibles intentos de ataque.

EJEMPLOS DE ENTRENAMIENTO:
- ENTRADA: "IP: 192.168.1.50 | RUTA: /index.php?page=home" -> CLASIFICACIÓN: Normal.
- ENTRADA: "IP: 198.51.100.11 | RUTA: /index.php?page=../../../etc/passwd" -> CLASIFICACIÓN: Ataque (Path Traversal).
- ENTRADA: "IP: 198.51.100.12 | RUTA: /?id=1' OR '1'='1" -> CLASIFICACIÓN: Ataque (SQL Injection).
- ENTRADA: "IP: 198.51.100.13 | RUTA: /wp-login.php" -> CLASIFICACIÓN: Sospechoso (Escaneo de bot buscando WordPress).
- ENTRADA: "IP: 198.51.100.14 | RUTA: /<script>alert(1)</script>" -> CLASIFICACIÓN: Ataque (XSS).

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

    # API estándar de Ollama: https://github.com/ollama/ollama/blob/main/docs/api.md
    payload = {
        "model": MODELO,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {"num_ctx": 4096, "temperature": 0.1},
    }

    if debug:
        print(f"🤖 Consultando a {MODELO} en {OLLAMA_URL}...")

    try:
        respuesta = requests.post(f"{OLLAMA_URL}/api/generate", json=payload, timeout=900)
        respuesta.raise_for_status()
        texto_generado = respuesta.json().get("response", "").strip()

        if debug:
            print("\n--- 🕵️ DEBUG: RESPUESTA CRUDA DE LA IA ---")
            print(texto_generado)
            print("------------------------------------------\n")

        # Limpiamos el texto por si el modelo devuelve algo fuera del JSON
        inicio = texto_generado.find("{")
        fin = texto_generado.rfind("}") + 1
        if inicio != -1 and fin > inicio:
            texto_generado = texto_generado[inicio:fin]

        return json.loads(texto_generado)

    except requests.exceptions.ConnectionError:
        print(f"❌ No se pudo conectar con Ollama en {OLLAMA_URL}.")
        print(f"   ¿Está instalado y en marcha? Prueba: ollama pull {MODELO}")
        return None
    except requests.exceptions.Timeout:
        print("⏳ Timeout: la IA no respondió a tiempo.")
        return None
    except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
        print(f"❌ Error con la respuesta de la IA: {e}")
        return None


def analizar_por_lotes(logs, tam_lote, debug=False):
    """Envía los registros a la IA en grupos pequeños y junta los resultados.

    Un modelo pequeño se pierde con muchos registros en un mismo prompt, así que
    se analizan por lotes. Además se descarta cualquier amenaza cuyo id_log no
    esté en el lote enviado: el modelo a veces se inventa registros.
    """
    amenazas = []
    lotes = [logs[i:i + tam_lote] for i in range(0, len(logs), tam_lote)]
    for n, lote in enumerate(lotes, start=1):
        print(f"   Lote {n}/{len(lotes)}...")
        texto = "".join(f"[ID: {log[0]}] IP: {log[1]} | RUTA: {log[2]} | FECHA: {log[3]}\n" for log in lote)
        resultado = analizar_logs_ia(texto, debug=debug)
        if resultado is None:
            return None
        ids_lote = {log[0] for log in lote}
        for a in resultado.get("amenazas_detectadas", []):
            if a.get("id_log") in ids_lote:
                amenazas.append(a)
            elif debug:
                print(f"   Descartada: la IA devolvió un id_log que no estaba en el lote ({a.get('id_log')})")
    return {"analisis_completado": True, "amenazas_detectadas": amenazas}


def imprimir_reporte(titulo, resultado):
    print("\n" + "=" * 50)
    print(f"🚨 REPORTE DE SEGURIDAD · {titulo}")
    print("=" * 50)

    if not resultado:
        print("❌ El análisis falló o no se obtuvo respuesta.")
        return

    amenazas = resultado.get("amenazas_detectadas", [])
    if not amenazas:
        print("✅ Tráfico limpio. No se detectaron anomalías.")
        return

    print(f"⚠️ {len(amenazas)} amenazas detectadas:\n")
    for a in amenazas:
        print(f"🛑 IP          : {a.get('ip')}")
        print(f"📄 Log ID      : {a.get('id_log')}")
        print(f"🎯 Ruta        : {a.get('ruta_atacada')}")
        print(f"🔪 Tipo        : {a.get('tipo_ataque')}")
        print(f"🔥 Gravedad    : {a.get('gravedad')}")
        print(f"🛡️ Recomendado : {a.get('recomendacion')}")
        print("-" * 50)


def comparar(res_reglas, res_ia):
    ids_reglas = {a.get("id_log") for a in res_reglas.get("amenazas_detectadas", [])}
    ids_ia = {a.get("id_log") for a in (res_ia or {}).get("amenazas_detectadas", [])}
    print("\n" + "=" * 50)
    print("⚖️ COMPARACIÓN")
    print("=" * 50)
    print(f"Detectados por los dos : {sorted(ids_reglas & ids_ia)}")
    print(f"Solo por las reglas    : {sorted(ids_reglas - ids_ia)}")
    print(f"Solo por la IA         : {sorted(ids_ia - ids_reglas)}")


def main():
    parser = argparse.ArgumentParser(description="Analizador IDS: detecta ataques en logs de acceso web.")
    parser.add_argument("--modo", choices=["reglas", "ia", "ambos"], default="reglas")
    parser.add_argument("--limite", type=int, default=50, help="Número de registros recientes a analizar")
    parser.add_argument("--lote", type=int, default=8, help="Registros por consulta a la IA (los modelos pequeños fallan con muchos a la vez)")
    parser.add_argument("--debug", action="store_true", help="Muestra la respuesta cruda de la IA")
    args = parser.parse_args()

    print("🛡️ Iniciando Analizador IDS...")
    logs_crudos = obtener_logs(args.limite)
    if not logs_crudos:
        print("No hay logs registrados para analizar.")
        sys.exit(1)

    print(f"📊 Se extrajeron {len(logs_crudos)} registros.")

    res_reglas = res_ia = None
    if args.modo in ("reglas", "ambos"):
        res_reglas = analizar_logs_reglas(logs_crudos)
        imprimir_reporte("REGLAS", res_reglas)

    if args.modo in ("ia", "ambos"):
        res_ia = analizar_por_lotes(logs_crudos, args.lote, debug=args.debug)
        imprimir_reporte(f"IA ({MODELO})", res_ia)

    if args.modo == "ambos":
        comparar(res_reglas, res_ia)


if __name__ == "__main__":
    main()
