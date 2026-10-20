"""Detección por reglas: busca patrones conocidos de ataque en la ruta de cada petición.

Es la forma clásica de trabajar de un IDS (por firmas). Es rápida y no necesita IA,
pero solo detecta lo que coincide con un patrón y no entiende el contexto.
"""
import re
from urllib.parse import unquote_plus

# (tipo de ataque, gravedad, recomendación, patrón)
FIRMAS = [
    ("Path Traversal", "Alta", "Bloquear IP y validar las rutas de archivo",
     re.compile(r"\.\./|\.\.\\|/etc/passwd|/etc/shadow", re.IGNORECASE)),
    ("SQL Injection", "Alta", "Bloquear IP y usar consultas preparadas",
     re.compile(r"'\s*(or|and)\s+'?\d*'?\s*=\s*'?\d|union\s+(all\s+)?select|;\s*drop\s+table|--\s*$|'\s*--", re.IGNORECASE)),
    ("XSS", "Alta", "Bloquear IP y escapar la salida HTML",
     re.compile(r"<\s*script|javascript:|on(error|load)\s*=|<\s*iframe", re.IGNORECASE)),
    ("Escaneo de bot", "Media", "Vigilar la IP y limitar peticiones",
     re.compile(r"wp-login\.php|wp-admin|phpmyadmin|/\.env\b|/\.git/|xmlrpc\.php", re.IGNORECASE)),
]


def clasificar(ruta: str):
    """Devuelve (tipo, gravedad, recomendación) si la ruta coincide con una firma, o None."""
    # Los atacantes suelen codificar la URL (%27 = ') para esquivar filtros: la decodificamos antes
    decodificada = unquote_plus(ruta)
    for tipo, gravedad, recomendacion, patron in FIRMAS:
        if patron.search(decodificada):
            return tipo, gravedad, recomendacion
    return None


def analizar_logs_reglas(logs):
    """Recibe filas (id, ip, page, fecha_hora) y devuelve el mismo formato de informe que la IA."""
    amenazas = []
    for id_log, ip, ruta, _fecha in logs:
        resultado = clasificar(ruta)
        if resultado:
            tipo, gravedad, recomendacion = resultado
            amenazas.append({
                "id_log": id_log,
                "ip": ip,
                "ruta_atacada": ruta,
                "tipo_ataque": tipo,
                "gravedad": gravedad,
                "recomendacion": recomendacion,
            })
    return {"analisis_completado": True, "amenazas_detectadas": amenazas}
