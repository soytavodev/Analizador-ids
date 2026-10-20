import os

# El archivo .env es opcional: si python-dotenv está instalado, lo cargamos.
# Sin él, el programa funciona con los valores por defecto de abajo.
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

# Valores por defecto pensados para funcionar en local sin configurar nada
DB_PATH = os.getenv("DB_PATH", "./analytics.db")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434").rstrip("/")
MODELO = os.getenv("MODELO", "qwen2.5:3b")
