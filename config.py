import os
from dotenv import load_dotenv

# Cargamos las variables ocultas del archivo .env
load_dotenv()

# Extraemos las variables, con valores por defecto por si falla algo
DB_PATH = os.getenv('DB_PATH', './analytics.db')
OLLAMA_API_URL = os.getenv('OLLAMA_API_URL', 'http://localhost:11434/api/')
MODELO = os.getenv('MODELO', 'qwen3:14b')
AI_USER = os.getenv('AI_USER', '')
AI_PASS = os.getenv('AI_PASS', '')

# Validación rápida de seguridad
if not AI_USER or not AI_PASS:
    print("⚠️  Advertencia: Credenciales de IA no configuradas en el archivo .env")
