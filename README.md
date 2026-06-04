# Analizador de Seguridad IDS (Prototipo) 🛡️🤖

## 📋 Descripción
Prototipo aislado de un **Sistema de Detección de Intrusos (IDS)** con enfoque *Blue Team*. Utiliza Inteligencia Artificial (LLMs ejecutados localmente) para auditar logs de tráfico web desde una base de datos relacional y detectar patrones anómalos, escaneos de bots y ataques directos (SQLi, XSS, Path Traversal).

A diferencia de los IDS tradicionales basados en firmas estáticas, esta herramienta comprende el contexto real de las peticiones HTTP utilizando técnicas de **Few-Shot Prompting**, reduciendo los falsos positivos y emitiendo reportes JSON altamente estructurados.

---

## 🛠️ Stack Tecnológico
* **Lenguaje:** Python 3.x
* **Inteligencia Artificial:** Ollama API (`qwen3:14b`)
* **Persistencia:** SQLite (`analytics.db`)
* **Seguridad y Entorno:** `python-dotenv` (Gestión segura de credenciales en `.env`)
* **Técnicas:** Prompt Engineering, Few-Shot Learning, Inyección de logs simulados.

---

## 🏗️ Arquitectura y Seguridad
El proyecto está diseñado bajo buenas prácticas de ingeniería, aislando la lógica de negocio de las credenciales sensibles.

```text
Analizador-ids/
├── .env                 # Variables de entorno y credenciales locales (Ignorado por Git)
├── .env.example         # Plantilla base para configuración de variables
├── config.py            # Validador y cargador seguro de credenciales
├── inyectar.py          # Script simulador de amenazas (Red Team)
└── main.py              # Orquestador del análisis y generador de reportes (Blue Team)
```

## ⚙️ Características Principales
Análisis Heurístico Contextual: Evalúa el peligro de una URL basándose en la intención de la petición, no solo en coincidencias exactas de texto.

Simulación de Ataques (Inyector): Incluye un script dedicado (inyectar.py) que escribe vectores de ataque reales directamente en la base de datos para probar la eficacia del escáner.

Seguridad por Diseño: Todo el análisis se realiza de forma local o a través de un túnel cifrado hacia el servidor de IA, sin exponer los logs a APIs de terceros públicas.

Salida Estructurada: Obliga a la IA a devolver exclusivamente un JSON válido, listo para ser consumido por un dashboard o un sistema de bloqueo de IPs (Firewall).

## 🚀 Instalación y Uso
Clonar el repositorio:

Bash
git clone [https://github.com/soytavodev/Analizador-ids.git](https://github.com/soytavodev/Analizador-ids.git)
cd Analizador-ids
Configurar el entorno virtual:

Bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
Configurar credenciales:
Copia el archivo de ejemplo y rellénalo con tus credenciales y rutas reales.

Bash
cp .env.example .env
Simular un ataque (Opcional):

Bash
python3 inyectar.py
Ejecutar la auditoría de seguridad:

Bash
python3 main.py
