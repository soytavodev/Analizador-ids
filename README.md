# Analizador IDS

Prototipo de **sistema de detección de intrusos** (IDS) para una web. Lee los últimos accesos guardados en una base de datos SQLite y busca intentos de ataque: SQL Injection, XSS, Path Traversal y escaneos de bots.

Tiene dos formas de analizar:

- **Por reglas:** busca patrones conocidos de ataque (firmas), como hacen los IDS clásicos. Es rápido y no necesita nada más que Python.
- **Con IA local:** envía los registros a un modelo de lenguaje que se ejecuta en tu ordenador con [Ollama](https://ollama.com), usando *few-shot prompting* (ejemplos de tráfico normal y de ataques dentro del propio prompt). El modelo devuelve un informe en JSON.

Con `--modo ambos` se ejecutan los dos y se compara qué detecta cada uno: las reglas solo ven patrones, y la IA intenta entender la intención de la petición.

## Resultados en mi prueba

Con la base de datos de ejemplo (40 visitas normales y 7 ataques), en una máquina virtual sin tarjeta gráfica y con el modelo `qwen2.5:1.5b` (unos 1 GB):

| Modo | Ataques detectados (de 7) | Falsos positivos | Tiempo |
| --- | --- | --- | --- |
| Reglas | 7 | 0 | instantáneo |
| IA, todos los registros en un solo prompt | 0 | 4 | 1 min 30 s |
| IA, por lotes de 8 registros | 4 | 1 | 3 min 40 s |

Lo que aprendí:
- Un modelo pequeño se pierde con muchos registros a la vez. Mandarlos **por lotes** pasó de 0 a 4 aciertos.
- El modelo a veces devuelve registros que no existen, así que el programa **descarta cualquier `id_log` que no estuviera en el lote** enviado.
- La IA acertó las inyecciones SQL (también la codificada en la URL), el XSS y el path traversal, pero no vio los escaneos de bots (`/wp-login.php`, `/.env`, `/phpmyadmin/`), que las reglas detectan sin problema. Por eso tiene sentido usar los dos: las reglas para lo conocido y la IA como segunda opinión.

Los resultados de la IA pueden variar un poco entre ejecuciones.

Empezó como un prototipo durante mis prácticas en empresa (FCT). Esta versión funciona sola, con una base de datos de ejemplo y sin depender de ningún servidor externo.

## Ejemplo

```text
$ python3 crear_bd_ejemplo.py && python3 inyectar.py && python3 main.py
✅ Base de datos creada en ./analytics.db con 40 visitas normales.
✅ 7 ataques inyectados.
🛡️ Iniciando Analizador IDS...
📊 Se extrajeron 47 registros.

==================================================
🚨 REPORTE DE SEGURIDAD · REGLAS
==================================================
⚠️ 7 amenazas detectadas:

🛑 IP          : 198.51.100.77
📄 Log ID      : 43
🎯 Ruta        : /buscar.php?q=%27%20UNION%20SELECT%20user,password%20FROM%20users--
🔪 Tipo        : SQL Injection
🔥 Gravedad    : Alta
🛡️ Recomendado : Bloquear IP y usar consultas preparadas
...
```

## Cómo funciona

- `crear_bd_ejemplo.py` crea `analytics.db` con 40 visitas normales a una tienda online inventada. Usa una semilla fija, así que siempre genera los mismos datos.
- `inyectar.py` simula al atacante (*Red Team*): añade 7 peticiones maliciosas a la tabla `visitas`.
- `main.py` hace de defensor (*Blue Team*): lee los últimos registros en modo solo lectura, los analiza y muestra el informe.
- `reglas.py` contiene las firmas. Antes de comparar, decodifica la URL, porque los atacantes suelen codificarla (`%27` es una comilla) para esquivar filtros simples.
- Todas las IP son de rangos privados o reservados para documentación (RFC 1918 y RFC 5737), no de personas o empresas reales.

## Instalación y uso

Necesitas Python 3.

```bash
git clone https://github.com/soytavodev/Analizador-ids.git
cd Analizador-ids

python3 crear_bd_ejemplo.py     # base de datos de ejemplo
python3 inyectar.py             # ataques simulados
python3 main.py                 # análisis por reglas
python3 -m unittest             # pruebas del detector por reglas
```

### Modo IA (opcional)

1. Instala [Ollama](https://ollama.com/download) y descarga un modelo. Por defecto se usa `qwen2.5:1.5b`, que ocupa unos 1 GB y funciona sin tarjeta gráfica (tarda unos minutos):
   ```bash
   ollama pull qwen2.5:1.5b
   ```
2. Instala la librería `requests` si no la tienes:
   ```bash
   pip install -r requirements.txt
   ```
3. Ejecuta el análisis con IA, o los dos modos para compararlos:
   ```bash
   python3 main.py --modo ia
   python3 main.py --modo ambos
   python3 main.py --modo ia --lote 5 --debug   # lotes más pequeños y respuesta cruda de la IA
   ```

Para cambiar el modelo, la dirección de Ollama o la ruta de la base de datos, copia `.env.example` como `.env` y edítalo.

## Estructura

```text
Analizador-ids/
├── config.py             # Configuración (con valores por defecto)
├── crear_bd_ejemplo.py   # Base de datos de ejemplo
├── inyectar.py           # Simulador de ataques
├── main.py               # Analizador e informe
├── reglas.py             # Detección por firmas
└── tests/                # Pruebas con unittest
```

## Tecnologías

Python, SQLite, expresiones regulares, Ollama (IA local) y `unittest`.

## Autor

Gustavo Delnardo · [GitHub](https://github.com/soytavodev) · [Web](https://gustavo-delnardo.vercel.app)
