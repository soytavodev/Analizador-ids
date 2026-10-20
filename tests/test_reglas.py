"""Pruebas del detector por reglas.  Ejecutar con:  python3 -m unittest"""
import unittest

from reglas import analizar_logs_reglas, clasificar


class TestClasificar(unittest.TestCase):
    def tipo(self, ruta):
        resultado = clasificar(ruta)
        return resultado[0] if resultado else None

    def test_trafico_normal(self):
        for ruta in ["/", "/index.php?page=productos", "/buscar.php?q=camiseta+negra",
                     "/index.php?page=blog&post=como-elegir-talla", "/img/logo.png"]:
            self.assertIsNone(self.tipo(ruta), ruta)

    def test_path_traversal(self):
        self.assertEqual(self.tipo("/index.php?page=../../../../etc/passwd"), "Path Traversal")

    def test_sql_injection(self):
        self.assertEqual(self.tipo("/index.php?page=home' OR '1'='1"), "SQL Injection")
        self.assertEqual(self.tipo("/buscar.php?q=x UNION SELECT user,password FROM users"), "SQL Injection")

    def test_sql_injection_codificada(self):
        # %27 es una comilla: el atacante codifica la URL para esquivar filtros simples
        self.assertEqual(self.tipo("/buscar.php?q=%27%20UNION%20SELECT%20user,password%20FROM%20users--"), "SQL Injection")

    def test_xss(self):
        self.assertEqual(self.tipo("/index.php?page=<script>alert('hack')</script>"), "XSS")
        self.assertEqual(self.tipo("/perfil.php?foto=x\" onerror=alert(1)"), "XSS")

    def test_escaneo(self):
        for ruta in ["/wp-login.php", "/.env", "/phpmyadmin/"]:
            self.assertEqual(self.tipo(ruta), "Escaneo de bot", ruta)


class TestInforme(unittest.TestCase):
    def test_formato(self):
        logs = [(1, "192.168.1.5", "/", "2026-06-01 09:00:00"),
                (2, "198.51.100.23", "/index.php?page=../../etc/passwd", "2026-06-01 09:01:00")]
        informe = analizar_logs_reglas(logs)
        self.assertTrue(informe["analisis_completado"])
        self.assertEqual(len(informe["amenazas_detectadas"]), 1)
        self.assertEqual(informe["amenazas_detectadas"][0]["id_log"], 2)


if __name__ == "__main__":
    unittest.main()
