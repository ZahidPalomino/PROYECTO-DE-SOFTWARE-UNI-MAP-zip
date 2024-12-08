import unittest
from unittest.mock import patch, MagicMock
from escanerNMAP import Notifier, NetworkScanner, VulnerabilityDatabase, ReportGenerator

class TestNotifier(unittest.TestCase):
    
# Preparar el entorno para las pruebas, asegurando que las dependencias necesarias estén correctamente configuradas.
    def setUp(self):
        """Configurar el entorno de prueba."""
        self.db = VulnerabilityDatabase(archivo="./test/test_vulnerabilidades.json")
        self.scanner = NetworkScanner("127.0.0.1", "vulnerabilidades", self.db)
        self.scanner.escanear_red()
        self.notifier = Notifier("admin@example.com")
        self.report_generator = ReportGenerator(self.scanner)  # Instancia real de ReportGenerator

    def test_filtrar_vulnerabilidades_criticas(self):
        """Prueba que el filtrado de vulnerabilidades críticas funcione correctamente."""
        self.notifier.filtrar_VulCritica(self.scanner)
        criticas = self.notifier.vulnerabilidades_criticas
        self.assertTrue(
            all(vuln.nivel_riesgo in ["Alto", "Medio"] for vuln in criticas),
            "El filtrado de vulnerabilidades críticas no excluye vulnerabilidades de bajo riesgo."
        )

    @patch("smtplib.SMTP")
    def test_enviar_notificacion(self, mock_smtp):
        """Prueba el envío de notificaciones con un mock del servidor SMTP."""
        self.notifier.filtrar_VulCritica(self.scanner)

        # Simular el servidor SMTP
        mock_server = MagicMock()
        mock_smtp.return_value.__enter__.return_value = mock_server

        # Intentar enviar la notificación con un ReportGenerator real
        self.notifier.enviar_notificacion(self.report_generator)

        # Verificar que se intentó enviar un correo
        mock_server.send_message.assert_called_once()
        llamado = mock_server.send_message.call_args
        mensaje = llamado[0][0]

        # Verificar que el correo tiene los parámetros correctos
        self.assertEqual(mensaje["To"], "admin@example.com", "El destinatario del correo no es correcto.")
        self.assertIn(
            "Reporte de Vulnerabilidades Críticas",
            mensaje["Subject"],
            "El asunto del correo no incluye 'Reporte de Vulnerabilidades Críticas'."
        )

    def test_validar_formato_correo(self):
        """Prueba que se valide correctamente el formato de los correos electrónicos."""
        with self.assertRaises(ValueError, msg="Se esperaba un ValueError para un correo con formato inválido."):
            Notifier("correo-invalido")  # Esto debería lanzar un ValueError

if __name__ == "__main__":
    unittest.main()
