"""Este archivo verifica el comportamiento de la clase ReportGenerator.

Pruebas básicas:

Generación de reportes en los formatos CSV, HTML y TXT.
Verificar que los reportes contienen la información esperada."""
import unittest
import os
from escanerNMAP import ReportGenerator, NetworkScanner, VulnerabilityDatabase

class TestReportGenerator(unittest.TestCase):

    def setUp(self):
        # Configurar el escáner con datos de prueba
        self.db = VulnerabilityDatabase(archivo="./test/test_vulnerabilidades.json")
        self.scanner = NetworkScanner("10.13.4.0/26", "vulnerabilidades", self.db)
        self.scanner.escanear_red()
        self.report_generator = ReportGenerator(self.scanner)
        
    def tearDown(self):
        # Limpiar los archivos generados después de cada prueba
        archivos = [
            "./test_output/reporte_vulnerabilidades.csv",
            "./test_output/reporte_vulnerabilidades.html",
            "./test_output/reporte_vulnerabilidades.txt"
        ]
        for archivo in archivos:
            if os.path.exists(archivo):
                os.remove(archivo)
                
#os.path.exists: Verifica si el archivo en la ruta especificada realmente existe en el sistema de archivos.
#self.assertTrue: Evalúa si la expresión pasada como argumento (os.path.exists(...)) es True.
#Si el archivo no existe, esta aserción fallará y la prueba será reportada como un error.
    def test_generar_csv(self):
        """Prueba la generación de reportes en formato CSV."""
        self.report_generator.exportar_a_csv("./test_output/reporte_vulnerabilidades.csv")
        self.assertTrue(os.path.exists("./test_output/reporte_vulnerabilidades.csv"), "El archivo CSV no se generó.")

    def test_generar_html(self):
        """Prueba la generación de reportes en formato HTML."""
        self.report_generator.exportar_a_html("./test_output/reporte_vulnerabilidades.html")
        self.assertTrue(os.path.exists("./test_output/reporte_vulnerabilidades.html"), "El archivo HTML no se generó.")

    def test_generar_txt(self):
        """Prueba la generación de reportes en formato TXT."""
        self.report_generator.exportar_a_txt("./test_output/reporte_vulnerabilidades.txt")
        self.assertTrue(os.path.exists("./test_output/reporte_vulnerabilidades.txt"), "El archivo TXT no se generó.")

if __name__ == "__main__":
    unittest.main()
