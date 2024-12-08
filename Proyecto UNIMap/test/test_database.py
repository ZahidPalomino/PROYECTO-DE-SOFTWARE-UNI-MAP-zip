"""Este archivo verifica el comportamiento de la clase VulnerabilityDatabase.

Pruebas básicas:

Asegúrate de que el archivo JSON se carga correctamente.
Verifica que las vulnerabilidades se obtienen correctamente.
Simula errores como un archivo JSON malformado o ausente."""
import unittest #Biblioteca estándar para definir y ejecutar pruebas.
from escanerNMAP import VulnerabilityDatabase

class TestDatabase(unittest.TestCase): #clase de pruebas, hereda de unittest.TestCase

    def setUp(self): #Este método se ejecuta antes de cada caso de prueba.
        # Ruta al archivo JSON de prueba
        self.db = VulnerabilityDatabase(archivo="./test/test_vulnerabilidades.json")

    def test_carga_exitosa(self):
        """Prueba que la base de datos se cargue correctamente."""
        self.assertTrue(len(self.db.vulnerabilidades) > 0, "La base de datos no cargó vulnerabilidades.")
#Verifica que una condición sea verdadera durante una prueba unitaria.
#Si la condición es falsa, la prueba fallará y se mostrará el mensaje de error asociado.

    def test_obtener_vulnerabilidad_existente(self):
        """Prueba la obtención de una vulnerabilidad existente."""
        resultado = self.db.obtener_vulnerabilidad_por_servicio("ftp")
# busca en la base de datos de vulnerabilidades, devuelve un diccionario con la información asociada al 
# servicio especificado.
        self.assertEqual(resultado["risk_level"], "Alto", "Nivel de riesgo incorrecto para 'ftp'.")

    def test_vulnerabilidad_no_existente(self):
        """Prueba que se devuelva una vulnerabilidad genérica para servicios inexistentes."""
        resultado = self.db.obtener_vulnerabilidad_por_servicio("servicio_inexistente")
        self.assertEqual(resultado["risk_level"], "Bajo", "El nivel de riesgo por defecto debería ser 'Bajo'.")
    
    def test_carga_archivo_invalido(self):
        """Prueba que el sistema maneje un archivo JSON inválido."""
        db_invalida = VulnerabilityDatabase(archivo="./test/archivo_invalido.json")
        self.assertEqual(len(db_invalida.vulnerabilidades), 0, 
                         "La base de datos debería estar vacía al cargar un archivo inválido.")

if __name__ == "__main__":
    unittest.main()
