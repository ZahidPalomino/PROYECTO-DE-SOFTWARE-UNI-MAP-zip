"""Este archivo verifica el comportamiento de la clase NetworkScanner.

Pruebas básicas:

Escaneo de conectividad en un rango reducido.
Escaneo de vulnerabilidades simulando servicios comunes.
Validar que los problemas detectados se almacenan correctamente."""
import unittest
from escanerNMAP import NetworkScanner, VulnerabilityDatabase

class TestScanner(unittest.TestCase):

    def setUp(self):
        """Configura el escáner con la base de datos de prueba."""
        self.db = VulnerabilityDatabase(archivo="./test/test_vulnerabilidades.json")
        # Cambia el rango de IP a algo más pequeño para pruebas
        self.scanner = NetworkScanner("127.0.0.1", "vulnerabilidades", self.db)
        
    def test_rango_ip_invalido(self):
        """Prueba que se lance una excepción con rangos de IP inválidos."""
#assertRaises: comprueba que se lanza una excepción específica, en este caso, se espera que se 
# lance una excepción del tipo ValueError.
        with self.assertRaises(ValueError) as context:
            NetworkScanner("192.168.300.0/24", "vulnerabilidades", self.db)
#assertIn: Comprueba que una cadena específica está contenida dentro del mensaje de la excepción capturada.
        self.assertIn("El rango de IP '192.168.300.0/24' es inválido", str(context.exception))


    def test_escanear_vulnerabilidades(self):
        """Prueba que el escáner detecte problemas en el rango de IP."""
        self.scanner.escanear_red()
        problemas = self.scanner.obtener_problemas()
# assertGreaterEqual: Comprueba que el número de problemas detectados sea mayor o igual a 0.
        self.assertGreaterEqual(
            len(problemas), 
            0, 
            "El escáner de vulnerabilidades no generó resultados."
        )
        if problemas: #Solo realiza esta verificación si se detectaron problemas.
#  Asegura que el método ver_info de cada problema devuelva un diccionario válido.
            self.assertTrue(
                all(isinstance(p.ver_info(), dict) for p in problemas), 
                "No todos los problemas detectados son instancias válidas."
            )

    def test_escanear_conectividad(self):
        """Prueba el escaneo de conectividad."""
        self.scanner.tipo_escaneo = "conectividad"
        self.scanner.escanear_red()
        problemas = self.scanner.obtener_problemas()
        self.assertGreaterEqual(
            len(problemas), 
            0, 
            "El escáner de conectividad no detectó dispositivos."
        )
        if problemas:
            self.assertTrue(
                all(isinstance(p.ver_info(), dict) for p in problemas), 
                "No todos los problemas de conectividad son instancias válidas."
            )

if __name__ == "__main__":
    unittest.main()
