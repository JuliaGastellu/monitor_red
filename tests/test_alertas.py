import unittest
from datetime import datetime
from unittest.mock import MagicMock
from src.alertas.sistema_alertas import SistemaAlertas

class TestSistemaAlertas(unittest.TestCase):

    def setUp(self):
        """Configura un objeto de configuración mock para las pruebas."""
        self.mock_config = MagicMock()
        self.mock_config.alertas_log = {'habilitado': False}
        self.mock_config.alertas_email = {'habilitado': False}

    def test_formatear_alerta_texto(self):
        """Prueba la función de formateo de alertas a texto."""
        sistema_alertas = SistemaAlertas(self.mock_config)

        alerta = {
            'timestamp': datetime(2024, 1, 1, 12, 30, 0),
            'tipo': 'TEST_ALERTA',
            'severidad': 'ALTA',
            'mensaje': 'Este es un mensaje de prueba.',
            'datos': {
                'ip_origen': '127.0.0.1',
                'detalle_extra': 'valor'
            }
        }

        texto_formateado = sistema_alertas._formatear_alerta_texto(alerta)

        self.assertIn("Tipo: TEST_ALERTA", texto_formateado)
        self.assertIn("Severidad: ALTA", texto_formateado)
        self.assertIn("Timestamp: 2024-01-01 12:30:00", texto_formateado)
        self.assertIn("Mensaje: Este es un mensaje de prueba.", texto_formateado)
        self.assertIn('"ip_origen": "127.0.0.1"', texto_formateado)
        self.assertIn('"detalle_extra": "valor"', texto_formateado)

    def test_sin_datos_adicionales(self):
        """Prueba el formateo cuando no hay datos adicionales."""
        sistema_alertas = SistemaAlertas(self.mock_config)

        alerta = {
            'timestamp': datetime.now(),
            'tipo': 'OTRA_ALERTA',
            'severidad': 'BAJA',
            'mensaje': 'Otro mensaje.',
            'datos': {}
        }

        texto_formateado = sistema_alertas._formatear_alerta_texto(alerta)
        # El bloque de detalles se imprime, pero estará vacío.
        self.assertIn("Detalles:\n---------", texto_formateado)

if __name__ == '__main__':
    unittest.main()
