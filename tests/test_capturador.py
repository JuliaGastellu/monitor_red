import unittest
from src.capturador.filtros import construir_filtro_bpf

class TestFiltros(unittest.TestCase):

    def test_construir_filtro_bpf_vacio(self):
        """Prueba que se genera una cadena vacía para una configuración vacía."""
        config = {}
        filtro = construir_filtro_bpf(config)
        self.assertEqual(filtro, "")

    def test_construir_filtro_bpf_protocolo(self):
        """Prueba un filtro solo con protocolo."""
        config = {'protocolo': 'tcp'}
        filtro = construir_filtro_bpf(config)
        self.assertEqual(filtro, "tcp")

    def test_construir_filtro_bpf_puertos(self):
        """Prueba un filtro con múltiples puertos."""
        config = {'puerto_incluir': [80, 443]}
        filtro = construir_filtro_bpf(config)
        self.assertEqual(filtro, "(port 80 or port 443)")

    def test_construir_filtro_bpf_excluir_ip(self):
        """Prueba un filtro para excluir una IP."""
        config = {'ip_origen_excluir': ['192.168.1.1']}
        filtro = construir_filtro_bpf(config)
        self.assertEqual(filtro, "(not src host 192.168.1.1)")

    def test_construir_filtro_bpf_complejo(self):
        """Prueba una combinación compleja de filtros."""
        config = {
            'ip_origen_excluir': ['192.168.1.1', '10.0.0.5'],
            'puerto_incluir': [80, 443, 8080],
            'protocolo': 'tcp'
        }
        filtro_esperado = "(not src host 192.168.1.1 and not src host 10.0.0.5) and (port 80 or port 443 or port 8080) and tcp"
        filtro_generado = construir_filtro_bpf(config)
        self.assertEqual(filtro_generado, filtro_esperado)

if __name__ == '__main__':
    unittest.main()
