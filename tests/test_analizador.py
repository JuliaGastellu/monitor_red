import unittest
from scapy.layers.inet import IP, TCP, UDP
from src.capturador.captura_paquetes import PaqueteWrapper

class TestPaqueteWrapper(unittest.TestCase):

    def test_paquete_tcp(self):
        """Prueba el wrapper con un paquete TCP simple."""
        paquete_scapy = IP(src="192.168.1.10", dst="8.8.8.8") / TCP(sport=12345, dport=80)
        wrapper = PaqueteWrapper(paquete_scapy)

        self.assertEqual(wrapper.ip_origen, "192.168.1.10")
        self.assertEqual(wrapper.ip_destino, "8.8.8.8")
        self.assertEqual(wrapper.puerto_origen, 12345)
        self.assertEqual(wrapper.puerto_destino, 80)
        self.assertEqual(wrapper.protocolo, "TCP")
        self.assertTrue(wrapper.es_tcp())
        self.assertFalse(wrapper.es_udp())
        self.assertEqual(wrapper.tamaño, len(paquete_scapy))

    def test_paquete_udp(self):
        """Prueba el wrapper con un paquete UDP simple."""
        paquete_scapy = IP(src="192.168.1.11", dst="8.8.4.4") / UDP(sport=54321, dport=53)
        wrapper = PaqueteWrapper(paquete_scapy)

        self.assertEqual(wrapper.ip_origen, "192.168.1.11")
        self.assertEqual(wrapper.ip_destino, "8.8.4.4")
        self.assertEqual(wrapper.puerto_origen, 54321)
        self.assertEqual(wrapper.puerto_destino, 53)
        self.assertEqual(wrapper.protocolo, "UDP")
        self.assertFalse(wrapper.es_tcp())
        self.assertTrue(wrapper.es_udp())

    def test_paquete_sin_ip(self):
        """Prueba el wrapper con un paquete que no es IP."""
        # Scapy por defecto crea paquetes Ethernet, que no tienen capa IP
        paquete_scapy = TCP()
        wrapper = PaqueteWrapper(paquete_scapy)

        # No debería tener información de IP
        self.assertIsNone(wrapper.ip_origen)
        self.assertIsNone(wrapper.ip_destino)
        # Pero sí de TCP
        self.assertEqual(wrapper.protocolo, "TCP")


if __name__ == '__main__':
    unittest.main()
