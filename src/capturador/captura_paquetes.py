import threading
import os
import platform
import socket
from scapy.all import sniff, Packet, conf
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS
from datetime import datetime
from src.utils.logger import configurar_logger

class PaqueteWrapper:
    """
    Una clase contenedora para normalizar la información de los paquetes de Scapy.
    """
    def __init__(self, paquete_scapy):
        self.paquete_original = paquete_scapy
        self.timestamp = datetime.now()
        self.ip_origen = None
        self.ip_destino = None
        self.puerto_origen = None
        self.puerto_destino = None
        self.protocolo = 'Desconocido'
        self.tamaño = len(paquete_scapy)
        self.info_adicional = {}

        self._parse()

    def _parse(self):
        """Extrae la información relevante del paquete Scapy."""
        if self.paquete_original.haslayer(IP):
            ip_layer = self.paquete_original.getlayer(IP)
            self.ip_origen = ip_layer.src
            self.ip_destino = ip_layer.dst

        if self.paquete_original.haslayer(TCP):
            tcp_layer = self.paquete_original.getlayer(TCP)
            self.puerto_origen = tcp_layer.sport
            self.puerto_destino = tcp_layer.dport
            self.protocolo = 'TCP'
            self.info_adicional['flags'] = str(tcp_layer.flags)

        elif self.paquete_original.haslayer(UDP):
            udp_layer = self.paquete_original.getlayer(UDP)
            self.puerto_origen = udp_layer.sport
            self.puerto_destino = udp_layer.dport
            self.protocolo = 'UDP'

        elif self.paquete_original.haslayer(DNS):
            self.protocolo = 'DNS'
            dns_layer = self.paquete_original.getlayer(DNS)
            if dns_layer.qr == 0: # Query
                if dns_layer.qd:
                    self.info_adicional['dns_query'] = dns_layer.qd.qname.decode()
            elif dns_layer.qr == 1: # Response
                 if dns_layer.an:
                    self.info_adicional['dns_response'] = [ans.rdata for ans in dns_layer.an]


    def es_tcp(self):
        return self.protocolo == 'TCP'

    def es_udp(self):
        return self.protocolo == 'UDP'

    def obtener_protocolo_nombre(self):
        return self.protocolo

class CapturadorPaquetes:
    """
    Captura tráfico de red en una interfaz específica.
    """
    def __init__(self, interfaz, callback_procesamiento, filtro_bpf=""):
        self.interfaz = interfaz
        self.callback_procesamiento = callback_procesamiento
        self.filtro_bpf = filtro_bpf
        self.logger = configurar_logger('CapturadorPaquetes')
        self.hilo_captura = None
        self.detener_captura_flag = threading.Event()
        
        # Configuración específica para Windows
        if platform.system() == 'Windows':
            self.logger.info("Sistema Windows detectado. Configurando para captura a nivel 3.")
            # Desactivar pcap para forzar el uso de sockets nativos
            conf.use_pcap = False

    def _procesar_paquete_scapy(self, paquete_scapy: Packet):
        """
        Función de callback para Scapy. Envuelve el paquete y lo pasa al detector.
        """
        if not self.detener_captura_flag.is_set():
            try:
                paquete_envuelto = PaqueteWrapper(paquete_scapy)
                self.callback_procesamiento(paquete_envuelto)
            except Exception as e:
                self.logger.error(f"Error al procesar paquete: {e}\nPaquete: {paquete_scapy.summary()}")

    def iniciar_captura(self):
        """
        Inicia la captura de paquetes en un hilo separado.
        """
        self.logger.info(f"Iniciando captura de paquetes en la interfaz: {self.interfaz or 'default'}")
        self.detener_captura_flag.clear()

        self.hilo_captura = threading.Thread(target=self._bucle_captura, daemon=True)
        self.hilo_captura.start()

    def _bucle_captura(self):
        """
        El bucle principal que ejecuta `sniff` de Scapy.
        """
        try:
            # Implementación alternativa para Windows
            if platform.system() == 'Windows':
                self.logger.info("Usando captura a nivel 3 en Windows")
                try:
                    # En Windows, usar sniff sin especificar interfaz
                    sniff(
                        prn=self._procesar_paquete_scapy,
                        filter=self.filtro_bpf,
                        store=False,
                        stop_filter=lambda p: self.detener_captura_flag.is_set()
                    )
                except Exception as e:
                    self.logger.error(f"Error con sniff: {e}, intentando con socket raw")
                    # Fallback a socket raw si sniff falla
                    self._captura_con_socket_raw()
            else:
                # En otros sistemas operativos, usar la interfaz especificada
                sniff(
                    iface=self.interfaz,
                    prn=self._procesar_paquete_scapy,
                    filter=self.filtro_bpf,
                    store=False,
                    stop_filter=lambda p: self.detener_captura_flag.is_set()
                )
            self.logger.info("Bucle de captura terminado.")
        except PermissionError:
            self.logger.error("Error de permisos. Asegúrate de ejecutar el programa con privilegios de administrador.")
        except OSError as e:
            self.logger.error(f"Error de red: {e}. Asegúrate de que la interfaz '{self.interfaz}' existe y está activa.")
        except Exception as e:
            self.logger.error(f"Error inesperado en la captura de paquetes: {e}")
            
    def _captura_con_socket_raw(self):
        """
        Método alternativo de captura usando socket raw en Windows.
        """
        try:
            # Crear un socket raw para capturar paquetes IP
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            
            # Encontrar una interfaz activa para enlazar el socket
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            self.logger.info(f"Usando interfaz con IP: {local_ip}")
            
            # Enlazar a la interfaz local
            raw_socket.bind((local_ip, 0))
            
            # Configurar el socket para incluir los encabezados IP
            raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            # Activar modo promiscuo
            raw_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            
            self.logger.info("Socket raw configurado correctamente")
            
            # Bucle de captura manual
            while not self.detener_captura_flag.is_set():
                try:
                    data = raw_socket.recv(65535)
                    if data:
                        # Convertir datos raw a paquete IP de Scapy
                        pkt = IP(data)
                        self._procesar_paquete_scapy(pkt)
                except Exception as e:
                    self.logger.error(f"Error capturando paquete: {e}")
                    if self.detener_captura_flag.is_set():
                        break
            
            # Limpiar
            try:
                raw_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except:
                pass
            raw_socket.close()
            
        except Exception as e:
            self.logger.error(f"Error configurando socket raw: {e}")

    def detener_captura(self):
        """
        Señala al hilo de captura que debe detenerse.
        """
        self.logger.info("Deteniendo la captura de paquetes...")
        self.detener_captura_flag.set()
        if self.hilo_captura and self.hilo_captura.is_alive():
            self.hilo_captura.join(timeout=2)
        self.logger.info("Captura de paquetes detenida.")
