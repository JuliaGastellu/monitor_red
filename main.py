#!/usr/bin/env python3
"""
Sistema de Monitoreo y Análisis de Tráfico de Red
Punto de entrada principal del sistema
"""

import sys
import signal
import threading
import time
import os
from src.configuracion.config import ConfiguracionSistema
from src.capturador.captura_paquetes import CapturadorPaquetes
from src.analizador.detector_amenazas import DetectorAmenazas
from src.analizador.estadisticas import CalculadorEstadisticas
from src.base_datos.gestor_bd import GestorBaseDatos
from src.alertas.sistema_alertas import SistemaAlertas
from src.web.servidor import ServidorWeb
from src.utils.logger import configurar_logger

class MonitorRed:
    """Clase principal que coordina todos los componentes del sistema"""
    
    def __init__(self):
        self.config = ConfiguracionSistema()
        self.logger = configurar_logger('MonitorRed')
        self.capturador = None
        self.detector = None
        self.gestor_bd = None
        self.sistema_alertas = None
        self.servidor_web = None
        self.calculador_estadisticas = None
        self.ejecutandose = False
        
    def inicializar_componentes(self):
        """Inicializa todos los componentes del sistema"""
        try:
            self.gestor_bd = GestorBaseDatos(self.config.ruta_bd)
            self.gestor_bd.inicializar()

            self.calculador_estadisticas = CalculadorEstadisticas(self.gestor_bd)
            
            self.sistema_alertas = SistemaAlertas(self.config)
            
            self.detector = DetectorAmenazas(
                self.gestor_bd, 
                self.sistema_alertas,
                self.config.reglas_deteccion,
                self.calculador_estadisticas
            )
            
            self.capturador = CapturadorPaquetes(
                self.config.interfaz_red,
                self.detector.procesar_paquete
            )
            
            self.servidor_web = ServidorWeb(self.gestor_bd, self.config)
            
            self.logger.info("Componentes inicializados correctamente")
            return True
            
        except Exception as e:
            self.logger.error(f"Error inicializando componentes: {e}")
            return False
    
    def iniciar_sistema(self):
        """Inicia todos los hilos del sistema"""
        if not self.inicializar_componentes():
            return False
            
        try:
            self.ejecutandose = True
            
            # Hilo del servidor web
            hilo_web = threading.Thread(
                target=self.servidor_web.ejecutar,
                args=(self.config.puerto_web, self.config.debug_web),
                daemon=True
            )
            hilo_web.start()
            
            # Hilo del capturador
            hilo_captura = threading.Thread(
                target=self.capturador.iniciar_captura,
                daemon=True
            )
            hilo_captura.start()

            if self.calculador_estadisticas:
                self.calculador_estadisticas.iniciar()
            
            self.logger.info("Sistema iniciado correctamente")
            self.logger.info(f"Dashboard disponible en http://localhost:{self.config.puerto_web}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error iniciando sistema: {e}")
            return False
    
    def detener_sistema(self):
        """Detiene todos los componentes del sistema"""
        self.logger.info("Deteniendo sistema...")
        self.ejecutandose = False
        
        if self.capturador:
            self.capturador.detener_captura()

        if self.calculador_estadisticas:
            self.calculador_estadisticas.detener()
            
        if self.gestor_bd:
            self.gestor_bd.cerrar_conexion()
            
        self.logger.info("Sistema detenido")
    
    def ejecutar_bucle_principal(self):
        """Ejecuta el bucle principal del sistema"""
        try:
            while self.ejecutandose:
                time.sleep(1)
                
        except KeyboardInterrupt:
            self.logger.info("Interrupción recibida")
        finally:
            self.detener_sistema()

def manejador_senal(signum, frame):
    """Maneja las señales del sistema para cierre limpio"""
    print("\nRecibida señal de interrupción. Cerrando sistema...")
    global monitor
    if monitor:
        monitor.detener_sistema()
    sys.exit(0)

def main():
    """Función principal"""
    global monitor
    
    print("=" * 60)
    print("Sistema de Monitoreo y Análisis de Tráfico de Red")
    print("=" * 60)
    
    # Configurar manejadores de señales
    signal.signal(signal.SIGINT, manejador_senal)
    signal.signal(signal.SIGTERM, manejador_senal)
    
    # Verificar permisos de administrador
    if sys.platform.startswith('linux') and os.geteuid() != 0:
        print("Error: Este programa necesita permisos de administrador para capturar tráfico de red")
        print("Ejecuta con: sudo python3 main.py")
        sys.exit(1)
    
    # Inicializar y ejecutar el monitor
    monitor = MonitorRed()
    
    if not monitor.iniciar_sistema():
        print("Error: No se pudo iniciar el sistema")
        sys.exit(1)
    
    try:
        monitor.ejecutar_bucle_principal()
    except Exception as e:
        print(f"Error inesperado: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()