import time
from collections import defaultdict
from threading import Thread, Event
from src.utils.logger import configurar_logger

class CalculadorEstadisticas:
    """
    Calcula estadísticas de tráfico de red en tiempo real.
    """
    def __init__(self, gestor_bd, intervalo_seg=60):
        self.gestor_bd = gestor_bd
        self.intervalo = intervalo_seg
        self.logger = configurar_logger('CalculadorEstadisticas')

        # Contadores para el intervalo actual
        self.paquetes_intervalo = 0
        self.bytes_intervalo = 0
        self.protocolos_intervalo = defaultdict(int)

        # Para el bucle de cálculo
        self.hilo = None
        self.detener_evento = Event()

        # Para calcular tasas
        self.tiempo_inicio_intervalo = time.time()

    def registrar_paquete(self, paquete_wrapper):
        """
        Registra un paquete para las estadísticas.
        Este método es llamado por cada paquete capturado.
        """
        self.paquetes_intervalo += 1
        self.bytes_intervalo += paquete_wrapper.tamaño
        self.protocolos_intervalo[paquete_wrapper.protocolo] += 1

    def _bucle_calculo(self):
        """
        Bucle que se ejecuta en un hilo para calcular y guardar
        estadísticas periódicamente.
        """
        while not self.detener_evento.is_set():
            self.detener_evento.wait(self.intervalo)
            if self.detener_evento.is_set():
                break

            self._calcular_y_guardar()
            self._reiniciar_contadores()

    def _calcular_y_guardar(self):
        """
        Calcula las métricas finales y las guarda en la base de datos.
        """
        tiempo_fin_intervalo = time.time()
        duracion_intervalo = tiempo_fin_intervalo - self.tiempo_inicio_intervalo

        if duracion_intervalo == 0:
            return # Evitar división por cero

        paquetes_por_segundo = self.paquetes_intervalo / duracion_intervalo
        bytes_por_segundo = self.bytes_intervalo / duracion_intervalo

        estadisticas = {
            'paquetes_totales': self.paquetes_intervalo,
            'bytes_totales': self.bytes_intervalo,
            'paquetes_por_segundo': round(paquetes_por_segundo, 2),
            'distribucion_protocolos': dict(self.protocolos_intervalo)
        }

        try:
            if self.gestor_bd and self.paquetes_intervalo > 0:
                self.gestor_bd.guardar_estadistica(estadisticas)
                self.logger.info(f"Nuevas estadísticas calculadas: {estadisticas}")
        except Exception as e:
            self.logger.error(f"Error al guardar estadísticas: {e}")

    def _reiniciar_contadores(self):
        """Reinicia los contadores para el siguiente intervalo."""
        self.paquetes_intervalo = 0
        self.bytes_intervalo = 0
        self.protocolos_intervalo.clear()
        self.tiempo_inicio_intervalo = time.time()

    def iniciar(self):
        """Inicia el hilo de cálculo de estadísticas."""
        if self.hilo is None or not self.hilo.is_alive():
            self.detener_evento.clear()
            self.hilo = Thread(target=self._bucle_calculo, daemon=True)
            self.hilo.start()
            self.logger.info(f"Cálculo de estadísticas iniciado (intervalo de {self.intervalo}s).")

    def detener(self):
        """Detiene el hilo de cálculo de estadísticas."""
        self.detener_evento.set()
        if self.hilo and self.hilo.is_alive():
            self.hilo.join(timeout=2)
        self.logger.info("Cálculo de estadísticas detenido.")
