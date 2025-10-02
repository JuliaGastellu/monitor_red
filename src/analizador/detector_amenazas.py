import time
import json
from collections import defaultdict, deque
from datetime import datetime, timedelta
from src.utils.logger import configurar_logger
from src.analizador.analizador_protocolos import analizar_protocolo_aplicacion

class DetectorAmenazas:
    """
    Detector de patrones maliciosos en tráfico de red.
    Esta clase es el núcleo del motor de análisis.
    """
    
    def __init__(self, gestor_bd, sistema_alertas, config_reglas, calculador_estadisticas):
        self.gestor_bd = gestor_bd
        self.sistema_alertas = sistema_alertas
        self.calculador_estadisticas = calculador_estadisticas
        self.logger = configurar_logger('DetectorAmenazas')
        
        # Cargar configuración de reglas
        self.config_reglas = config_reglas
        self.ips_maliciosas = set(self.config_reglas.get('ips_maliciosas_conocidas', []))
        
        # Estructuras para tracking de estado
        self.ventana_tiempo = 60  # segundos
        self.conexiones_por_ip = defaultdict(lambda: deque(maxlen=200))
        self.puertos_escaneados = defaultdict(set)
        self.intentos_conexion_fallidos = defaultdict(lambda: defaultdict(int)) # Para fuerza bruta
        self.volumen_trafico_ip = defaultdict(lambda: {'bytes': 0, 'paquetes': 0, 'timestamp': time.time()})
        
        # Para evitar alertas duplicadas rápidamente
        self.cache_alertas = defaultdict(lambda: 0)
        self.intervalo_cache_alerta = 300 # 5 minutos

    def procesar_paquete(self, paquete_wrapper):
        """
        Punto de entrada principal para el análisis de cada paquete.
        """
        try:
            # 1. Registrar para estadísticas generales
            if self.calculador_estadisticas:
                self.calculador_estadisticas.registrar_paquete(paquete_wrapper)

            # 2. Analizar protocolos de aplicación (HTTP, DNS, etc.)
            info_app = analizar_protocolo_aplicacion(paquete_wrapper)
            if info_app:
                paquete_wrapper.info_adicional.update(info_app)

            # 3. Registrar conexión para análisis de comportamiento
            self._registrar_conexion(paquete_wrapper)
            
            # 4. Ejecutar todas las detecciones
            self._detectar_escaneo_puertos(paquete_wrapper)
            self._detectar_fuerza_bruta(paquete_wrapper) # Simplificado
            self._detectar_trafico_anomalo_volumen(paquete_wrapper)
            self._detectar_comunicacion_ip_maliciosa(paquete_wrapper)
            self._detectar_protocolos_no_autorizados(paquete_wrapper)
            self._evaluar_reglas_personalizadas(paquete_wrapper)
            
            # 5. Guardar paquete en base de datos (si es relevante)
            self._guardar_paquete_bd(paquete_wrapper)  # Guardamos todos los paquetes en la BD

        except Exception as e:
            self.logger.error(f"Error procesando paquete: {e}")

    def _registrar_conexion(self, paquete):
        if not paquete.ip_origen: return
        self.conexiones_por_ip[paquete.ip_origen].append(paquete)

    def _generar_alerta(self, tipo, mensaje, paquete, severidad, detalles_adicionales=None):
        """Genera y envía una alerta, evitando duplicados."""
        ahora = time.time()
        # Clave para cache: tipo de alerta + IP origen
        cache_key = f"{tipo}-{paquete.ip_origen}"
        
        if (ahora - self.cache_alertas[cache_key]) > self.intervalo_cache_alerta:
            self.cache_alertas[cache_key] = ahora
            
            alerta = {
                'timestamp': paquete.timestamp,
                'tipo': tipo,
                'mensaje': mensaje,
                'severidad': severidad,
                'datos': {
                    'ip_origen': paquete.ip_origen,
                    'ip_destino': paquete.ip_destino,
                    'puerto_origen': paquete.puerto_origen,
                    'puerto_destino': paquete.puerto_destino,
                    'protocolo': paquete.protocolo,
                    **(detalles_adicionales or {})
                }
            }

            if self.sistema_alertas:
                self.sistema_alertas.procesar_alerta(alerta)

            if self.gestor_bd:
                self.gestor_bd.guardar_alerta(alerta)

            self.logger.warning(f"ALERTA GENERADA: {mensaje}")

    def _detectar_escaneo_puertos(self, paquete):
        if not paquete.ip_origen or not paquete.puerto_destino: return
        
        ip_origen = paquete.ip_origen
        self.puertos_escaneados[ip_origen].add(paquete.puerto_destino)
        
        # Limpiar puertos antiguos para no crecer indefinidamente
        # (Una implementación más robusta usaría timestamps)
        if len(self.puertos_escaneados[ip_origen]) > 1000:
            self.puertos_escaneados[ip_origen].clear()

        if len(self.puertos_escaneados[ip_origen]) > self.config_reglas.get('max_puertos_por_minuto', 20):
            self._generar_alerta(
                'ESCANEO_PUERTOS',
                f'Posible escaneo de puertos desde {ip_origen}',
                paquete, 'MEDIA',
                {'puertos_contactados': len(self.puertos_escaneados[ip_origen])}
            )
            # Resetear para no generar alertas continuas para la misma IP
            self.puertos_escaneados[ip_origen].clear()

    def _detectar_fuerza_bruta(self, paquete):
        # Esta es una detección simplificada. Una real necesitaría
        # analizar fallos de login en protocolos como SSH, RDP, etc.
        # Aquí simulamos detectando muchas conexiones TCP a puertos críticos.
        if not paquete.es_tcp() or not paquete.puerto_destino: return
        
        puertos_criticos = {21, 22, 23, 3389, 3306} # FTP, SSH, Telnet, RDP, MySQL
        if paquete.puerto_destino in puertos_criticos:
            key = f"{paquete.ip_origen}:{paquete.puerto_destino}"
            self.intentos_conexion_fallidos[paquete.ip_origen][paquete.puerto_destino] += 1
            
            intentos = self.intentos_conexion_fallidos[paquete.ip_origen][paquete.puerto_destino]
            max_intentos = self.config_reglas.get('max_intentos_conexion', 30)

            if intentos > max_intentos:
                self._generar_alerta(
                    'FUERZA_BRUTA',
                    f'Posible ataque de fuerza bruta a puerto {paquete.puerto_destino} desde {paquete.ip_origen}',
                    paquete, 'ALTA',
                    {'intentos': intentos}
                )
                self.intentos_conexion_fallidos[paquete.ip_origen][paquete.puerto_destino] = 0


    def _detectar_trafico_anomalo_volumen(self, paquete):
        if not paquete.ip_origen: return

        ip_origen = paquete.ip_origen
        stats_ip = self.volumen_trafico_ip[ip_origen]
        
        # Reiniciar si ha pasado más de un minuto
        ahora = time.time()
        if (ahora - stats_ip['timestamp']) > 60:
            stats_ip['bytes'] = 0
            stats_ip['paquetes'] = 0
            stats_ip['timestamp'] = ahora

        stats_ip['bytes'] += paquete.tamaño
        stats_ip['paquetes'] += 1

        if stats_ip['bytes'] > self.config_reglas.get('max_bytes_por_minuto', 10485760):
            self._generar_alerta(
                'TRAFICO_ANOMALO_VOLUMEN',
                f'Volumen de tráfico anómalo desde {ip_origen}',
                paquete, 'MEDIA',
                {'bytes_en_minuto': stats_ip['bytes']}
            )
            stats_ip['bytes'] = 0 # Reset para evitar alertas continuas

    def _detectar_comunicacion_ip_maliciosa(self, paquete):
        if paquete.ip_origen in self.ips_maliciosas:
            self._generar_alerta('IP_MALICIOSA', f'Tráfico originado en IP maliciosa conocida: {paquete.ip_origen}', paquete, 'ALTA')
        if paquete.ip_destino in self.ips_maliciosas:
            self._generar_alerta('IP_MALICIOSA', f'Tráfico destinado a IP maliciosa conocida: {paquete.ip_destino}', paquete, 'ALTA')

    def _detectar_protocolos_no_autorizados(self, paquete):
        protocolos_no_autorizados = self.config_reglas.get('protocolos_no_autorizados', [])
        if paquete.protocolo.upper() in protocolos_no_autorizados:
            self._generar_alerta(
                'PROTOCOLO_NO_AUTORIZADO',
                f'Uso detectado de protocolo no autorizado ({paquete.protocolo}) desde {paquete.ip_origen}',
                paquete, 'BAJA'
            )

    def _evaluar_reglas_personalizadas(self, paquete):
        for regla in self.config_reglas.get('reglas_personalizadas', []):
            if self._paquete_cumple_regla(paquete, regla['condiciones']):
                self._generar_alerta(
                    f"REGLA_PERSONALIZADA:{regla['nombre']}",
                    f"Regla personalizada '{regla['nombre']}' activada por tráfico desde {paquete.ip_origen}",
                    paquete, regla.get('severidad', 'MEDIA'),
                    {'descripcion_regla': regla.get('descripcion', '')}
                )

    def _paquete_cumple_regla(self, paquete, condiciones):
        for campo, valor_esperado in condiciones.items():
            valor_paquete = getattr(paquete, campo, None)
            if valor_paquete != valor_esperado:
                return False
        return True

    def _guardar_paquete_bd(self, paquete):
        """Guarda información del paquete en la base de datos."""
        if self.gestor_bd:
            datos_paquete = {
                'timestamp': paquete.timestamp,
                'ip_origen': paquete.ip_origen,
                'ip_destino': paquete.ip_destino,
                'puerto_origen': paquete.puerto_origen,
                'puerto_destino': paquete.puerto_destino,
                'protocolo': paquete.obtener_protocolo_nombre(),
                'tamaño': paquete.tamaño,
                'info_adicional': json.dumps(paquete.info_adicional) if paquete.info_adicional else None
            }
            self.gestor_bd.guardar_paquete(datos_paquete)
