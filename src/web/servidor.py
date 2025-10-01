from flask import Flask, render_template, jsonify
from threading import Thread
from src.utils.logger import configurar_logger
from src.utils.utilidades import convertir_bytes_a_legible, obtener_timestamp_legible
import json

class ServidorWeb:
    """
    Servidor web Flask para la visualización de datos.
    """
    def __init__(self, gestor_bd, config):
        # Corregir la ruta a las plantillas y archivos estáticos
        self.app = Flask(__name__, template_folder='templates', static_folder='static')
        self.gestor_bd = gestor_bd
        self.config = config
        self.logger = configurar_logger('ServidorWeb')
        self._configurar_rutas()

        # Inyectar funciones útiles en las plantillas
        self.app.jinja_env.globals.update(
            convertir_bytes_a_legible=convertir_bytes_a_legible,
            obtener_timestamp_legible=obtener_timestamp_legible
        )

    def _configurar_rutas(self):
        """Define las rutas y endpoints de la API."""
        self.app.route('/')(self.dashboard)
        self.app.route('/alertas')(self.vista_alertas)
        self.app.route('/api/datos_dashboard')(self.api_datos_dashboard)

    def dashboard(self):
        """Renderiza el panel principal."""
        return render_template('dashboard.html', titulo="Dashboard")

    def vista_alertas(self):
        """Renderiza la vista histórica de alertas."""
        try:
            alertas = self.gestor_bd.obtener_alertas_recientes(limite=100)
            return render_template('alertas.html', titulo="Alertas", alertas=alertas)
        except Exception as e:
            self.logger.error(f"Error al obtener alertas para la vista: {e}")
            return render_template('alertas.html', titulo="Alertas", alertas=[], error="No se pudieron cargar las alertas.")

    def api_datos_dashboard(self):
        """Endpoint de la API para proveer datos al dashboard en tiempo real."""
        try:
            alertas = self.gestor_bd.obtener_alertas_recientes(limite=10)
            estadisticas = self.gestor_bd.obtener_estadisticas_recientes()

            # Formatear datos para que sean serializables en JSON
            datos_alertas = [
                {
                    'timestamp': a.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    'tipo': a.tipo_alerta,
                    'mensaje': a.mensaje,
                    'severidad': a.severidad,
                    'ip_origen': a.ip_origen
                } for a in alertas
            ]

            datos_estadisticas = {}
            if estadisticas:
                dist_protocolos = json.loads(estadisticas.distribucion_protocolos) if isinstance(estadisticas.distribucion_protocolos, str) else estadisticas.distribucion_protocolos
                datos_estadisticas = {
                    'paquetes_totales': estadisticas.paquetes_totales,
                    'bytes_totales_legible': convertir_bytes_a_legible(estadisticas.bytes_totales),
                    'paquetes_por_segundo': estadisticas.paquetes_por_segundo,
                    'distribucion_protocolos': dist_protocolos
                }

            return jsonify({
                'alertas': datos_alertas,
                'estadisticas': datos_estadisticas
            })
        except Exception as e:
            self.logger.error(f"Error en la API de datos del dashboard: {e}")
            return jsonify({'error': 'No se pudieron obtener los datos'}), 500

    def ejecutar(self, puerto, debug=False):
        """Ejecuta el servidor Flask."""
        self.logger.info(f"Iniciando servidor web en http://0.0.0.0:{puerto}")
        # Usar '0.0.0.0' para que sea accesible desde fuera del contenedor/máquina
        self.app.run(host='0.0.0.0', port=puerto, debug=debug, use_reloader=False)
