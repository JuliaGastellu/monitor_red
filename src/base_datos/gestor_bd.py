import json
from contextlib import contextmanager
from sqlalchemy import func
from src.base_datos.modelos import Paquete, Alerta, Estadistica, crear_engine, inicializar_bd, crear_sesion
from src.utils.logger import configurar_logger

class GestorBaseDatos:
    """
    Gestiona todas las interacciones con la base de datos SQLite.
    """
    def __init__(self, ruta_bd):
        self.logger = configurar_logger('GestorBaseDatos')
        try:
            self.engine = crear_engine(ruta_bd)
            self.Session = crear_sesion(self.engine)
            self.logger.info(f"Conexión establecida con la base de datos en {ruta_bd}")
        except Exception as e:
            self.logger.error(f"Error al conectar con la base de datos: {e}")
            raise

    def inicializar(self):
        """Inicializa la base de datos creando las tablas si no existen."""
        try:
            inicializar_bd(self.engine)
            self.logger.info("Base de datos inicializada correctamente.")
        except Exception as e:
            self.logger.error(f"Error al inicializar la base de datos: {e}")
            raise

    @contextmanager
    def get_session(self):
        """Provee un contexto transaccional para una sesión de base de datos."""
        session = self.Session()
        try:
            yield session
            session.commit()
        except Exception as e:
            self.logger.error(f"Error en la sesión de base de datos: {e}")
            session.rollback()
            raise
        finally:
            session.close()

    def guardar_paquete(self, datos_paquete):
        """Guarda un nuevo paquete en la base de datos."""
        nuevo_paquete = Paquete(**datos_paquete)
        with self.get_session() as session:
            session.add(nuevo_paquete)

    def guardar_alerta(self, datos_alerta):
        """Guarda una nueva alerta en la base de datos."""
        if isinstance(datos_alerta.get('datos'), dict):
            detalles_json = json.dumps(datos_alerta['datos'])
        else:
            detalles_json = datos_alerta.get('datos')

        alerta = Alerta(
            timestamp=datos_alerta['timestamp'],
            tipo_alerta=datos_alerta['tipo'],
            severidad=datos_alerta['severidad'],
            mensaje=datos_alerta['mensaje'],
            ip_origen=datos_alerta.get('datos', {}).get('ip_origen'),
            ip_destino=datos_alerta.get('datos', {}).get('ip_destino'),
            detalles=detalles_json
        )
        with self.get_session() as session:
            session.add(alerta)
        self.logger.info(f"Alerta guardada: {datos_alerta['tipo']}")

    def guardar_estadistica(self, datos_estadistica):
        """Guarda un nuevo registro de estadísticas."""
        if isinstance(datos_estadistica.get('distribucion_protocolos'), dict):
            datos_estadistica['distribucion_protocolos'] = json.dumps(datos_estadistica['distribucion_protocolos'])

        nueva_estadistica = Estadistica(**datos_estadistica)
        with self.get_session() as session:
            session.add(nueva_estadistica)
        self.logger.info("Estadísticas guardadas.")

    def obtener_alertas_recientes(self, limite=50):
        """Obtiene las alertas más recientes de la base de datos."""
        with self.get_session() as session:
            return session.query(Alerta).order_by(Alerta.timestamp.desc()).limit(limite).all()

    def obtener_estadisticas_recientes(self, limite=1):
        """Obtiene el último registro de estadísticas como diccionario."""
        with self.get_session() as session:
            estadistica = session.query(Estadistica).order_by(Estadistica.timestamp.desc()).limit(limite).first()
            if estadistica:
                return {
                    'id': estadistica.id,
                    'timestamp': estadistica.timestamp,
                    'paquetes_totales': estadistica.paquetes_totales,
                    'bytes_totales': estadistica.bytes_totales,
                    'paquetes_por_segundo': estadistica.paquetes_por_segundo,
                    'distribucion_protocolos': estadistica.distribucion_protocolos
                }
            return None

    def obtener_trafico_total(self):
        """Obtiene el número total de paquetes y bytes."""
        with self.get_session() as session:
            total_paquetes = session.query(func.count(Paquete.id)).scalar()
            total_bytes = session.query(func.sum(Paquete.tamaño)).scalar()
            return total_paquetes or 0, total_bytes or 0

    def cerrar_conexion(self):
        """Cierra la conexión con la base de datos."""
        if self.engine:
            self.engine.dispose()
            self.logger.info("Conexión con la base de datos cerrada.")
