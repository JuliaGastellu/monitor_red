import json
import os

class ConfiguracionSistema:
    """
    Gestiona la configuración general del sistema.
    """
    def __init__(self, ruta_config_json='config.json'):
        # Valores por defecto
        self.interfaz_red = self._get_default_interface()
        self.ruta_bd = 'data/monitor_red.db'
        self.puerto_web = 8080
        self.debug_web = True
        self.ruta_reglas = 'src/configuracion/reglas_deteccion.json'

        # Configuración de alertas (se podría externalizar)
        self.alertas_email = {
            'habilitado': False,
            'servidor_smtp': 'smtp.example.com',
            'puerto_smtp': 587,
            'usuario_smtp': 'user@example.com',
            'password_smtp': 'password',
            'destinatario': 'alerts@example.com'
        }

        self.alertas_log = {
            'habilitado': True,
            'archivo_log': 'data/logs/alertas.log'
        }

        self.reglas_deteccion = self._cargar_reglas()

        # Cargar configuración desde archivo JSON si existe
        if os.path.exists(ruta_config_json):
            self._cargar_desde_json(ruta_config_json)

    def _get_default_interface(self):
        """Obtiene la interfaz de red por defecto según el SO."""
        if os.name == 'nt': # Windows
            # En Windows, scapy puede encontrar la interfaz correcta
            # pero a menudo es necesario especificarla. 'Ethernet' o 'Wi-Fi' son comunes.
            # Devolver None para que scapy intente autodetectar.
            return None
        else: # Linux/macOS
            return 'eth0'

    def _cargar_reglas(self):
        """Carga las reglas de detección desde el archivo JSON."""
        try:
            with open(self.ruta_reglas, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Advertencia: No se pudo cargar el archivo de reglas {self.ruta_reglas}. Se usarán valores por defecto. Error: {e}")
            # Retornar un conjunto de reglas por defecto si el archivo no existe o es inválido
            return {
                "max_puertos_por_minuto": 20,
                "max_intentos_conexion": 50,
                "max_bytes_por_minuto": 10485760,
                "max_paquetes_por_minuto": 1000,
                "reglas_personalizadas": []
            }

    def _cargar_desde_json(self, ruta_config_json):
        """Carga la configuración desde un archivo JSON y sobreescribe los valores por defecto."""
        try:
            with open(ruta_config_json, 'r', encoding='utf-8') as f:
                config_json = json.load(f)
                for key, value in config_json.items():
                    if hasattr(self, key):
                        setattr(self, key, value)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Advertencia: No se pudo cargar el archivo de configuración {ruta_config_json}. Se usarán los valores por defecto. Error: {e}")

    def __str__(self):
        return f"Configuración(Interfaz: {self.interfaz_red}, BD: {self.ruta_bd}, Puerto Web: {self.puerto_web})"
