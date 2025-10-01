import smtplib
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from src.utils.logger import configurar_logger

class SistemaAlertas:
    """
    Gestiona el envío de alertas a través de diferentes canales.
    """
    def __init__(self, config):
        self.config = config
        self.logger = configurar_logger('SistemaAlertas')
        self.manejadores_alerta = []
        self._configurar_manejadores()

    def _configurar_manejadores(self):
        """Configura los manejadores de alertas basados en la configuración."""
        if self.config.alertas_log.get('habilitado'):
            self.manejadores_alerta.append(self._manejar_alerta_log)
            self.logger.info("Manejador de alertas por log habilitado.")

        if self.config.alertas_email.get('habilitado'):
            self.manejadores_alerta.append(self._manejar_alerta_email)
            self.logger.info("Manejador de alertas por email habilitado.")

    def procesar_alerta(self, alerta):
        """
        Procesa una alerta y la envía a todos los manejadores configurados.
        """
        for manejador in self.manejadores_alerta:
            try:
                manejador(alerta)
            except Exception as e:
                self.logger.error(f"Error en el manejador de alertas {manejador.__name__}: {e}")

    def _formatear_alerta_texto(self, alerta):
        """Formatea una alerta como texto plano."""
        mensaje = f"""
Alerta de Seguridad del Monitor de Red
=====================================
Tipo: {alerta['tipo']}
Severidad: {alerta['severidad']}
Timestamp: {alerta['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}
Mensaje: {alerta['mensaje']}

Detalles:
---------
"""
        if alerta.get('datos'):
            detalles_json = json.dumps(alerta['datos'], indent=4, default=str)
            mensaje += detalles_json

        return mensaje

    def _manejar_alerta_log(self, alerta):
        """Escribe la alerta en un archivo de log dedicado."""
        try:
            # Se podría usar un logger específico para alertas si se quisiera
            # un formato o archivo diferente al log principal.
            mensaje_formateado = self._formatear_alerta_texto(alerta).replace('\n', ' ')
            self.logger.warning(f"ALERTA REGISTRADA: {mensaje_formateado}")
        except Exception as e:
            self.logger.error(f"No se pudo escribir la alerta al log: {e}")

    def _manejar_alerta_email(self, alerta):
        """Envía la alerta por correo electrónico."""
        cfg_email = self.config.alertas_email

        msg = MIMEMultipart()
        msg['From'] = cfg_email['usuario_smtp']
        msg['To'] = cfg_email['destinatario']
        msg['Subject'] = f"[ALERTA DE SEGURIDAD] {alerta['tipo']} - Severidad {alerta['severidad']}"

        cuerpo_mensaje = self._formatear_alerta_texto(alerta)
        msg.attach(MIMEText(cuerpo_mensaje, 'plain'))

        try:
            with smtplib.SMTP(cfg_email['servidor_smtp'], cfg_email['puerto_smtp']) as server:
                server.starttls()
                server.login(cfg_email['usuario_smtp'], cfg_email['password_smtp'])
                server.send_message(msg)
                self.logger.info(f"Alerta enviada por email a {cfg_email['destinatario']}")
        except smtplib.SMTPAuthenticationError:
            self.logger.error("Error de autenticación SMTP. Revisa usuario/contraseña.")
        except Exception as e:
            self.logger.error(f"No se pudo enviar el email de alerta: {e}")
