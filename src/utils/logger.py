import logging
import sys
from logging.handlers import RotatingFileHandler

def configurar_logger(nombre, nivel=logging.INFO, archivo_log='data/logs/monitor.log'):
    """
    Configura y retorna un logger.

    Args:
        nombre (str): El nombre del logger.
        nivel (int): El nivel de logging (e.g., logging.INFO).
        archivo_log (str): La ruta al archivo de log.

    Returns:
        logging.Logger: La instancia del logger configurado.
    """
    logger = logging.getLogger(nombre)
    logger.setLevel(nivel)

    # Evitar duplicación de handlers si el logger ya está configurado
    if logger.hasHandlers():
        return logger

    # Formateador
    formato = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Handler para la consola
    handler_consola = logging.StreamHandler(sys.stdout)
    handler_consola.setFormatter(formato)

    # Handler para el archivo con rotación
    try:
        handler_archivo = RotatingFileHandler(
            archivo_log,
            maxBytes=1024 * 1024 * 5, # 5 MB
            backupCount=2
        )
        handler_archivo.setFormatter(formato)
        logger.addHandler(handler_archivo)
    except FileNotFoundError:
        # Esto puede pasar si el directorio de logs no existe.
        # En un escenario real, nos aseguraríamos de que el directorio exista.
        print(f"Advertencia: No se pudo crear el archivo de log en {archivo_log}. El directorio podría no existir.")


    # Añadir handler de consola
    logger.addHandler(handler_consola)

    return logger
