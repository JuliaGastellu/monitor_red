import logging
import sys
import os
from logging.handlers import RotatingFileHandler

def configurar_logger(nombre, nivel=logging.INFO, archivo_log='data/logs/monitor.log'):
    """
    Configura y retorna un logger.
    """
    logger = logging.getLogger(nombre)
    logger.setLevel(nivel)

    if logger.hasHandlers():
        return logger

    formato = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    handler_consola = logging.StreamHandler(sys.stdout)
    handler_consola.setFormatter(formato)

    try:
        # Crear directorio si no existe
        os.makedirs(os.path.dirname(archivo_log), exist_ok=True)
        
        handler_archivo = RotatingFileHandler(
            archivo_log,
            maxBytes=1024 * 1024 * 5,
            backupCount=2
        )
        handler_archivo.setFormatter(formato)
        logger.addHandler(handler_archivo)
    except Exception as e:
        print(f"Advertencia: No se pudo crear el archivo de log en {archivo_log}: {e}")

    logger.addHandler(handler_consola)
    return logger
