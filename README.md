# Sistema de Monitoreo y Análisis de Tráfico de Red

Sistema integral de ciberseguridad desarrollado en Python para el monitoreo continuo del tráfico de red, detección automática de amenazas y generación de alertas en tiempo real. Diseñado para proporcionar visibilidad completa sobre la actividad de red y detectar patrones maliciosos de forma proactiva.

## Descripción del Sistema

Este sistema implementa un motor de análisis de tráfico de red que opera en tiempo real, capturando y analizando paquetes para identificar comportamientos sospechosos como escaneos de puertos, ataques de fuerza bruta, comunicaciones con IPs maliciosas conocidas y uso de protocolos no autorizados. La arquitectura modular permite una fácil extensión y personalización de las reglas de detección.

## Tecnologías Utilizadas

### Scapy - Captura y Análisis de Paquetes
Biblioteca especializada en manipulación de paquetes de red que permite la captura en tiempo real y el análisis detallado de protocolos. Se eligió por su capacidad de trabajar a bajo nivel con diferentes tipos de paquetes y su flexibilidad para crear filtros personalizados.

### SQLAlchemy - Gestión de Base de Datos
ORM robusto que facilita la interacción con la base de datos SQLite, proporcionando un mapeo objeto-relacional eficiente. Su elección se debe a la portabilidad, facilidad de configuración y capacidad de manejar grandes volúmenes de datos de tráfico de red.

### Flask - Interfaz Web
Framework web ligero y flexible que permite crear una interfaz de usuario intuitiva para la visualización de datos en tiempo real. Se seleccionó por su simplicidad, rapidez de desarrollo y capacidad de integración con JavaScript para actualizaciones dinámicas.

### SQLite - Almacenamiento de Datos
Base de datos embebida que no requiere configuración adicional, ideal para sistemas de monitoreo que necesitan almacenar grandes cantidades de datos de tráfico y alertas de forma eficiente y sin dependencias externas.

## Características Principales

- **Captura de tráfico en tiempo real** utilizando Scapy con soporte para múltiples interfaces de red
- **Motor de detección de amenazas** con algoritmos para identificar escaneos de puertos, ataques de fuerza bruta y comportamientos anómalos
- **Sistema de alertas multicanalal** con notificaciones por email y registro en logs
- **Dashboard web interactivo** con visualización de estadísticas y alertas en tiempo real
- **Base de datos integrada** para almacenamiento histórico de paquetes, alertas y estadísticas
- **Análisis de protocolos** con soporte para HTTP, DNS, TCP y UDP
- **Configuración flexible** mediante archivos JSON para reglas de detección personalizadas
- **Arquitectura modular** que permite extensiones y personalizaciones

## Requisitos del Sistema

- Python 3.7 o superior
- Permisos de administrador para captura de paquetes de red
- Compatible con Windows, Linux y macOS
- Mínimo 512 MB de RAM disponible
- Espacio en disco para almacenamiento de logs y base de datos

## Instalación y Configuración

### Instalación Automática (Windows)
```bash
instalar.bat
```

### Instalación Manual
```bash
pip install -r requirements.txt
python inicializar_proyecto.py
```

### Configuración Inicial
Editar el archivo `config.json` para personalizar:
- Interfaz de red a monitorear
- Configuración de alertas por email
- Reglas de detección personalizadas
- Puerto del servidor web
- Parámetros de la base de datos

## Uso del Sistema

### Ejecución
```bash
# Windows (ejecutar como administrador)
python main.py

# Linux/macOS
sudo python3 main.py
```

### Acceso al Dashboard
Abrir navegador web en: `http://localhost:8080`

El dashboard proporciona:
- Estadísticas de tráfico en tiempo real
- Gráficos de distribución de protocolos
- Lista de alertas de seguridad recientes
- Métricas de rendimiento del sistema

## Arquitectura del Sistema
