# Monitor de Red - Sistema de Detección de Amenazas

Sistema avanzado de monitoreo y análisis de tráfico de red en tiempo real, diseñado para detectar amenazas de seguridad y proporcionar alertas inmediatas.

## Características Principales

- Captura y análisis de tráfico de red en tiempo real
- Detección de patrones de tráfico sospechosos y amenazas potenciales
- Dashboard web interactivo con estadísticas y visualizaciones
- Sistema de alertas configurable (email y logs)
- Almacenamiento de datos en base de datos SQLite
- Interfaz en español con documentación completa

## Tecnologías Utilizadas

El sistema ha sido desarrollado utilizando tecnologías modernas y eficientes:

- **Scapy**: Biblioteca potente para manipulación de paquetes de red. Elegida por su flexibilidad para capturar y analizar tráfico de red a bajo nivel, permitiendo una inspección detallada de los paquetes.

- **SQLAlchemy**: ORM (Object-Relational Mapping) que facilita la interacción con la base de datos. Seleccionada por su robustez y capacidad para abstraer la complejidad de las operaciones de base de datos, permitiendo un código más mantenible.

- **Flask**: Framework web ligero y versátil para la creación del dashboard. Escogido por su simplicidad y eficiencia para crear aplicaciones web sin agregar complejidad innecesaria.

- **SQLite**: Sistema de gestión de bases de datos relacional. Elegido por su naturaleza embebida que no requiere un servidor separado, facilitando la instalación y portabilidad del sistema.

## Arquitectura del Sistema

El monitor de red está estructurado en módulos independientes que trabajan en conjunto:

1. **Capturador**: Intercepta paquetes de red utilizando Scapy con soporte para Windows (socket raw) y Linux/macOS (sniff directo)
2. **Analizador**: Procesa los paquetes para detectar patrones sospechosos mediante múltiples detectores especializados
3. **Sistema de Alertas**: Notifica sobre amenazas detectadas por log y opcionalmente por email
4. **Base de Datos**: Almacena paquetes, alertas y estadísticas usando SQLite con SQLAlchemy ORM
5. **Servidor Web**: Proporciona una interfaz visual para monitoreo con actualización automática cada 5 segundos

Esta arquitectura modular facilita el mantenimiento y la extensión del sistema, permitiendo agregar nuevas funcionalidades sin afectar los componentes existentes.

## Capacidades de Detección

El sistema implementa múltiples detectores de amenazas:

- **Escaneo de Puertos**: Detecta cuando una IP contacta múltiples puertos en poco tiempo
- **Ataques de Fuerza Bruta**: Identifica múltiples intentos de conexión a puertos críticos (SSH, RDP, FTP, MySQL, Telnet)
- **Tráfico Anómalo por Volumen**: Alerta sobre volúmenes inusuales de datos desde una IP
- **IPs Maliciosas Conocidas**: Compara tráfico contra una lista de IPs maliciosas configurables
- **Protocolos No Autorizados**: Detecta uso de protocolos prohibidos según configuración
- **Reglas Personalizadas**: Sistema flexible para definir reglas de detección propias

## Requisitos

- Python 3.8 o superior
- Privilegios de administrador para captura de paquetes
- En Windows: [Npcap](https://npcap.com/#download) instalado (requerido por Scapy)
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

### Requisitos adicionales para Windows
Para que la captura de paquetes funcione correctamente en Windows, es necesario instalar Npcap:
1. Descargar Npcap desde [https://npcap.com/#download](https://npcap.com/#download)
2. Instalar con las opciones predeterminadas

### Configuración Inicial
Editar el archivo `config.json` para personalizar:
- Interfaz de red a monitorear (null para autodetección)
- Configuración de alertas por email (deshabilitado por defecto)
- Puerto del servidor web (8080 por defecto)
- Ruta de la base de datos

Editar `src/configuracion/reglas_deteccion.json` para ajustar:
- Umbrales de detección (puertos por minuto, intentos de conexión, etc.)
- Lista de IPs maliciosas conocidas
- Protocolos no autorizados
- Reglas personalizadas de detección

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
- Estadísticas de tráfico en tiempo real (paquetes, volumen, tasa)
- Gráfico circular de distribución de protocolos
- Tabla de alertas de seguridad recientes con severidad codificada por color
- Actualización automática cada 5 segundos

### Navegación
- **Dashboard**: Vista principal con estadísticas y alertas recientes
- **Alertas**: Historial completo de todas las alertas generadas con detalles

## Casos de Uso

- **Monitoreo de seguridad**: Detección de escaneos de puertos, intentos de fuerza bruta y tráfico anómalo.
- **Análisis de red**: Visualización de patrones de tráfico y estadísticas de uso.
- **Auditoría**: Registro detallado de comunicaciones para cumplimiento normativo.
- **Educación**: Herramienta didáctica para entender protocolos y seguridad de red.

## Estructura del Proyecto

```
monitor_red/
├── src/
│   ├── __init__.py
│   ├── alertas/
│   │   ├── __init__.py
│   │   └── sistema_alertas.py          # Gestión de alertas (log y email)
│   ├── analizador/
│   │   ├── __init__.py
│   │   ├── analizador_protocolos.py    # Análisis de HTTP y DNS
│   │   ├── detector_amenazas.py        # Motor de detección de amenazas
│   │   └── estadisticas.py             # Cálculo de estadísticas en tiempo real
│   ├── base_datos/
│   │   ├── __init__.py
│   │   ├── gestor_bd.py                # Gestión de operaciones de BD
│   │   └── modelos.py                  # Modelos SQLAlchemy (Paquete, Alerta, Estadistica)
│   ├── capturador/
│   │   ├── __init__.py
│   │   ├── captura_paquetes.py         # Captura con Scapy (Windows/Linux)
│   │   └── filtros.py                  # Construcción de filtros BPF
│   ├── configuracion/
│   │   ├── __init__.py
│   │   ├── config.py                   # Carga de configuración del sistema
│   │   └── reglas_deteccion.json       # Reglas y umbrales de detección
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── logger.py                   # Configuración de logging
│   │   └── utilidades.py               # Funciones auxiliares
│   └── web/
│       ├── __init__.py
│       ├── servidor.py                 # Servidor Flask
│       ├── static/
│       │   ├── css/
│       │   │   └── estilos.css         # Estilos del dashboard
│       │   └── js/
│       │       └── dashboard.js        # Lógica del dashboard
│       └── templates/
│           ├── base.html               # Plantilla base
│           ├── dashboard.html          # Vista principal
│           └── alertas.html            # Vista de alertas
├── data/
│   ├── logs/                           # Logs del sistema
│   ├── reglas/                         # Reglas adicionales
│   └── monitor_red.db                  # Base de datos SQLite (generada)
├── docs/
│   ├── configuracion.md                # Guía de configuración
│   ├── instalacion.md                  # Guía de instalación
│   └── manual_usuario.md               # Manual de usuario
├── tests/
│   ├── test_alertas.py                 # Tests del sistema de alertas
│   ├── test_analizador.py              # Tests del analizador
│   └── test_capturador.py              # Tests del capturador
├── main.py                             # Punto de entrada principal
├── config.json                         # Configuración general
├── requirements.txt                    # Dependencias Python
├── setup.py                            # Script de instalación
├── inicializar_proyecto.py             # Inicialización de directorios
└── instalar.bat                        # Instalador automático (Windows)
```

## Funcionamiento Interno

### Flujo de Datos

1. **Captura**: `CapturadorPaquetes` intercepta paquetes de red usando Scapy
2. **Normalización**: Los paquetes se envuelven en `PaqueteWrapper` para extraer información relevante
3. **Análisis**: `DetectorAmenazas` ejecuta múltiples detectores sobre cada paquete
4. **Estadísticas**: `CalculadorEstadisticas` registra métricas y las guarda periódicamente
5. **Alertas**: Cuando se detecta una amenaza, `SistemaAlertas` notifica según configuración
6. **Almacenamiento**: `GestorBaseDatos` guarda paquetes, alertas y estadísticas en SQLite
7. **Visualización**: `ServidorWeb` expone una API REST que el dashboard consulta cada 5 segundos

### Hilos de Ejecución

El sistema ejecuta múltiples hilos concurrentes:
- **Hilo principal**: Coordina el sistema y maneja señales
- **Hilo de captura**: Ejecuta el bucle de captura de paquetes
- **Hilo web**: Servidor Flask para el dashboard
- **Hilo de estadísticas**: Calcula y guarda estadísticas cada 60 segundos

**Autora: Julia Gastellu - 2025**