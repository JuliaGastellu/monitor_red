# Sistema de Monitoreo y Análisis de Tráfico de Red

Sistema completo de ciberseguridad para monitoreo de red en tiempo real, detección de amenazas y generación de alertas automáticas.

## Características

- **Captura de tráfico** en tiempo real usando Scapy
- **Detección de amenazas** automática (escaneo de puertos, fuerza bruta, IPs maliciosas)
- **Sistema de alertas** por email y logs
- **Dashboard web** en tiempo real
- **Base de datos** SQLite para almacenamiento
- **Estadísticas** de tráfico de red
- **Análisis de protocolos** (HTTP, DNS, TCP, UDP)

## Requisitos

- Python 3.7+
- Permisos de administrador (para captura de paquetes)
- Windows/Linux/macOS

## Instalación

1. Clonar el repositorio
2. Ejecutar `instalar.bat` (Windows) o instalar manualmente:
   ```bash
   pip install -r requirements.txt
   ```
3. Configurar `config.json` según necesidades

## Uso

```bash
# Windows (como administrador)
python main.py

# Linux/macOS
sudo python3 main.py
```

Acceder al dashboard: http://localhost:8080

## Configuración

Editar `config.json` para:
- Cambiar interfaz de red
- Configurar alertas por email
- Ajustar reglas de detección
- Modificar puerto web

## Estructura del Proyecto
