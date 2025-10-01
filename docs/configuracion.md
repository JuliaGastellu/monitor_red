# Guía de Configuración

La configuración principal de la aplicación se gestiona a través de dos archivos:

1.  `config.json` (opcional, en la raíz del proyecto)
2.  `src/configuracion/reglas_deteccion.json`

## `config.json`

Este archivo permite sobreescribir la configuración por defecto. Si no existe, se usarán los valores predeterminados.

Ejemplo de `config.json`:
```json
{
    "interfaz_red": "eth0",
    "puerto_web": 8080,
    "debug_web": false
}
```

## `reglas_deteccion.json`

Este archivo contiene las reglas que el motor de detección de amenazas utiliza.

### Secciones:
-   `max_puertos_por_minuto`: Umbral para la detección de escaneo de puertos.
-   `max_intentos_conexion`: Umbral para la detección de ataques de fuerza bruta.
-   `ips_maliciosas_conocidas`: Una lista de direcciones IP a vigilar.
-   `protocolos_no_autorizados`: Una lista de protocolos que generarán una alerta.
-   `reglas_personalizadas`: Define reglas con condiciones específicas.
