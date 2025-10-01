# Monitor de Red y Detector de Amenazas

## Propósito del Proyecto

Este proyecto es una aplicación de monitoreo de red diseñada para capturar y analizar el tráfico en tiempo real. Su objetivo principal es ofrecer una visión clara del estado de la red y detectar de forma proactiva posibles actividades maliciosas o anómalas, como escaneos de puertos, picos inusuales de tráfico o comunicaciones con direcciones IP conocidas por ser maliciosas.

La herramienta está pensada tanto para administradores de sistemas que necesitan una forma sencilla de vigilar su red, como para entusiastas de la seguridad informática interesados en el análisis de tráfico.

## Funcionamiento

El sistema está compuesto por varios módulos que trabajan en conjunto:

1.  **Capturador de Paquetes**: Utiliza raw sockets para capturar todo el tráfico de red en una interfaz específica. Cada paquete es envuelto en un formato estandarizado para su posterior análisis.

2.  **Motor de Análisis y Detección**: Es el cerebro del sistema. Cada paquete capturado pasa por este motor, que realiza las siguientes tareas:
    - **Análisis de Protocolos**: Identifica protocolos comunes como TCP, UDP, y DNS.
    - **Detección de Amenazas**: Aplica un conjunto de reglas para identificar patrones sospechosos. Las detecciones implementadas incluyen:
        - Escaneo de puertos.
        - Intentos de ataques de fuerza bruta (simplificado).
        - Tráfico anómalo por volumen de datos.
        - Conexiones desde o hacia IPs maliciosas conocidas.
        - Uso de protocolos no autorizados (ej. Telnet).
        - Reglas personalizadas definidas en un archivo de configuración.

3.  **Sistema de Alertas**: Cuando el motor de detección identifica una amenaza, genera una alerta. Estas alertas se registran en la base de datos y se muestran en el dashboard. El sistema es extensible y puede configurarse para enviar notificaciones por otros canales (como email).

4.  **Base de Datos**: Utiliza SQLite para almacenar de forma persistente todas las alertas generadas y las estadísticas de tráfico periódicas. Esto permite un análisis histórico y mantiene un registro de los eventos de seguridad.

5.  **Dashboard Web**: Proporciona una interfaz de usuario web en tiempo real que muestra:
    - Estadísticas clave del tráfico de red (paquetes/segundo, volumen total).
    - Un gráfico con la distribución de los protocolos.
    - Una tabla con las últimas alertas de seguridad detectadas.
    - Una vista histórica de todas las alertas.

## Tecnologías Utilizadas

-   **Python**: El lenguaje principal sobre el que se construye toda la aplicación.
-   **Scapy**: Una potente biblioteca de Python utilizada para la captura, manipulación y análisis de paquetes de red.
-   **Flask**: Un micro-framework de Python utilizado para construir el servidor web y la API que alimenta el dashboard.
-   **SQLAlchemy**: Un ORM (Object-Relational Mapper) que facilita la interacción con la base de datos SQLite de una manera orientada a objetos.
-   **Chart.js**: Una biblioteca de JavaScript para crear gráficos interactivos y visualmente atractivos en el dashboard.
-   **HTML/CSS/JavaScript**: Las tecnologías estándar para la construcción de la interfaz de usuario web.
