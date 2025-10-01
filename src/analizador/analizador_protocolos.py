from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import TCP
from scapy.packet import Raw


def analizar_http(paquete_scapy):
    """
    Analiza un paquete HTTP y extrae información detallada.

    Args:
        paquete_scapy: El paquete original de Scapy.

    Returns:
        Un diccionario con la información HTTP, o None si no es HTTP.
    """
    # Scapy a veces no disecta HTTP si no está en el puerto 80,
    # por lo que revisamos la capa Raw.
    if not paquete_scapy.haslayer(HTTPRequest) and not paquete_scapy.haslayer(HTTPResponse):
        if not paquete_scapy.haslayer(Raw):
            return None
        try:
            # Intentar decodificar como HTTPRequest
            http_layer = HTTPRequest(paquete_scapy[Raw].load)
        except Exception:
            try:
                # Intentar decodificar como HTTPResponse
                http_layer = HTTPResponse(paquete_scapy[Raw].load)
            except Exception:
                return None
    else:
        http_layer = paquete_scapy.getlayer(HTTPRequest) or paquete_scapy.getlayer(HTTPResponse)

    info_http = {}
    if isinstance(http_layer, HTTPRequest):
        info_http['tipo'] = 'request'
        info_http['host'] = http_layer.Host.decode() if http_layer.Host else 'N/A'
        info_http['metodo'] = http_layer.Method.decode() if http_layer.Method else 'N/A'
        info_http['ruta'] = http_layer.Path.decode() if http_layer.Path else 'N/A'
        return info_http

    if isinstance(http_layer, HTTPResponse):
        info_http['tipo'] = 'response'
        info_http['codigo_estado'] = http_layer.Status_Code.decode() if hasattr(http_layer, 'Status_Code') and http_layer.Status_Code else 'N/A'
        info_http['frase_estado'] = http_layer.Reason_Phrase.decode() if hasattr(http_layer, 'Reason_Phrase') and http_layer.Reason_Phrase else 'N/A'
        return info_http

    return None

def analizar_dns(paquete_scapy):
    """
    Analiza un paquete DNS y extrae información de la consulta/respuesta.

    Args:
        paquete_scapy: El paquete original de Scapy.

    Returns:
        Un diccionario con la información DNS, o None si no es DNS.
    """
    if not paquete_scapy.haslayer(DNS):
        return None

    dns_layer = paquete_scapy.getlayer(DNS)
    info_dns = {'id_transaccion': dns_layer.id}

    # Es una consulta (Query)
    if dns_layer.qr == 0 and dns_layer.qd:
        info_dns['tipo'] = 'query'
        info_dns['consulta'] = dns_layer.qd.qname.decode()
        info_dns['tipo_q'] = dns_layer.qd.qtype
        return info_dns

    # Es una respuesta (Response)
    elif dns_layer.qr == 1 and dns_layer.an:
        info_dns['tipo'] = 'response'
        info_dns['consulta'] = dns_layer.question.qname.decode()
        respuestas = []
        for i in range(dns_layer.ancount):
            respuesta = dns_layer.an[i]
            if isinstance(respuesta, DNSRR):
                respuestas.append({
                    'nombre': respuesta.rrname.decode(),
                    'tipo': respuesta.type,
                    'ttl': respuesta.ttl,
                    'datos': str(respuesta.rdata)
                })
        info_dns['respuestas'] = respuestas
        return info_dns

    return None

def analizar_protocolo_aplicacion(paquete_wrapper):
    """
    Función principal que intenta analizar protocolos de aplicación
    comunes dentro de un paquete.

    Args:
        paquete_wrapper: Una instancia de PaqueteWrapper.

    Returns:
        Un diccionario con la información del protocolo de aplicación, o None.
    """
    paquete_scapy = paquete_wrapper.paquete_original

    # HTTP se ejecuta comúnmente sobre el puerto 80, pero puede estar en otros (8080)
    if paquete_wrapper.protocolo == 'TCP':
        if paquete_scapy.haslayer(Raw):
            http_info = analizar_http(paquete_scapy)
            if http_info:
                return {'protocolo': 'HTTP', 'datos': http_info}

    # DNS se ejecuta comúnmente sobre el puerto 53
    if paquete_wrapper.protocolo == 'UDP' and (paquete_wrapper.puerto_destino == 53 or paquete_wrapper.puerto_origen == 53):
        if paquete_scapy.haslayer(DNS):
            dns_info = analizar_dns(paquete_scapy)
            if dns_info:
                return {'protocolo': 'DNS', 'datos': dns_info}

    # Aquí se podrían añadir más analizadores (e.g., TLS/SSL, FTP, etc.)

    return None
