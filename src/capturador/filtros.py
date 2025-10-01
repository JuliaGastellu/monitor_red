def construir_filtro_bpf(config_filtros):
    """
    Construye una cadena de filtro BPF a partir de un diccionario de configuración.

    Args:
        config_filtros (dict): Un diccionario con las reglas de filtrado.
            Ejemplo:
            {
                'ip_origen_excluir': ['192.168.1.1', '10.0.0.1'],
                'puerto_incluir': [80, 443],
                'protocolo': 'tcp'
            }

    Returns:
        str: Una cadena de filtro BPF compatible con Scapy/tcpdump.
    """
    filtros = []

    # Excluir IPs de origen
    if 'ip_origen_excluir' in config_filtros and config_filtros['ip_origen_excluir']:
        ips_excluir = ' and '.join([f"not src host {ip}" for ip in config_filtros['ip_origen_excluir']])
        filtros.append(f"({ips_excluir})")

    # Incluir puertos de destino
    if 'puerto_incluir' in config_filtros and config_filtros['puerto_incluir']:
        puertos_incluir = ' or '.join([f"port {p}" for p in config_filtros['puerto_incluir']])
        filtros.append(f"({puertos_incluir})")

    # Filtrar por protocolo
    if 'protocolo' in config_filtros and config_filtros['protocolo']:
        filtros.append(str(config_filtros['protocolo']).lower())

    # Unir todos los filtros con 'and'
    filtro_final = ' and '.join(filtros)

    return filtro_final

if __name__ == '__main__':
    # Ejemplo de uso
    config = {
        'ip_origen_excluir': ['192.168.1.1'],
        'puerto_incluir': [80, 443],
        'protocolo': 'tcp'
    }

    filtro = construir_filtro_bpf(config)
    print(f"Configuración: {config}")
    print(f"Filtro BPF generado: {filtro}")

    config_vacia = {}
    filtro_vacio = construir_filtro_bpf(config_vacia)
    print(f"\nConfiguración vacía: {config_vacia}")
    print(f"Filtro BPF generado: {filtro_vacio}")
