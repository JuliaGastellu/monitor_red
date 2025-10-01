def convertir_bytes_a_legible(num_bytes):
    """
    Convierte un número de bytes a un formato legible (KB, MB, GB, etc.).

    Args:
        num_bytes (int): El número de bytes.

    Returns:
        str: La representación legible de los bytes.
    """
    if num_bytes is None:
        return "0 B"

    power = 1024
    n = 0
    power_labels = {0: '', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}

    while num_bytes >= power and n < len(power_labels) - 1:
        num_bytes /= power
        n += 1

    return f"{num_bytes:.2f} {power_labels[n]}B"

def obtener_timestamp_legible(ts):
    """
    Convierte un timestamp a una cadena de texto legible.

    Args:
        ts (int, float, datetime): El timestamp a convertir.

    Returns:
        str: La fecha y hora en formato legible.
    """
    from datetime import datetime
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    if isinstance(ts, datetime):
        return ts.strftime('%Y-%m-%d %H:%M:%S')
    return str(ts)
