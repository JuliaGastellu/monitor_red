#!/usr/bin/env python3
"""
Script para inicializar el proyecto creando directorios necesarios
"""
import os

def crear_directorios():
    """Crea los directorios necesarios para el proyecto"""
    directorios = [
        'data/logs',
        'data/reglas'
    ]
    
    for directorio in directorios:
        try:
            os.makedirs(directorio, exist_ok=True)
            print(f"Directorio creado: {directorio}")
        except Exception as e:
            print(f"Error creando directorio {directorio}: {e}")

if __name__ == "__main__":
    print("Inicializando proyecto Monitor de Red...")
    crear_directorios()
    print("Inicialización completada.")