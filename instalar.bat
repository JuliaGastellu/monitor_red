@echo off
echo Instalando dependencias del Monitor de Red...

REM Crear directorios necesarios
mkdir data\logs 2>nul
mkdir data\reglas 2>nul

REM Instalar dependencias de Python
pip install -r requirements.txt

echo.
echo Instalacion completada.
echo Para ejecutar el sistema: python main.py
echo NOTA: Necesita permisos de administrador para capturar trafico de red.
pause