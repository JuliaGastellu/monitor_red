from setuptools import setup, find_packages

setup(
    name="monitor-red",
    version="1.0.0",
    description="Sistema de Monitoreo y Análisis de Tráfico de Red",
    author="Tu Nombre",
    author_email="tu_email@dominio.com",
    packages=find_packages(),
    install_requires=[
        "scapy>=2.4.5",
        "SQLAlchemy>=1.4.0",
        "Flask>=2.0.0"
    ],
    python_requires=">=3.7",
    entry_points={
        "console_scripts": [
            "monitor-red=main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Topic :: System :: Networking :: Monitoring",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
)
