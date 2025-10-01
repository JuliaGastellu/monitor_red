from setuptools import setup, find_packages

setup(
    name='monitor_red',
    version='0.1.0',
    description='Un monitor de tráfico de red y sistema de detección de amenazas.',
    author='Jules',
    packages=find_packages(),
    install_requires=[
        'scapy',
        'SQLAlchemy',
        'Flask',
    ],
    entry_points={
        'console_scripts': [
            'monitor_red=main:main',
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.8',
)
