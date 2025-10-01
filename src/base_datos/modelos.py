from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Float
from sqlalchemy.orm import declarative_base, sessionmaker
import datetime

Base = declarative_base()

class Paquete(Base):
    """Modelo para los paquetes de red capturados."""
    __tablename__ = 'paquetes'

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.datetime.now)
    ip_origen = Column(String(45))
    ip_destino = Column(String(45))
    puerto_origen = Column(Integer)
    puerto_destino = Column(Integer)
    protocolo = Column(String(10))
    tamaño = Column(Integer)
    info_adicional = Column(Text, nullable=True)

    def __repr__(self):
        return f"<Paquete(id={self.id}, {self.ip_origen}:{self.puerto_origen} -> {self.ip_destino}:{self.puerto_destino})>"

class Alerta(Base):
    """Modelo para las alertas de seguridad generadas."""
    __tablename__ = 'alertas'

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.datetime.now)
    tipo_alerta = Column(String(50))
    severidad = Column(String(20))
    mensaje = Column(Text)
    ip_origen = Column(String(45), nullable=True)
    ip_destino = Column(String(45), nullable=True)
    detalles = Column(Text, nullable=True) # Para almacenar datos JSON

    def __repr__(self):
        return f"<Alerta(id={self.id}, tipo='{self.tipo_alerta}', severidad='{self.severidad}')>"

class Estadistica(Base):
    """Modelo para las estadísticas de red."""
    __tablename__ = 'estadisticas'

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.datetime.now)
    paquetes_totales = Column(Integer)
    bytes_totales = Column(Integer)
    paquetes_por_segundo = Column(Float)
    distribucion_protocolos = Column(Text) # Almacenado como JSON

    def __repr__(self):
        return f"<Estadistica(id={self.id}, paquetes={self.paquetes_totales}, bytes={self.bytes_totales})>"


def crear_engine(ruta_bd):
    """Crea el motor de la base de datos."""
    return create_engine(f'sqlite:///{ruta_bd}')

def inicializar_bd(engine):
    """Crea todas las tablas en la base de datos."""
    Base.metadata.create_all(engine)

def crear_sesion(engine):
    """Crea y retorna una nueva sesión de base de datos."""
    Session = sessionmaker(bind=engine)
    return Session()
