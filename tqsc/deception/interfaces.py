"""
tqsc/deception/interfaces.py — Contratos abstractos para la malla de engaño.
Permite DI, testing con mocks, y reemplazo de implementaciones.
"""
from abc import ABC, abstractmethod
from typing import Optional, Protocol


class ITokenGenerator(ABC):
    @abstractmethod
    def generar(self, tipo: str, ubicacion: str, memo: str = "") -> dict: ...

    @abstractmethod
    def verificar(self, valor: str) -> Optional[dict]: ...


class IHoneyFile(ABC):
    @abstractmethod
    def plantar(self, directorios: list[str] = None): ...

    @abstractmethod
    def verificar(self): ...


class IHoneyCredential(ABC):
    @abstractmethod
    def generar_lote(self, cantidad: int): ...

    @abstractmethod
    def eliminar_todos(self): ...


class ICanaryDNS(ABC):
    @abstractmethod
    def generar(self, memo: str = "") -> str: ...

    @abstractmethod
    def verificar(self, dominio: str) -> bool: ...


class ICanaryHTTP(ABC):
    @abstractmethod
    def iniciar(self): ...


class IStorage(ABC):
    @abstractmethod
    def guardar(self, coleccion: str, datos: dict) -> str: ...

    @abstractmethod
    def consultar(self, coleccion: str, filtro: dict = None, limite: int = 100) -> list[dict]: ...


class IAlertEngine(ABC):
    @abstractmethod
    def disparar(self, alerta: dict): ...

    @abstractmethod
    def correlacionar(self, alerta: dict) -> Optional[dict]: ...
