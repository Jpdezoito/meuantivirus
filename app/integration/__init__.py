"""Camada de integracao entre o nucleo do SentinelaPC e clientes externos."""

from app.integration.antivirus_bridge import AntivirusBridge, get_bridge

__all__ = ["AntivirusBridge", "get_bridge"]
