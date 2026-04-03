"""Tipos centrais relacionados a classificacao de risco do SentinelaPC."""

from __future__ import annotations

from enum import StrEnum


class RiskLevel(StrEnum):
    """Enumera os niveis de risco usados pelos modulos de diagnostico."""

    LOW = "baixo"
    MEDIUM = "medio"
    HIGH = "alto"
    CRITICAL = "critico"


class ThreatClassification(StrEnum):
    """Classificacao final simplificada para exibicao e tomada de decisao."""

    TRUSTED = "confiavel"
    SUSPICIOUS = "suspeito"
    MALICIOUS = "malicioso"