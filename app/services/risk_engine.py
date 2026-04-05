"""Motor central de pontuacao de risco para combinar sinais de multiplas camadas."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from app.core.risk import RiskLevel, ThreatClassification


class ResponseAction(StrEnum):
    """Acao recomendada com base no score final."""

    ALLOW = "permitir"
    MONITOR = "monitorar_e_logar"
    REVIEW = "revisao_manual"
    QUARANTINE = "quarentena_recomendada"


@dataclass(frozen=True)
class RiskSignal:
    """Sinal de risco individual gerado por um modulo de analise."""

    reason: str
    weight: int
    category: str = "desconhecido"
    module: str = "desconhecido"


@dataclass(frozen=True)
class RiskAssessment:
    """Resultado consolidado da avaliacao de risco."""

    score: int
    risk_level: RiskLevel
    classification: ThreatClassification
    recommended_action: ResponseAction
    reasons: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)


class RiskEngine:
    """Combina sinais fracos e fortes em um score unico e acao recomendada."""

    CLEAN_MAX = 19
    LIGHT_MAX = 39
    MODERATE_MAX = 69

    def assess(self, *, base_score: int = 0, signals: list[RiskSignal] | None = None) -> RiskAssessment:
        """Consolida score final e classifica risco por faixa operacional."""
        active_signals = signals or []
        score = max(0, int(base_score) + sum(signal.weight for signal in active_signals))
        score = min(100, score)

        reasons = [signal.reason for signal in active_signals if signal.reason]
        categories = sorted({signal.category for signal in active_signals if signal.category})

        if score <= self.CLEAN_MAX:
            return RiskAssessment(
                score=score,
                risk_level=RiskLevel.LOW,
                classification=ThreatClassification.TRUSTED,
                recommended_action=ResponseAction.ALLOW,
                reasons=reasons,
                categories=categories,
            )

        if score <= self.LIGHT_MAX:
            return RiskAssessment(
                score=score,
                risk_level=RiskLevel.MEDIUM,
                classification=ThreatClassification.SUSPICIOUS,
                recommended_action=ResponseAction.MONITOR,
                reasons=reasons,
                categories=categories,
            )

        if score <= self.MODERATE_MAX:
            return RiskAssessment(
                score=score,
                risk_level=RiskLevel.HIGH,
                classification=ThreatClassification.SUSPICIOUS,
                recommended_action=ResponseAction.REVIEW,
                reasons=reasons,
                categories=categories,
            )

        return RiskAssessment(
            score=score,
            risk_level=RiskLevel.CRITICAL,
            classification=ThreatClassification.MALICIOUS,
            recommended_action=ResponseAction.QUARANTINE,
            reasons=reasons,
            categories=categories,
        )
