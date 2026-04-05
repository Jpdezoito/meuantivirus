"""Servico de reputacao por hash com suporte local e preparo para consulta online futura."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ReputationVerdict:
    """Resultado de reputacao para um hash."""

    verdict: str
    source: str
    confidence: str
    reason: str


class ReputationService:
    """Abstracao para enriquecer reputacao sem acoplar o scanner a um provedor externo."""

    def lookup_hash(self, sha256_hash: str) -> ReputationVerdict:
        """Retorna estado desconhecido; pontos de extensao para feeds online futuros."""
        _ = sha256_hash
        return ReputationVerdict(
            verdict="desconhecido",
            source="local_stub",
            confidence="baixa",
            reason="Sem correspondencia local; pronto para consulta online futura.",
        )
