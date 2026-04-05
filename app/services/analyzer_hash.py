"""Analise de reputacao por hash com base local de confiaveis e maliciosos."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from app.services.reputation_service import ReputationService
from app.services.risk_engine import RiskSignal


class HashAnalyzer:
    """Classifica hash em confiavel, malicioso ou desconhecido usando base local."""

    def __init__(self, logger: logging.Logger, data_dir: Path | None = None) -> None:
        self.logger = logger
        self.data_dir = data_dir or (Path(__file__).resolve().parents[1] / "data")
        self.trusted_hashes = self._load_hashes(self.data_dir / "trusted_hashes.json", key="hashes")
        self.malicious_hashes = self._load_hashes(self.data_dir / "malicious_hashes.json", key="hashes")
        self.reputation_service = ReputationService()

    def analyze(self, sha256_hash: str) -> list[RiskSignal]:
        """Gera sinais de risco para o hash informado."""
        normalized = sha256_hash.lower().strip()
        if not normalized:
            return []

        if normalized in self.malicious_hashes:
            return [
                RiskSignal(
                    reason="Hash em base local de assinaturas maliciosas conhecidas",
                    weight=55,
                    category="trojan/backdoor",
                    module="analyzer_hash",
                )
            ]

        if normalized in self.trusted_hashes:
            return [
                RiskSignal(
                    reason="Hash presente em base local de arquivos confiaveis",
                    weight=-20,
                    category="contexto_legitimo",
                    module="analyzer_hash",
                )
            ]

        future_verdict = self.reputation_service.lookup_hash(normalized)
        if future_verdict.verdict == "malicioso":
            return [
                RiskSignal(
                    reason=f"Reputacao externa sinalizou hash malicioso ({future_verdict.source})",
                    weight=45,
                    category="reputacao_online",
                    module="analyzer_hash",
                )
            ]

        return [
            RiskSignal(
                reason="Hash sem reputacao local conhecida; classificado como desconhecido",
                weight=0,
                category="desconhecido",
                module="analyzer_hash",
            )
        ]

    def _load_hashes(self, file_path: Path, *, key: str) -> set[str]:
        if not file_path.exists():
            return set()

        try:
            with file_path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError) as error:
            self.logger.warning("Falha ao carregar base de hashes %s: %s", file_path, error)
            return set()

        if isinstance(data, dict):
            raw_hashes = data.get(key, [])
        elif isinstance(data, list):
            raw_hashes = data
        else:
            raw_hashes = []

        return {
            item.strip().lower()
            for item in raw_hashes
            if isinstance(item, str) and len(item.strip()) == 64
        }
