"""Modelos de dados para o modulo de Auditoria Avancada de Seguranca do SentinelaPC."""

# Adicionado: modelos exclusivos da auditoria avancada de seguranca.

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class AuditCategory(StrEnum):
    """Categorias principais de achados da auditoria avancada."""

    MALWARE = "Malware"
    SYSTEM_CONFIG = "Configuracao do Sistema"
    PRIVACY = "Privacidade"
    BROWSER = "Navegador"
    EMAIL = "E-mail"
    NETWORK = "Rede / Wi-Fi"
    FIREWALL = "Firewall"
    REMOTE_ACCESS = "Acesso Remoto"
    DATA_PROTECTION = "Protecao de Dados"


class AuditSeverity(StrEnum):
    """Nivel de severidade de um achado individual da auditoria."""

    INFORMATIVE = "Informativo"
    LOW = "Baixo"
    MEDIUM = "Medio"
    HIGH = "Alto"
    CRITICAL = "Critico"


class AuditStatus(StrEnum):
    """Status conclusivo de cada verificacao de auditoria."""

    SAFE = "Seguro"
    ATTENTION = "Atencao"
    VULNERABLE = "Vulneravel"
    CRITICAL = "Critico"
    UNKNOWN = "Nao foi possivel verificar"


@dataclass
class AuditFinding:
    """Representa um achado individual da auditoria avancada de seguranca.

    Cada instancia corresponde a uma checagem tecnica com base em evidencias reais.
    Nao deve conter conclusoes genericas ou infereridas sem base tecnica.
    """

    # Categoria de seguranca a que o achado pertence
    category: AuditCategory
    # Nome descritivo do problema ou verificacao
    problem_name: str
    # Severidade tecnica do achado (impacto potencial)
    severity: AuditSeverity
    # Status resultante da verificacao (o que foi constatado)
    status: AuditStatus
    # Score de risco para este achado (0 = seguro / sem risco)
    score: int
    # Evidencias tecnicas que fundamentam o achado
    evidence: list[str] = field(default_factory=list)
    # Recomendacao de correcao ou mitigacao (vazia se status = Seguro)
    recommendation: str = ""
    # Detalhes adicionais (ex.: motivo de nao ter sido possivel verificar)
    details: str = ""
    # Identificador interno para resolucao automatica ou guiada do achado
    resolver_key: str | None = None
    # Indica se o item pode ser resolvido automaticamente pelo aplicativo
    auto_resolvable: bool = False


# ---------------------------------------------------------------------------
# Limiares de score para classificacao do status geral do sistema:
#   0  a 19 -> Seguro
#   20 a 39 -> Atencao
#   40 a 69 -> Vulneravel
#   70+     -> Critico
# Os pesos individuais dos achados seguem as recomendacoes do projeto.
# ---------------------------------------------------------------------------

AUDIT_SCORE_THRESHOLD_ATTENTION = 20
AUDIT_SCORE_THRESHOLD_VULNERABLE = 40
AUDIT_SCORE_THRESHOLD_CRITICAL = 70


@dataclass
class AuditReport:
    """Resultado consolidado da auditoria avancada de seguranca.

    Agrupa todos os achados, o score total calculado e o status geral
    derivado diretamente da pontuacao acumulada.
    """

    # Todos os achados produzidos pela auditoria (inclui os seguros)
    findings: list[AuditFinding] = field(default_factory=list)
    # Score total: soma dos scores dos achados com status nao-seguro
    total_score: int = 0
    # Status geral derivado do score total
    overall_status: AuditStatus = AuditStatus.SAFE
    # True se a auditoria foi interrompida antes de completar todas as checagens
    interrupted: bool = False


@dataclass(frozen=True)
class AuditResolutionResult:
    """Resultado de uma tentativa de resolver um achado da auditoria."""

    applied: bool
    message: str
    details: list[str] = field(default_factory=list)
    requires_restart: bool = False
