"""Modelos e excecoes para conexao online com provedores de e-mail."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class EmailProvider(StrEnum):
    """Provedores online suportados pelo SentinelaPC."""

    GMAIL = "gmail"
    OUTLOOK = "outlook"


@dataclass(frozen=True)
class EmailAccountStatus:
    """Estado atual de conexao OAuth de um provedor."""

    provider: EmailProvider
    connected: bool
    account_label: str = ""
    config_present: bool = False
    scopes: tuple[str, ...] = ()
    error_message: str = ""


class EmailAccountError(RuntimeError):
    """Erro base para conexao ou leitura de e-mail online."""


class EmailOAuthConfigurationError(EmailAccountError):
    """Falha causada por ausencia ou invalidade da configuracao OAuth."""


class EmailOAuthDependencyError(EmailAccountError):
    """Falha causada por dependencia opcional ausente."""