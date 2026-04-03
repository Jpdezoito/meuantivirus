"""Dialogos padronizados para confirmacao e permissao administrativa."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.ui.action_policy import ActionPolicy, ActionSeverity
from app.ui.widgets import CardFrame, SectionHeader


_SEVERITY_TITLES = {
    ActionSeverity.NORMAL: "Acao padrao",
    ActionSeverity.SENSITIVE: "Acao sensivel",
    ActionSeverity.HIGH: "Acao de alto impacto",
    ActionSeverity.CRITICAL: "Acao critica",
}


class ConfirmActionDialog(QDialog):
    """Exibe resumo, impacto e validacao de uma acao sensivel."""

    def __init__(
        self,
        policy: ActionPolicy,
        *,
        target_summary: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._policy = policy
        self.setWindowTitle(policy.title)
        self.setModal(True)
        self.resize(640, 420)
        self.setObjectName("confirmActionDialog")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(14)

        header_card = CardFrame(elevated=True)
        header_layout = QVBoxLayout(header_card)
        header_layout.setContentsMargins(18, 16, 18, 16)
        header_layout.setSpacing(6)

        title_label = QLabel(policy.title)
        title_label.setObjectName("dialogTitle")
        title_label.setWordWrap(True)

        severity_label = QLabel(_SEVERITY_TITLES[policy.severity])
        severity_label.setObjectName("dialogSeverityLabel")

        description_label = QLabel(policy.description)
        description_label.setObjectName("dialogBody")
        description_label.setWordWrap(True)

        header_layout.addWidget(severity_label)
        header_layout.addWidget(title_label)
        header_layout.addWidget(description_label)
        layout.addWidget(header_card)

        impact_card = CardFrame()
        impact_layout = QVBoxLayout(impact_card)
        impact_layout.setContentsMargins(18, 16, 18, 16)
        impact_layout.setSpacing(8)
        impact_layout.addWidget(SectionHeader("Resumo da acao", "Confira o alvo e os impactos antes de continuar."))

        self._summary_label = QLabel(target_summary)
        self._summary_label.setObjectName("dialogBody")
        self._summary_label.setWordWrap(True)
        impact_layout.addWidget(self._summary_label)

        if policy.detail_lines:
            details = QTextEdit()
            details.setObjectName("pageConsole")
            details.setReadOnly(True)
            details.setFixedHeight(110)
            details.setPlainText("\n".join(f"- {line}" for line in policy.detail_lines))
            impact_layout.addWidget(details)

        if policy.irreversible:
            irreversible_label = QLabel(
                "Esta acao altera o estado do sistema de forma sensivel. Revise com atencao antes de confirmar."
            )
            irreversible_label.setObjectName("dialogWarning")
            irreversible_label.setWordWrap(True)
            impact_layout.addWidget(irreversible_label)

        self._confirm_input: QLineEdit | None = None
        if policy.confirm_phrase:
            phrase_label = QLabel(
                f"Digite {policy.confirm_phrase} para habilitar a confirmacao final."
            )
            phrase_label.setObjectName("dialogWarning")
            phrase_label.setWordWrap(True)
            impact_layout.addWidget(phrase_label)

            self._confirm_input = QLineEdit()
            self._confirm_input.setPlaceholderText(policy.confirm_phrase)
            self._confirm_input.textChanged.connect(self._update_confirm_state)
            impact_layout.addWidget(self._confirm_input)

        layout.addWidget(impact_card)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        self._confirm_button = QPushButton(policy.confirm_label)
        self._confirm_button.setObjectName("dangerActionButton" if policy.severity in {ActionSeverity.HIGH, ActionSeverity.CRITICAL} else "primaryActionButton")
        self._confirm_button.clicked.connect(self.accept)
        buttons.addButton(self._confirm_button, QDialogButtonBox.ButtonRole.AcceptRole)
        cancel_button = buttons.button(QDialogButtonBox.StandardButton.Cancel)
        if cancel_button is not None:
            cancel_button.setText("Cancelar")
            cancel_button.setObjectName("secondaryActionButton")
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self._update_confirm_state()

    def _update_confirm_state(self) -> None:
        """Habilita a confirmacao final quando a validacao obrigatoria for atendida."""
        if self._confirm_input is None or self._policy.confirm_phrase is None:
            self._confirm_button.setEnabled(True)
            return

        self._confirm_button.setEnabled(self._confirm_input.text().strip() == self._policy.confirm_phrase)


class AdminPermissionDialog(QDialog):
    """Solicita elevacao administrativa antes de uma operacao sensivel."""

    def __init__(
        self,
        policy: ActionPolicy,
        *,
        target_summary: str,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Permissao de administrador necessaria")
        self.setModal(True)
        self.resize(620, 320)
        self.setObjectName("adminPermissionDialog")
        self._choice = "cancel"

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(14)

        card = CardFrame(elevated=True)
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(18, 16, 18, 16)
        card_layout.setSpacing(8)

        title_label = QLabel("Esta acao exige privilegios elevados do Windows")
        title_label.setObjectName("dialogTitle")
        title_label.setWordWrap(True)
        card_layout.addWidget(title_label)

        body_label = QLabel(policy.admin_reason or policy.description)
        body_label.setObjectName("dialogBody")
        body_label.setWordWrap(True)
        card_layout.addWidget(body_label)

        summary_label = QLabel(target_summary)
        summary_label.setObjectName("dialogBody")
        summary_label.setWordWrap(True)
        card_layout.addWidget(summary_label)

        note_label = QLabel(
            "Ao continuar, o SentinelaPC tentara reiniciar com UAC para concluir a operacao de forma segura."
        )
        note_label.setObjectName("dialogWarning")
        note_label.setWordWrap(True)
        card_layout.addWidget(note_label)
        layout.addWidget(card)

        button_row = QHBoxLayout()
        button_row.setSpacing(10)
        button_row.addStretch()

        cancel_button = QPushButton("Cancelar")
        cancel_button.setObjectName("secondaryActionButton")
        cancel_button.clicked.connect(self.reject)

        relaunch_button = QPushButton("Reiniciar como administrador")
        relaunch_button.setObjectName("primaryActionButton")
        relaunch_button.clicked.connect(self._accept_relaunch)

        button_row.addWidget(cancel_button)
        button_row.addWidget(relaunch_button)
        layout.addLayout(button_row)

    @property
    def choice(self) -> str:
        """Retorna a decisao tomada pelo usuario."""
        return self._choice

    def _accept_relaunch(self) -> None:
        self._choice = "relaunch"
        self.accept()