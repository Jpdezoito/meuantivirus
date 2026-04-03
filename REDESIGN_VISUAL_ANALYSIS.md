# 🎨 DIAGNÓSTICO VISUAL + PLANO DE REDESIGN
## SentinelaPC — Interface Desktop Premium

**Análise por:** Expert em Design de UI/UX para Software de Segurança (PySide6/Qt Widgets)  
**Data:** Abril 2026  
**Projeto:** SentinelaPC v1.0  
**Status:** Interface funcional, requer refinamento visual para tier premium  

---

## 📊 DIAGNÓSTICO VISUAL ATUAL

### ✅ Pontos Fortes
- **Paleta de cores profissional**: Dark mode bem executado (#111827 base, #3b9eff accent)
- **Estrutura modular**: Componentes bem organizados (cards, buttons, panels)
- **Tipografia clara**: Segoe UI, hierarchy bem definida
- **Espaçamento consistente**: Grid visual bem aplicado
- **Tema de segurança**: Azul + verde/vermelho é padrão em antivírus premium

### ⚠️ Problemas Críticos Identificados

#### 1. **ÍCONES (Problema Mais Crítico)**
- **Problema**: Uso de emoji Unicode (⚡🔍🚀🌐✉🛡) é muito amador
- **Impacto**: Diminui percepção de qualidade profissional
- **Tamanho**: Muito pequenos (18-24px), não dão presença visual
- **Inconsistência**: Emoji renderizam diferente em Windows/Linux, alguns aparecem pixelados

**Status Atual:**
```
• Sidebar: "  ◉  Dashboard" (emoji pequeno, tímido)
• Botões: "⚡\nVerificar arquivos" (emoji unicode acima do label)
• Resultado: Parece app hobby, não software de $$$
```

#### 2. **SIDEBAR**
- Muito "discreta" para uma navegação crítica
- Ícones unicode não dão identificação visual clara
- Largura fixa 190-220px é limítrofe - difícil ler labels
- Item ativo (checked) é sutil demais
- Falta visual feedback em hover/active

#### 3. **BOTÕES**
- Botões estão ok, mas faltam ícones de verdade
- ActionTile (grid buttons) usa emoji acima de label = visual fraco
- Botões poderiam ser maiores para dar presença (46px → 52px)
- Faltam estados visuais mais claros (disabled, loading, focus outline)

#### 4. **CARDS E BLOCOS**
- Cards têm border sutil (1px #2a3f55) - pouco destaque
- Falta sombra/profundidade visual (shadow)
- Padding interno é ok, mas distribuição poderia melhorar
- Cards mértricas são pequenas demais (metricValue = 24px, poderia ser 32px)

#### 5. **DASHBOARD / HERO CARD**
- Status hero é funcional mas não é "impactante"
- Falta elemento visual forte no topo
- Ícone de status (verde/vermelho) é pequeno
- Background do hero card poderia ter gradient ou padrão sutil

#### 6. **CONSOLE/LOG**
- Muito genérico, parece terminal dos anos 90
- Tipografia monospace é ok mas precisa mais estilo
- Falta visual distinction (cores para tipos de evento)
- Scrollbar muito sutil

#### 7. **TYPOGRAPHY / HIERARCHY**
- Títulos (26px) estão ok
- Descrições (12px) podem ser maiores em alguns contextos
- Falta letter-spacing em alguns títulos
- Alguns elementos precisam de weight maior (font-weight: 700 vs 800)

#### 8. **ESPAÇAMENTO / PROPORÇÃO**
- Geral está bom, mas alguns blocos têm espaço desperdiçado
- ActionTile (110x90) é muito pequeno para ícones grandes
- Cards de métrica poderiam ser maiores/mais impactantes
- Margins entre seções: 16px é ok, mas 18-20px daria mais respiro

---

## 🎯 SOLUÇÃO PROPOSTA: REDESIGN VISUAL

### Estratégia Geral
**Manter:** Base técnica (código, lógica, estrutura modular)  
**Melhorar:** Ícones (→ icon font ou SVG), botões (→ maiores), cards (→ sombras), hierarchy (→ mais clara)  
**Resultado:** Visual de software profissional premium (comparável a Avast, Norton, Kaspersky)

---

## 📐 RECOMENDAÇÕES CONCRETAS

### 1. ÍCONES - Solução Completa

#### ❌ ANTES (Problema)
```
_NAV_ICONS: dict[str, str] = {
    "dashboard":   "◉",      # Muito pequeno, amador
    "files":       "🔍",
    "processes":   "⚙",
    ...
}
```

#### ✅ DEPOIS (Solução)

**Opção A: Font Awesome (Recomendado)**
- Instale: `pip install pyside6-fontawesome5`
- Importar: `from PySide6.QtGui import QFont; from PySide6.QtWidgets import QLabel`
- Ícones profissionais, 1600+ opções, renderização vetorial perfeita

**Opção B: Icon Font Integration (Material Design Icons)**
- Use Material Design Icons (Google)
- Arquivo: `.ttf` incluído no projeto
- Método: Definir font customizada em QSS

**Opção C: SVG (Máximo Controle)**
- Use SVG embarcado
- Escalável, customizável, pequeno arquivo
- Use `QSvgRenderer` da PySide6

#### **Recomendação Final: Material Design Icons + Font Awesome**
- Razão: Já existe em projects profissionais, renderização perfeita
- Setup: Instalar e usar via PySide6

### Tamanhos Recomendados de Ícones

| Contexto | Tamanho Atual | Novo Tamanho | Razão |
|----------|---------------|--------------|-------|
| Sidebar | 18px | **32-36px** | Presença visual forte na navegação |
| NavButton ícone | 16px | **24px** | Melhor legibilidade |
| ActionTile ícone | 24px | **48px** | Destaque principal do tile |
| ActionButton ícone | N/A | **20px** | Novo elemento para botões |
| Card status ícone | 18px | **28px** | Maior presença |
| Métrica ícone | 18px | **24px** | Harmonizar com label |
| Dialogs/alerts | 20px | **32px** | Mais impactante |

### Exemplos de Novas Ícones (Material Design Icons)
```
dashboard     → 󰒓 (grid icon)
files         → 󰈙 (file search)
processes     → 󰐱 (activity/processes)
startup       → 󰐤 (boot/rocket)
browsers      → 󰖟 (globe/web)
emails        → 󰇰 (envelope)
audit         → 󰒃 (shield check)
quarantine    → 󰒉 (lock)
reports       → 󰈙 (document)
history       → 󰄐 (history/clock)
diagnostics   → 󰔧 (wrench/tools)
```

---

### 2. SIDEBAR - Redesign

#### Layout Melhorado
```
Atual (190-220px, discreto):              Novo (250px, premium):
┌──────────────┐                          ┌──────────────────────┐
│🛡 Sentinela  │                          │ 🛡 SentinelaPC       │
│Central seg.  │                          │ Central de Segurança │
├──────────────┤                          ├──────────────────────┤
│ VISÃO GERAL  │                          │ VISÃO GERAL          │
│ ◉ Dashboard  │  ← Emoji tímido          │ 󰒓 Dashboard         │  ← Ícone 32px
│ 🔍 Arquivos  │                          │ 󰈙 Arquivos          │
│ ⚙ Processos  │                          │ 󰐱 Processos         │
│              │                          │                      │
│ SEGURANÇA    │                          │ SEGURANÇA            │
│ ✉ E-mails   │                          │ 󰇰 E-mails          │
│ 🌐 Navegad. │                          │ 󰖟 Navegadores      │
│ 🛡 Auditoria │                          │ 󰒃 Auditoria        │
│              │                          │                      │
│ FERRAMENTAS  │                          │ FERRAMENTAS          │
│ 🔒 Quarent.  │                          │ 󰒉 Quarentena       │
│ 📄 Relatós   │                          │ 󰈙 Relatórios       │
│ 📋 Histórico │                          │ 󰄐 Histórico        │
│ 💊 Diag.     │                          │ 󰔧 Diagnóstico      │
└──────────────┘                          └──────────────────────┘
```

#### Mudanças Visuais na Sidebar
```css
QWidget#navSidebar {
    /* Antes */
    background-color: #0d1b2a;
    border-right: 1px solid #1a2c3e;
    /* NOVO: Adicionar sombra e border mais definida */
    border-right: 2px solid #1e3f5c;  /* Border mais visível */
}

QPushButton#navButton {
    /* Antes */
    padding: 10px 14px;
    border-radius: 10px;
    /* NOVO: Mais padding para dar respiro */
    padding: 14px 16px;          /* Mais espaço vertical/horizontal */
    border-radius: 12px;         /* Mais arredondado */
    margin: 0px 8px;             /* Margem lateral */
    min-height: 44px;            /* Altura mínima maior */
    font-size: 13px;             /* Tipografia ligeiramente maior */
    font-weight: 600;            /* Mais peso */
}

QPushButton#navButton:hover {
    /* NOVO: Hover mais pronunciado */
    background-color: #1a3f5e;   /* Mais saturado */
    border-left: 3px solid transparent;  /* Preparar para checked */
}

QPushButton#navButton:checked {
    /* Antes */
    background-color: #1a3550;
    border-left: 3px solid #3b9eff;
    /* NOVO: Muito mais presença */
    background-color: #1a4570;               /* Azul mais vibrante */
    border-left: 4px solid #3b9eff;         /* Border mais grossa */
    box-shadow: inset -2px 0 8px rgba(59, 158, 255, 0.2);  /* Sombra interna */
}

QLabel#navBrand {
    /* Antes */
    font-size: 18px;
    /* NOVO: Maior destaque */
    font-size: 20px;
    font-weight: 800;  /* Ultra bold */
    letter-spacing: -0.5px;
}
```

#### Aumentar Largura da Sidebar
```python
# No __init__ de SidebarNavigation:
# Antes:
self.setMinimumWidth(190)
self.setMaximumWidth(220)

# NOVO:
self.setMinimumWidth(250)  # Crédito para ícones maiores + labels
self.setMaximumWidth(280)
```

---

### 3. BOTÕES - Redesign

#### ActionTile Melhorado
```python
# ANTES: Botão com emoji acima de label
ActionButton(
    "quick_scan",
    "Verificar\narquivos",  # Texto quebrado, tímido
    tile=True  # Usa unicode emoji
)
# Resultado: 110x90px, emoji pequenininho

# DEPOIS: Ícone grande + label claro
class ActionTile(QPushButton):
    def __init__(self, icon: str, label: str, action_key: str):
        super().__init__()
        self.setObjectName("actionTile")
        
        # Layout com ícone grande no topo
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)
        
        # Ícone da font awesome (32px, azul accent)
        icon_label = QLabel(icon)
        icon_label.setFont(QFont("Material Design Icons", 48))  # 48px!
        icon_label.setAlignment(Qt.AlignCenter)
        
        # Label
        label_widget = QLabel(label)
        label_widget.setFont(QFont("Segoe UI", 12, QFont.Bold))
        label_widget.setAlignment(Qt.AlignCenter)
        label_widget.setWordWrap(True)
        
        layout.addStretch()
        layout.addWidget(icon_label)
        layout.addWidget(label_widget)
        layout.addStretch()
        
        # Size ajustado
        self.setMinimumSize(140, 120)  # Maior, com espaço pro ícone
        self.setMaximumSize(180, 140)
```

#### Estilo QSS para ActionTile Novo
```css
QPushButton#actionTile {
    /* Antes */
    background-color: #1e2d3d;
    border: 1px solid #2a3f55;
    border-radius: 14px;
    padding: 18px 14px;
    
    /* NOVO: Mais refinado e profissional */
    background-color: #1a2f40;
    border: 1px solid #2d4564;
    border-radius: 16px;
    padding: 18px 14px;
    
    /* Adicionar sombra */
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.4);
    
    /* Transição suave */
    transition: all 0.15s ease;
}

QPushButton#actionTile:hover {
    /* Antes */
    background-color: #243344;
    border-color: #3b6a91;
    
    /* NOVO: Mais impacto */
    background-color: #1d3f56;
    border-color: #3b9eff;
    box-shadow: 0 4px 12px rgba(59, 158, 255, 0.25);  /* Glow azul */
}

QPushButton#actionTile:pressed {
    /* Antes */
    background-color: #1a2c3e;
    border-color: #3b9eff;
    
    /* NOVO */
    background-color: #16293c;
    box-shadow: inset 0 2px 6px rgba(0, 0, 0, 0.6);  /* Pressed inset */
}
```

#### Botões Inline (primários/secundários)
```css
/* Aumentar tamanho */
QPushButton#primaryActionButton,
QPushButton#secondaryActionButton {
    /* NOVO: Altura aumentada, padding maior */
    min-height: 52px;     /* Era 46px */
    padding: 14px 22px;   /* Era 11px 20px */
    border-radius: 12px;  /* Era 10px */
    font-size: 13px;      /* Era 12px */
    font-weight: 700;     /* Era 700 */
    gap: 8px;             /* Espaço entre ícone e texto */
}

/* Adicionar ícone antes do texto (opcional com setIcon()) */
QPushButton#primaryActionButton::icon {
    opacity: 1.0;
}

/* Hover state mais visível */
QPushButton#primaryActionButton:hover {
    transform: translateY(-2px);  /* Pseudo-3D lift */
    box-shadow: 0 6px 16px rgba(59, 158, 255, 0.3);  /* Sombra maior */
}

/* State focus (importante para acessibilidade) */
QPushButton#primaryActionButton:focus {
    outline: 2px solid #3b9eff;
    outline-offset: 2px;
}
```

---

### 4. CARDS - Deeper Visual

#### Adicionar Sombras e Profundidade
```css
/* Base - Adicionar sombra */
QFrame#cardFrame {
    /* Antes */
    background-color: #1e2d3d;
    border: 1px solid #2a3f55;
    border-radius: 16px;
    
    /* NOVO: Sombra para profundidade */
    background-color: #1e2d3d;
    border: 1px solid #2a3f55;
    border-radius: 16px;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);  /* Sombra sutil */
}

QFrame#cardFrameElevated {
    /* Antes */
    background-color: #253447;
    border: 1px solid #334d66;
    border-radius: 16px;
    
    /* NOVO: Mais prominente */
    background-color: #253447;
    border: 1px solid #334d66;
    border-radius: 16px;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.5);  /* Sombra mais forte */
}

QFrame#heroCard {
    /* NOVO: Transformar em elemento verdadeiramente destaque */
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:1,
        stop:0 #1d3d56,
        stop:0.5 #192f46,
        stop:1 #1d3f56
    );
    border: 2px solid #2e4a66;
    border-radius: 20px;
    box-shadow: 0 8px 20px rgba(59, 158, 255, 0.2);  /* Glow azul sutil */
}
```

#### Cards de Métrica Redesign
```python
class MetricCard(CardFrame):
    """Card de metrica com melhor visual."""
    
    def __init__(self, label: str, value: str, caption: str, ...):
        super().__init__(parent)
        
        outer = QVBoxLayout(self)
        outer.setContentsMargins(20, 20, 20, 20)  # Aumentar padding
        outer.setSpacing(10)  # Aumentar spacing
        
        # Top row: Icon + Label
        top = QHBoxLayout()
        top.setSpacing(10)
        
        if icon:
            # Ícone maior: 28px em vez de 18px
            icon_label = QLabel(icon)
            icon_label.setFont(QFont("Material Design Icons", 28))
            icon_label.setStyleSheet("""
                background: transparent;
                color: #3b9eff;
            """)
            top.addWidget(icon_label)
        
        label_widget = QLabel(label)
        label_widget.setObjectName("metricLabel")
        label_widget.setStyleSheet("""
            font-size: 11px;
            font-weight: 600;
            color: #5d7a93;
            letter-spacing: 1px;
        """)
        top.addWidget(label_widget)
        top.addStretch()
        
        # Value: 32px em vez de 24px
        self.value_label = QLabel(value)
        self.value_label.setStyleSheet("""
            font-size: 32px;
            font-weight: 800;
            color: #3b9eff;
            letter-spacing: 0.5px;
        """)
        
        # Caption
        caption_widget = QLabel(caption)
        caption_widget.setObjectName("metricCaption")
        caption_widget.setStyleSheet("""
            font-size: 10px;
            color: #4d6a83;
            line-height: 1.4;
        """)
        caption_widget.setWordWrap(True)
        
        outer.addLayout(top)
        outer.addSpacing(6)
        outer.addWidget(self.value_label)
        outer.addWidget(caption_widget)
        outer.addStretch()
```

#### QSS para Cards de Métrica
```css
QFrame#cardFrame {
    /* Novo estilo mais sofisticado */
    background: qlineargradient(
        x1:0, y1:0, x2:1, y2:1,
        stop:0 #1e2d3d,
        stop:1 #192840
    );
    border: 1px solid #2a3f55;
    border-radius: 16px;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
}
```

---

### 5. DASHBOARD HERO CARD - Mais Impacto

#### Visual Antes vs. Depois

**ANTES:**
```
┌─ SentinelaPC Status ──────────────────┐
│                                       │
│  Status: ✅ SEGURO                   │
│  Última verificação: Hoje às 14:32    │
│  Ameaças detectadas: 0                │
│                                       │
└───────────────────────────────────────┘
```

**DEPOIS (Premium):**
```
┌─────────────────────────────────────────────────────────┐
│  🛡 SentinelaPC — Status de Segurança                  │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ✓ SISTEMA PROTEGIDO                                  │ ← Verde vibrante
│                                                         │
│  Última varredura: Hoje às 14:32                       │
│  Ameaças detectadas: 0                                 │
│  Arquivos monitorados: 2.4M                            │
│                                                         │
│  [Executar Varredura Rápida] [Relatório Completo]     │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

#### Código para HeroStatusCard Redesign
```python
class HeroStatusCard(CardFrame):
    """Card com status do sistema — elemento visual forte no topo."""
    
    def __init__(self, parent=None):
        super().__init__(parent, elevated=True)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(16)
        
        # Header: Ícone + título
        header = QHBoxLayout()
        header.setSpacing(12)
        
        shield_icon = QLabel("🛡")
        shield_icon.setFont(QFont("Arial", 40))
        shield_icon.setAlignment(Qt.AlignCenter)
        
        title_layout = QVBoxLayout()
        title_layout.setSpacing(2)
        
        main_title = QLabel("SentinelaPC")
        main_title.setFont(QFont("Segoe UI", 22, QFont.Bold))
        main_title.setStyleSheet("color: #f0f6ff;")
        
        subtitle = QLabel("Status de Segurança")
        subtitle.setFont(QFont("Segoe UI", 12))
        subtitle.setStyleSheet("color: #8ba3bb;")
        
        title_layout.addWidget(main_title)
        title_layout.addWidget(subtitle)
        
        header.addWidget(shield_icon)
        header.addLayout(title_layout)
        header.addStretch()
        
        layout.addLayout(header)
        layout.addSpacing(8)
        
        # Status badge
        status_layout = QHBoxLayout()
        status_layout.setSpacing(10)
        
        self.status_icon = QLabel("✓")
        self.status_icon.setFont(QFont("Arial", 28, QFont.Bold))
        self.status_icon.setStyleSheet("color: #22c55e;")  # Verde
        
        self.status_text = QLabel("SISTEMA PROTEGIDO")
        self.status_text.setFont(QFont("Segoe UI", 18, QFont.Bold))
        self.status_text.setStyleSheet("color: #22c55e;")
        
        status_layout.addWidget(self.status_icon)
        status_layout.addWidget(self.status_text)
        status_layout.addStretch()
        
        layout.addLayout(status_layout)
        layout.addSpacing(4)
        
        # Info grid
        info_grid = QGridLayout()
        info_grid.setHorizontalSpacing(32)
        info_grid.setVerticalSpacing(12)
        
        infos = [
            ("Última varredura", "––:––"),
            ("Ameaças detectadas", "0"),
            ("Arquivos monitorados", "0"),
        ]
        
        for i, (label, value) in enumerate(infos):
            label_widget = QLabel(label)
            label_widget.setStyleSheet("color: #8ba3bb; font-size: 11px; font-weight: 600;")
            
            value_widget = QLabel(value)
            value_widget.setStyleSheet("color: #f0f6ff; font-size: 14px; font-weight: 700;")
            
            info_grid.addWidget(label_widget, i, 0)
            info_grid.addWidget(value_widget, i, 1)
        
        layout.addLayout(info_grid)
        layout.addSpacing(8)
        
        # Action buttons
        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)
        
        scan_btn = QPushButton("Executar Varredura Rápida")
        scan_btn.setFont(QFont("Segoe UI", 12, QFont.Bold))
        scan_btn.setMinimumHeight(44)
        scan_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #2e8ee8, stop:1 #1a6dbf);
                color: #ffffff;
                border: none;
                border-radius: 10px;
                padding: 12px 24px;
                font-weight: 700;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #3b9eff, stop:1 #2176ca);
                box-shadow: 0 4px 12px rgba(59, 158, 255, 0.3);
            }
        """)
        
        report_btn = QPushButton("Ver Relatório Completo")
        report_btn.setFont(QFont("Segoe UI", 12))
        report_btn.setMinimumHeight(44)
        report_btn.setStyleSheet("""
            QPushButton {
                background-color: #1a2c3e;
                color: #c8dff0;
                border: 1px solid #2a3f55;
                border-radius: 10px;
                padding: 12px 24px;
            }
            QPushButton:hover {
                background-color: #1e3449;
                border-color: #3b9eff;
                color: #f0f6ff;
            }
        """)
        
        button_layout.addWidget(scan_btn)
        button_layout.addWidget(report_btn)
        button_layout.addStretch()
        
        layout.addLayout(button_layout)
    
    def set_status(self, is_safe: bool, message: str):
        if is_safe:
            self.status_icon.setText("✓")
            self.status_icon.setStyleSheet("color: #22c55e;")
            self.status_text.setText(message)
            self.status_text.setStyleSheet("color: #22c55e;")
        else:
            self.status_icon.setText("!")
            self.status_icon.setStyleSheet("color: #ef4444;")
            self.status_text.setText(message)
            self.status_text.setStyleSheet("color: #ef4444;")
```

---

### 6. CONSOLE/LOG - Estilo Terminal Moderno

```css
QTextEdit#resultsConsole,
QTextEdit#pageConsole {
    /* Antes */
    background-color: #0f1c28;
    color: #98b8d0;
    border: 1px solid #1e2d3d;
    border-radius: 12px;
    padding: 14px;
    
    /* NOVO: Mais estilo de terminal moderno */
    background: qlineargradient(
        x1:0, y1:0, x2:0, y2:1,
        stop:0 #0d1520,
        stop:1 #0f1c28
    );
    color: #65d0ff;
    border: 1px solid #1e3f5c;
    border-radius: 12px;
    padding: 16px;
    
    /* Font melhor: monospace maior */
    font-family: "Consolas", "Monaco", "Courier New", monospace;
    font-size: 12px;
    
    /* Selection melhor */
    selection-background-color: #1d4570;
    selection-color: #f0f6ff;
    
    /* Sombra interna */
    box-shadow: inset 0 1px 4px rgba(0, 0, 0, 0.5);
}
```

#### Adicionar Cores por Tipo de Log (Python)
```python
def append_colored_line(self, text: str, level: str = "info"):
    """Adiciona linha com cor baseada no tipo de evento."""
    
    color_map = {
        "INFO":    "#65d0ff",      # Ciano claro
        "WARNING": "#ffcc7a",      # Amarelo
        "ERROR":   "#ff6b7a",      # Vermelho
        "SUCCESS": "#22c55e",      # Verde
        "DEBUG":   "#8ba3bb",      # Cinza
    }
    
    color = color_map.get(level, "#65d0ff")
    prefix = f"[{level}]"
    
    # Log estruturado
    timestamp = datetime.now().strftime("%H:%M:%S")
    formatted = f"<span style='color: #4d6a83;'>{timestamp}</span> "
    formatted += f"<span style='color: {color};'>{prefix}</span> {text}"
    
    # Usar QTextEdit em modo HTML
    self.console.insertHtml(formatted + "<br/>")
    self.console.ensureCursorVisible()
```

---

### 7. TIPOGRAFIA - Melhorias de Hierarchy

```css
/* Melhorar tamanhos e weights */

QLabel#pageTitleLarge {
    /* Antes */
    font-size: 26px;
    font-weight: 700;
    
    /* NOVO */
    font-size: 32px;    /* Mais destaque */
    font-weight: 800;   /* Ultra bold */
    letter-spacing: -0.5px;
}

QLabel#sectionTitle {
    /* Antes */
    font-size: 14px;
    font-weight: 700;
    
    /* NOVO */
    font-size: 15px;
    font-weight: 700;
    letter-spacing: 0.2px;
}

QLabel#metricValue {
    /* Antes */
    font-size: 24px;
    font-weight: 700;
    
    /* NOVO: Mais impacto */
    font-size: 32px;    /* Maior visibilidade */
    font-weight: 800;   /* Mais pesado */
    letter-spacing: 0.5px;
}

QLabel#pageEyebrow {
    /* Antes */
    font-size: 10px;
    letter-spacing: 1.5px;
    
    /* NOVO: Mais presença */
    font-size: 11px;
    font-weight: 800;
    letter-spacing: 2px;  /* Mais spacing */
}
```

---

### 8. PADRÃO VISUAL GERAL - Summary

| Elemento | Mudança | Razão |
|----------|---------|-------|
| **Ícones Sidebar** | Unicode (18px) → Font Icons (32-36px) | Profissionalismo, renderização |
| **Ícones Botões** | Nenhum → Font Icons (20-48px) | Identidade visual forte |
| **Sidebar Largura** | 190-220px → 250-280px | Espaço para ícones maiores + labels |
| **ActionTile** | 110x90px → 140x120px | Dar presença aos ícones (48px) |
| **Botões Inline** | 46px → 52px altura | Proporção melhor |
| **Card Sombras** | Nenhuma → 0 2-8px rgba() | Profundidade visual |
| **Hero Card** | Simples → Gradient + glow | Elemento impactante |
| **Métrica Valores** | 24px → 32px | Maior destaque |
| **Tipografia** | Vários → Font-weight 800 em títulos | Hierarchy mais clara |

---

## 🚀 PLANO DE IMPLEMENTAÇÃO

### Fase 1: Setup do Icon Font (30 min)
1. Instalar `pip install pyside6-fontawesome5`
2. Criar `app/ui/icons.py` com mapeamento de ícones
3. Registrar font no QSS

### Fase 2: Atualizar Sidebar (45 min)
1. Aumentar largura para 250px
2. Aumentar tamanho de ícones para 32px
3. Melhorar padding/hover/active states
4. Adicionar sombra

### Fase 3: Redesign de Botões (60 min)
1. Aumentar ActionTile para 140x120
2. Adicionar ícones grandes (48px)
3. Atualizar hover/pressed states
4. Adicionar transições suaves

### Fase 4: Cards + Dashboard (90 min)
1. Adicionar sombras a todos os cards
2. Redesign HeroStatusCard
3. Aumentar tamanhos de métricas
4. Gradient no hero card

### Fase 5: Polish Final (30 min)
1. Ajustar tipografia
2. Adicionar cores de log por tipo
3. Testar responsividade
4. Validar em diferentes resoluções

**Tempo Total Estimado: 4-5 horas de trabalho**

---

## 📝 ARQUIVOS A MODIFICAR

```
app/ui/
├── styles.py                 ← Atualizar QSS completo
├── navigation.py             ← Aumentar sidebar, ícones
├── widgets.py                ← ActionButton redesign
├── panels.py                 ← HeroStatusCard redesign
├── icons.py                  ← NOVO: Mapeamento de icon font
└── main_window.py            ← Pequenos ajustes

installer/
└── requirements.txt          ← Adicionar pyside6-fontawesome5
```

---

## ✅ RESULTADO ESPERADO

**Antes:** Interface funcional, parece project hobby
**Depois:** Software profissional de nível Avast/Norton

- ✓ Sidebar elegante com ícones grandes (32-36px)
- ✓ Botões impactantes com visual premium
- ✓ Cards com profundidade (sombras)
- ✓ Dashboard hero card como elemento focal
- ✓ Tipografia com hierarchy clara
- ✓ Console com estilo de terminal moderno
- ✓ Consistência visual em toda a interface
- ✓ Parece software de $$$, não hobby

---

**Próximo Passo:** Implementar Fase 1 (Icon Font) ou deseja mais detalhes em alguma seção?
