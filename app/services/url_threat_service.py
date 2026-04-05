"""Motor de reputacao heuristica para URLs suspeitas (safe browsing local)."""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import json
from pathlib import Path
import re
from urllib.parse import urlparse


@dataclass(frozen=True)
class UrlThreatAssessment:
    """Resultado de avaliacao de risco para uma URL."""

    url: str
    score: int
    reasons: list[str] = field(default_factory=list)

    @property
    def suspicious(self) -> bool:
        return self.score >= 20


class UrlThreatService:
    """Detecta sinais locais de phishing, malware e engenharia social em links."""

    SHORTENERS = ("bit.ly", "tinyurl", "t.co", "is.gd", "cutt.ly", "rebrand.ly")
    SUSPICIOUS_TLDS = {
        "zip",
        "mov",
        "top",
        "xyz",
        "click",
        "gq",
        "tk",
        "work",
        "support",
    }
    SENSITIVE_KEYWORDS = (
        "login",
        "signin",
        "verify",
        "password",
        "senha",
        "conta",
        "bank",
        "banco",
        "wallet",
        "pix",
    )
    BRAND_KEYWORDS = (
        "google",
        "microsoft",
        "paypal",
        "itau",
        "nubank",
        "bradesco",
        "caixa",
        "mercadopago",
        "amazon",
        "apple",
    )

    BRAND_LEGIT_DOMAINS = {
        "google": ("google.com", "gmail.com", "youtube.com", "googleusercontent.com"),
        "microsoft": ("microsoft.com", "office.com", "live.com", "outlook.com", "azure.com"),
        "paypal": ("paypal.com",),
        "amazon": ("amazon.com", "amazon.com.br", "aws.amazon.com"),
        "apple": ("apple.com", "icloud.com"),
        "itau": ("itau.com.br",),
        "nubank": ("nubank.com.br",),
        "bradesco": ("bradesco.com.br",),
        "caixa": ("caixa.gov.br",),
        "mercadopago": ("mercadopago.com", "mercadopago.com.br"),
    }

    CONFIG_FILENAME = "url_guard_config.json"
    DEFAULT_BLOCKLIST_HOSTS = {
        "goog1e-login.com",
        "micr0soft-auth.com",
        "secure-paypal-checkout.com",
    }
    DEFAULT_ALLOWLIST_HOSTS = {
        "google.com",
        "microsoft.com",
        "paypal.com",
        "apple.com",
    }

    def __init__(self, data_dir: Path | None = None) -> None:
        self._data_dir = data_dir
        self._config_path = (data_dir / self.CONFIG_FILENAME) if data_dir else None
        self._blocklist_hosts = set(self.DEFAULT_BLOCKLIST_HOSTS)
        self._allowlist_hosts = set(self.DEFAULT_ALLOWLIST_HOSTS)
        self._extra_brands: dict[str, tuple[str, ...]] = {}
        self._load_config()

    def assess_url(self, url: str) -> UrlThreatAssessment:
        """Avalia uma URL com regras locais para reduzir risco de phishing."""
        normalized = (url or "").strip()
        if not normalized:
            return UrlThreatAssessment(url=url, score=0, reasons=[])

        score = 0
        reasons: list[str] = []

        parsed = urlparse(normalized)
        host = (parsed.hostname or "").lower()
        scheme = (parsed.scheme or "").lower()
        path_query = f"{parsed.path} {parsed.query}".lower()
        port = int(parsed.port or 0)

        if not host:
            return UrlThreatAssessment(url=normalized, score=0, reasons=[])

        if host in self._allowlist_hosts:
            return UrlThreatAssessment(url=normalized, score=0, reasons=[])

        if host in self._blocklist_hosts:
            score += 75
            reasons.append("Host em blocklist local de phishing/malware")

        if any(short in host for short in self.SHORTENERS):
            score += 20
            reasons.append("Link encurtado detectado")

        if "@" in normalized:
            score += 20
            reasons.append("URL usa caractere @ para possivel ofuscacao")

        if host.startswith("xn--") or ".xn--" in host:
            score += 30
            reasons.append("Dominio punycode detectado (possivel homografo)")

        is_ip_host = self._is_ip_host(host)
        if is_ip_host:
            score += 30
            reasons.append("URL usa endereco IP direto no lugar de dominio")
            if scheme == "http":
                score += 10
                reasons.append("HTTP com host em IP direto aumenta risco de MITM")

        if not is_ip_host:
            tld = host.rsplit(".", 1)[-1] if "." in host else ""
            if tld in self.SUSPICIOUS_TLDS:
                score += 15
                reasons.append(f"TLD com historico de abuso detectado: .{tld}")

            if host.count(".") >= 3:
                score += 10
                reasons.append("Dominio com subdominios excessivos")

            typo_brand = self._detect_typosquatting_brand(host)
            if typo_brand:
                score += 35
                reasons.append(f"Possivel typosquatting de marca: {typo_brand}")

            if host.count("-") >= 3:
                score += 8
                reasons.append("Dominio com hifenizacao excessiva")

        if self._looks_like_brand_impersonation(host):
            score += 30
            reasons.append("Dominio aparenta imitar marca conhecida")

        if port and port not in {80, 443, 8080, 8443}:
            score += 10
            reasons.append(f"Porta incomum em URL: {port}")

        if scheme == "http" and any(keyword in path_query for keyword in self.SENSITIVE_KEYWORDS):
            score += 15
            reasons.append("HTTP sem criptografia em pagina com termos sensiveis")

        credential_keywords = ("login", "signin", "verify", "password", "senha", "2fa", "token", "auth")
        if any(keyword in path_query for keyword in credential_keywords):
            score += 12
            reasons.append("Padrao de coleta de credenciais detectado na URL")

        dedup_reasons = list(dict.fromkeys(reasons))
        return UrlThreatAssessment(url=normalized, score=min(score, 100), reasons=dedup_reasons)

    def is_suspicious_url(self, url: str) -> bool:
        return self.assess_url(url).suspicious

    def _looks_like_brand_impersonation(self, host: str) -> bool:
        lowered = host.lower()
        for brand in self.BRAND_KEYWORDS:
            if brand in lowered and any(char.isdigit() for char in lowered):
                return True
            if brand.replace("o", "0") in lowered:
                return True
            if f"{brand}-secure" in lowered or f"secure-{brand}" in lowered:
                return True
        return False

    def _detect_typosquatting_brand(self, host: str) -> str | None:
        host_no_www = host[4:] if host.startswith("www.") else host
        host_labels = [part for part in re.split(r"[.\-]", host_no_www) if part]
        brands = set(self.BRAND_KEYWORDS)
        brands.update(self._extra_brands.keys())

        for label in host_labels:
            for brand in brands:
                if label == brand:
                    continue
                if brand in label:
                    continue
                distance = self._bounded_levenshtein(label, brand, max_distance=2)
                if distance <= 2 and not self._is_legit_brand_host(host_no_www, brand):
                    return brand
        return None

    def _is_legit_brand_host(self, host: str, brand: str) -> bool:
        legit_domains = self.BRAND_LEGIT_DOMAINS.get(brand, ())
        legit_domains = tuple(set(legit_domains).union(self._extra_brands.get(brand, ())))
        return any(host == legit or host.endswith(f".{legit}") for legit in legit_domains)

    def _bounded_levenshtein(self, left: str, right: str, *, max_distance: int) -> int:
        if abs(len(left) - len(right)) > max_distance:
            return max_distance + 1
        if left == right:
            return 0

        previous = list(range(len(right) + 1))
        for i, ch_left in enumerate(left, start=1):
            current = [i]
            row_min = current[0]
            for j, ch_right in enumerate(right, start=1):
                cost = 0 if ch_left == ch_right else 1
                current.append(
                    min(
                        previous[j] + 1,
                        current[j - 1] + 1,
                        previous[j - 1] + cost,
                    )
                )
                row_min = min(row_min, current[j])
            if row_min > max_distance:
                return max_distance + 1
            previous = current
        return previous[-1]

    def _load_config(self) -> None:
        if self._config_path is None:
            return

        default_data = {
            "blocklist_hosts": sorted(self.DEFAULT_BLOCKLIST_HOSTS),
            "allowlist_hosts": sorted(self.DEFAULT_ALLOWLIST_HOSTS),
            "extra_brand_legit_domains": {},
        }

        raw = default_data
        try:
            self._config_path.parent.mkdir(parents=True, exist_ok=True)
            if self._config_path.exists():
                raw = json.loads(self._config_path.read_text(encoding="utf-8"))
            else:
                self._config_path.write_text(json.dumps(default_data, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception:
            raw = default_data

        blocklist = raw.get("blocklist_hosts", [])
        if isinstance(blocklist, list):
            self._blocklist_hosts = {str(item).strip().lower() for item in blocklist if str(item).strip()}

        allowlist = raw.get("allowlist_hosts", [])
        if isinstance(allowlist, list):
            self._allowlist_hosts = {str(item).strip().lower() for item in allowlist if str(item).strip()}

        extras = raw.get("extra_brand_legit_domains", {})
        parsed_extras: dict[str, tuple[str, ...]] = {}
        if isinstance(extras, dict):
            for brand, domains in extras.items():
                brand_key = str(brand).strip().lower()
                if not brand_key:
                    continue
                if not isinstance(domains, list):
                    continue
                normalized_domains = tuple(
                    str(item).strip().lower()
                    for item in domains
                    if str(item).strip()
                )
                if normalized_domains:
                    parsed_extras[brand_key] = normalized_domains
        self._extra_brands = parsed_extras

    def _is_ip_host(self, host: str) -> bool:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return False
        return True
