"""Integração com VirusTotal API para consulta de reputação de arquivos."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional
import requests

from app.utils.logger import log_info, log_warning, log_error


class VirusTotalCache:
    """Gerencia cache local de consultas ao VirusTotal."""

    def __init__(self, cache_file: Path | None = None) -> None:
        if cache_file is None:
            cache_file = Path(__file__).parent.parent / "data" / "virustotal_cache.json"
        
        self.cache_file = cache_file
        self._cache: dict = self._load_cache()

    def _load_cache(self) -> dict:
        """Carrega cache do arquivo."""
        if not self.cache_file.exists():
            return {}
        
        try:
            with self.cache_file.open("r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}

    def _save_cache(self) -> None:
        """Salva cache no arquivo."""
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            with self.cache_file.open("w", encoding="utf-8") as f:
                json.dump(self._cache, f, indent=2)
        except OSError:
            pass

    def get(self, sha256_hash: str) -> dict | None:
        """Obtém entrada de cache se não estiver expirada."""
        key = sha256_hash.lower()
        
        if key not in self._cache:
            return None
        
        entry = self._cache[key]
        cached_time = datetime.fromisoformat(entry.get("cached_at", ""))
        
        # Cache válido por 30 dias
        if datetime.now() - cached_time < timedelta(days=30):
            return entry.get("data")
        
        # Remover cache expirado
        del self._cache[key]
        self._save_cache()
        return None

    def set(self, sha256_hash: str, data: dict) -> None:
        """Armazena resultado da consulta no cache."""
        key = sha256_hash.lower()
        self._cache[key] = {
            "data": data,
            "cached_at": datetime.now().isoformat(),
        }
        self._save_cache()


class VirusTotalService:
    """Consulta API do VirusTotal para obter reputação de hashes."""

    # URL da API v3 do VirusTotal
    API_BASE = "https://www.virustotal.com/api/v3"
    REQUEST_TIMEOUT = 5  # segundos

    def __init__(self, api_key: str | None = None, logger: logging.Logger | None = None) -> None:
        self.api_key = api_key or self._load_api_key()
        self.logger = logger
        self.cache = VirusTotalCache()
        self._session: Optional[requests.Session] = None

    def _load_api_key(self) -> str | None:
        """Carrega chave da API de arquivo de configuração."""
        try:
            config_file = Path(__file__).parent.parent / "data" / "virustotal_config.json"
            if config_file.exists():
                with config_file.open("r", encoding="utf-8") as f:
                    data = json.load(f)
                    return data.get("api_key")
        except OSError:
            pass
        return None

    def _get_session(self) -> requests.Session:
        """Reutiliza sessão de requests com headers pré-configurados."""
        if self._session is None:
            self._session = requests.Session()
            if self.api_key:
                self._session.headers.update({
                    "x-apikey": self.api_key,
                    "User-Agent": "SentinelaPC/1.0",
                })
        return self._session

    def check_file_reputation(self, sha256_hash: str) -> dict:
        """
        Consulta reputação de um arquivo no VirusTotal.
        
        Retorna:
        {
            "found": bool,
            "detections": int (0-90),
            "last_analysis_date": str,
            "reputation": int (score VirusTotal),
            "meaningful_name": str | None,
            "error": str | None (se houve erro)
        }
        """
        if not self.api_key:
            return {
                "found": False,
                "error": "API key do VirusTotal não configurada",
            }

        # Tentar cache primeiro
        cached = self.cache.get(sha256_hash)
        if cached is not None:
            return cached

        try:
            session = self._get_session()
            response = session.get(
                f"{self.API_BASE}/files/{sha256_hash.lower()}",
                timeout=self.REQUEST_TIMEOUT,
            )

            if response.status_code == 404:
                # Arquivo não encontrado na base do VirusTotal
                result = {
                    "found": False,
                    "detections": 0,
                    "message": "Hash não encontrado na base do VirusTotal (novo ou legítimo)",
                }
                self.cache.set(sha256_hash, result)
                return result

            if response.status_code != 200:
                error_msg = response.text[:100] if response.text else response.status_code
                log_warning(
                    self.logger,
                    f"VirusTotal error {response.status_code}: {error_msg}"
                )
                return {
                    "found": False,
                    "error": f"VirusTotal API error {response.status_code}",
                }

            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            
            # Extrai informações de análise
            last_analysis_stats = attributes.get("last_analysis_stats", {})
            detections = last_analysis_stats.get("malicious", 0)
            
            result = {
                "found": True,
                "detections": detections,
                "total_vendors": sum(last_analysis_stats.values()),
                "last_analysis_date": attributes.get("last_analysis_date"),
                "reputation": attributes.get("reputation", 0),
                "meaningful_name": attributes.get("meaningful_name"),
            }
            
            # Cache resultado
            self.cache.set(sha256_hash, result)
            
            log_info(
                self.logger,
                f"VirusTotal: {sha256_hash[:16]}... → {detections} detections"
            )
            
            return result

        except requests.RequestException as e:
            log_warning(self.logger, f"VirusTotal request failed: {e}")
            return {
                "found": False,
                "error": f"Connection error: {str(e)[:50]}",
            }

    def calculate_vt_score_delta(self, vt_result: dict) -> int:
        """Calcula ajuste de score baseado em resultado do VirusTotal."""
        if not vt_result.get("found"):
            # Arquivo novo ou desconhecido - ajuste mínimo
            if vt_result.get("error"):
                return 0  # Sem acesso, manter score
            return -5  # Leve redução por estar registrado

        detections = vt_result.get("detections", 0)
        
        if detections == 0:
            # Arquivo conhecido como seguro
            return -30
        elif detections <= 2:
            # Poucas detecções, pode ser falso positivo
            return -15
        elif detections <= 5:
            # Algumas detecções, suspeito moderado
            return +10
        elif detections <= 10:
            # Muitas detecções, decidamente suspeito
            return +25
        else:
            # Muitas detecções, quase certamente malicioso
            return +40

    def close(self) -> None:
        """Fecha a sessão de requests."""
        if self._session:
            self._session.close()
            self._session = None

    def __enter__(self) -> VirusTotalService:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


def create_virustotal_config_template() -> None:
    """Cria arquivo de configuração template para VirusTotal API."""
    config_file = Path(__file__).parent.parent / "data" / "virustotal_config.json"
    
    if config_file.exists():
        return  # Já existe
    
    template = {
        "api_key": "INSIRA_SUA_CHAVE_API_DO_VIRUSTOTAL_AQUI",
        "notes": "Obtenha uma chave gratuita em https://www.virustotal.com/gui/home/upload",
    }
    
    try:
        config_file.parent.mkdir(parents=True, exist_ok=True)
        with config_file.open("w", encoding="utf-8") as f:
            json.dump(template, f, indent=2)
    except OSError:
        pass
