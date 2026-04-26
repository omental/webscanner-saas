from functools import lru_cache

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Web Scanner Service"
    app_env: str = "development"
    app_version: str = "0.1.0"
    api_v1_prefix: str = "/api/v1"
    database_url: str = (
        "postgresql+asyncpg://postgres:postgres@localhost:5432/webscanner"
    )
    cors_origins: list[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    # --- OpenRouter / LLM ---
    openrouter_api_key: SecretStr | None = None
    openrouter_model: str = "nvidia/nemotron-3-super-120b-a12b:free"
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    app_public_url: str = "http://localhost:3000"
    scanner_max_depth: int = 2
    scanner_max_pages: int = 25
    scanner_timeout_seconds: int = 10
    scanner_user_agent: str = "WebScannerBot/0.1"
    enable_stored_xss_checks: bool = False
    enable_stored_xss_browser_verify: bool = False
    stored_xss_max_forms: int = 3
    stored_xss_revisit_max_pages: int = 10
    enable_advanced_sqli_checks: bool = False
    advanced_sqli_max_params: int = 10
    advanced_sqli_max_probes_per_param: int = 4
    advanced_sqli_timeout_seconds: int = 8
    enable_ssrf_checks: bool = False
    ssrf_callback_url: str | None = None
    ssrf_max_params: int = 10
    ssrf_timeout_seconds: int = 8
    enable_rce_checks: bool = False
    rce_max_params: int = 10
    rce_timeout_seconds: int = 8
    enable_waf_detection: bool = True
    waf_detection_safe_probes: bool = True
    waf_detection_timeout_seconds: int = 8
    enable_subdomain_discovery: bool = False
    subdomain_discovery_max_results: int = 100
    nvd_import_path: str | None = None
    mitre_import_path: str | None = None
    kev_import_path: str | None = None
    ghsa_import_path: str | None = None
    osv_import_path: str | None = None
    exploitdb_import_path: str | None = None
    wordfence_import_path: str | None = None

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, value: str | list[str]) -> list[str]:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator("ssrf_callback_url", mode="before")
    @classmethod
    def parse_optional_url(cls, value: str | None) -> str | None:
        if isinstance(value, str) and not value.strip():
            return None
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
