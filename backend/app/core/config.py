"""Application configuration.

All settings are read from environment variables (12-factor). A `.env` file is
automatically loaded when present, which keeps local development simple while
remaining fully container-deployable.
"""

from functools import lru_cache
from typing import Any, Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

AppEnv = Literal["development", "test", "production"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- App ---
    app_name: str = "SIEM Platform"
    app_env: AppEnv = "development"
    debug: bool = True
    api_v1_prefix: str = "/api/v1"
    cors_origins: list[str] = Field(
        default_factory=lambda: [
            "http://localhost:5173",
            "http://localhost:3000",
            "http://localhost:8080",
        ]
    )
    rate_limit_per_minute: int = 120

    # --- Ingest (agents/integrations) ---
    # If set, the ingest endpoint requires this value in the X-API-Key header.
    # If unset, ingest falls back to JWT authentication (analyst or admin).
    ingest_api_key: str | None = None

    # --- Security ---
    secret_key: str = "change-me-to-a-long-random-string"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60 * 24
    token_url: str = "/api/v1/auth/login"

    # --- Database (metadata / cases / alerts / users) ---
    database_url: str = "sqlite:///./data/siem.db"

    # --- Event bus ---
    # redis://localhost:6379/0  |  inmemory://
    event_bus_url: str = "redis://localhost:6379/0"

    # --- Log store ---
    # elasticsearch://localhost:9200  |  local://./data/events
    log_store_url: str = "elasticsearch://localhost:9200"
    log_store_index_prefix: str = "siem-events"
    log_store_day_rollover: bool = True
    elasticsearch_username: str | None = None
    elasticsearch_password: str | None = None
    elasticsearch_verify_tls: bool = False

    # --- AI agent ---
    ai_provider: Literal["heuristic", "openai", "groq", "ollama"] = "heuristic"
    openai_api_key: str | None = None
    openai_model: str = "gpt-4o-mini"
    openai_base_url: str | None = None
    groq_api_key: str | None = None
    groq_model: str = "llama-3.3-70b-versatile"
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.1"
    ai_max_events_context: int = 25
    ai_timeout_seconds: float = 30.0

    # --- SOAR ---
    soar_allow_destructive: bool = False
    soar_playbooks_dir: str = "./data/playbooks"
    soar_webhook_default_url: str | None = None
    soar_endpoint_isolation_api: str | None = None
    soar_firewall_block_api: str | None = None

    # --- Alerting ---
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_from: str = "siem@localhost"
    alert_webhook_default_url: str | None = None

    # --- ML / detection ---
    ml_model_dir: str = "./data/ml"
    ml_anomaly_threshold: float = 0.62
    yara_rules_dir: str = "./data/yara"
    yara_enabled: bool = True

    # --- Bootstrap admin ---
    first_admin_username: str = "admin"
    first_admin_password: str = "Admin@12345"
    first_admin_email: str = "admin@example.com"

    # --- Retention (days) ---
    retention_hot_days: int = 7
    retention_warm_days: int = 30
    retention_cold_days: int = 90
    retention_delete_days: int = 180

    # --- File Integrity Monitoring (FIM / syscheck) ---
    # Demo mode seeds deterministic syscheck data for frontend development.
    # When disabled, no demo data is generated and events come only from
    # registered endpoint agents through POST /api/v1/fim/ingest.
    fim_demo_mode: bool = True
    # Shared secret an endpoint agent must present to enroll. If unset,
    # enrollment falls back to an authenticated admin/analyst JWT.
    fim_registration_token: str | None = None
    # Optional JSON list overriding the default FIM severity rules.
    # See app/services/fim_rules.py for the schema.
    fim_rules_json: str | None = None

    # --- Threat Intelligence (IOC) ---
    # Demo mode seeds deterministic IOC observations for frontend development.
    # When disabled, observations come only from registered endpoint agents
    # through POST /api/v1/ioc/ingest. Lookups run against the bundled offline
    # IOC list first and optionally against the configured online provider.
    ioc_demo_mode: bool = True
    # Shared secret an endpoint agent must present to register itself. If unset,
    # registration falls back to an authenticated admin/analyst JWT.
    ioc_registration_token: str | None = None
    # Local YAML/JSON file path with the bundled offline IOC list.
    ioc_list_path: str = "./data/ioc/iocs.yaml"
    # Online threat intel provider. Offline-only by default; never fabricate
    # reputation - when no source can answer, lookups report "unknown".
    threat_intel_enabled: bool = False
    threat_intel_provider: Literal["abuseipdb", "virustotal", "otx", "greynoise"] = "abuseipdb"
    threat_intel_api_key: str | None = None
    threat_intel_timeout_seconds: float = 10.0

    # --- Vulnerability detection ---
    # Demo mode seeds deterministic inventory + findings for frontend
    # development. When disabled, scans collect real installed-software data
    # from registered endpoint agents.
    vulnerability_demo_mode: bool = True
    # Shared secret an endpoint agent must present to register itself. If unset,
    # registration falls back to an authenticated admin/analyst JWT.
    vulnerability_registration_token: str | None = None
    # Path to the bundled CVE database. Without a CVE database every finding is
    # reported with status "unknown" (never a fabricated verdict).
    cve_db_path: str = "./data/cve/cve_db.json"
    # Time-to-live (seconds) for cached scan results before agents are
    # requested to rescan. Efficiency knob: agents avoid repeated full scans.
    vulnerability_scan_interval_seconds: int = 3600
    # Max concurrent vulnerability scan jobs.
    vulnerability_worker_threads: int = 2

    # --- Threat hunting ---
    # Directory of built-in hunt definitions (YAML).
    hunts_dir: str = "./data/hunts"

    # --- Network + Process/Service monitoring ---
    # Demo mode seeds deterministic network/process/service telemetry for
    # frontend development. When disabled, data comes only from enrolled
    # endpoint agents through POST /api/v1/telemetry/ingest. Every row carries
    # source_label="demo" so it can never be mistaken for a real finding.
    network_demo_mode: bool = True
    process_demo_mode: bool = True
    # Shared secret an endpoint agent must present to register itself. If unset,
    # registration falls back to an authenticated admin/analyst JWT.
    telemetry_registration_token: str | None = None
    # Suggested poll cadence (seconds) surfaced to endpoint agents and the UI.
    # The agent reads its own ENDPOINT_AGENT_* knobs; these document the
    # expected server-side cadence.
    network_monitor_interval: int = 5
    process_monitor_interval: int = 5
    service_monitor_interval: int = 15

    # --- Security Configuration Assessment (SCA) ---
    # Demo mode seeds deterministic benchmark results for frontend development.
    # When disabled, scans collect real endpoint evidence through agents.
    sca_demo_mode: bool = True
    # "local" runs the engine's collectors on the manager host; "remote"
    # dispatches scan jobs to registered endpoint agents which submit evidence.
    sca_agent_mode: str = "local"
    # Shared secret an endpoint agent must present to register itself. If unset,
    # registration falls back to an authenticated admin/analyst JWT.
    sca_registration_token: str | None = None
    # Max seconds the scan worker waits for an agent to answer a job.
    sca_agent_timeout_seconds: float = 60.0
    # Max number of concurrent scan jobs.
    sca_worker_threads: int = 2

    # --- Protected endpoint (single-device model) ---
    # This product protects ONE device: the PC it runs on. ``max_protected_endpoints``
    # caps how many distinct machines may register. Default 1 enforces the
    # single-device model at the backend: a second, different machine is rejected
    # with error code ``single_endpoint_limit``. Raise it only when deliberately
    # operating a multi-device deployment.
    max_protected_endpoints: int = 1
    # Shared secret the local endpoint agent must present to enroll the
    # protected endpoint. If unset, registration falls back to an admin JWT.
    protected_endpoint_registration_token: str | None = None

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _parse_cors(cls, value: Any) -> Any:
        if isinstance(value, str):
            if value.startswith("["):
                import json

                return json.loads(value)
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
