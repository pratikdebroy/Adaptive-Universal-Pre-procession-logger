"""
Central configuration for the Universal Log Pre-processing Framework.
All tunable parameters are defined here and can be overridden via environment variables.
"""

from pathlib import Path
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings. Override via environment variables prefixed with ULFP_."""

    # --- Paths ---
    base_dir: Path = Path(__file__).parent.parent
    data_dir: Path = base_dir / "data"
    evidence_dir: Path = base_dir / "data" / "evidence"
    db_path: Path = base_dir / "data" / "ulfp.db"
    templates_dir: Path = base_dir / "data" / "templates"
    samples_dir: Path = base_dir / "data" / "samples"

    # --- Ingestion / Defensive & DoS Limits ---
    max_event_size_bytes: int = 65536  # 64KB
    max_field_count: int = 100
    max_field_length: int = 4096
    max_nesting_depth: int = 5
    rate_limit_events_per_second: int = 1000
    rate_limit_burst: int = 100
    timestamp_max_future_seconds: int = 86400  # 1 day future bound
    timestamp_max_past_years: int = 10  # 10 years past bound

    # --- Parsing ---
    fast_path_confidence_threshold: float = 0.85
    structural_confidence_threshold: float = 0.70
    semantic_confidence_threshold: float = 0.75
    tier3_confidence_threshold: float = 0.60
    drain_depth: int = 4
    drain_sim_threshold: float = 0.5
    drain_max_children: int = 100

    # --- Trust Gate ---
    min_confidence_threshold: float = 0.70
    valid_protocols: list[str] = [
        "TCP", "UDP", "ICMP", "GRE", "ESP", "AH",
        "SCTP", "tcp", "udp", "icmp", "gre", "esp", "ah", "sctp",
    ]
    valid_actions: list[str] = [
        "ALLOW", "DENY", "DROP", "BLOCK", "REJECT", "PERMIT",
        "ACCEPT", "RESET", "allow", "deny", "drop", "block",
        "reject", "permit", "accept", "reset",
        "Allowed", "Denied", "Dropped", "Blocked",
        "LOGIN", "LOGOUT", "SUCCESS", "FAILURE", "login", "logout", "success", "failed",
    ]

    # --- Ollama / Inference ---
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:3b"
    ollama_timeout_seconds: int = 60
    
    # --- Groq / Cloud Inference ---
    groq_api_key: str = ""
    groq_model: str = "llama3-8b-8192"
    
    inference_mode: str = "auto"  # "auto", "groq", "ollama", "demo_fallback"

    # --- RAG ---
    rag_top_k: int = 3
    rag_min_similarity: float = 0.3

    # --- Registry ---
    parser_test_sample_count: int = 3  # samples to test before promotion

    # --- OCSF ---
    ocsf_version: str = "1.1.0"
    ocsf_profile: str = "firewall"

    # --- Server ---
    host: str = "0.0.0.0"
    port: int = 8000
    cors_origins: list[str] = ["http://localhost:3000", "http://localhost:5173"]

    model_config = {
        "env_prefix": "ULFP_",
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore"
    }


settings = Settings()
