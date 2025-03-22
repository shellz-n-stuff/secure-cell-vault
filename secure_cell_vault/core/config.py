from pydantic import BaseSettings, validator
from typing import Optional, Dict, Any, List
import yaml
import os
from pathlib import Path

class Settings(BaseSettings):
    # Project Info
    PROJECT_NAME: str = "Secure Cell Vault"
    VERSION: str = "0.1.0"
    API_V1_STR: str = "/api/v1"
    
    # Security
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    PASSWORD_MIN_LENGTH: int = 12
    BCRYPT_ROUNDS: int = 12
    
    # Database
    POSTGRES_SERVER: str
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str
    POSTGRES_DB: str
    SQLALCHEMY_DATABASE_URI: Optional[str] = None
    
    @validator("SQLALCHEMY_DATABASE_URI", pre=True)
    def assemble_db_connection(cls, v: Optional[str], values: Dict[str, Any]) -> str:
        if v:
            return v
        return f"postgresql://{values['POSTGRES_USER']}:{values['POSTGRES_PASSWORD']}@{values['POSTGRES_SERVER']}/{values['POSTGRES_DB']}"
    
    # Redis
    REDIS_HOST: str
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: Optional[str] = None
    REDIS_DB: int = 0
    
    # Cell Configuration
    DEFAULT_CELL_ROTATION_DAYS: int = 30
    MIN_KEY_LENGTH: int = 32
    MAX_SECRETS_PER_CELL: int = 1000
    
    # HSM Configuration
    USE_HSM: bool = False
    HSM_PROVIDER: Optional[str] = None
    HSM_CONFIG: Dict[str, Any] = {}
    
    # Audit
    AUDIT_LOG_PATH: str = "audit.log"
    STRUCTURED_LOGGING: bool = True
    LOG_LEVEL: str = "INFO"
    
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 100
    RATE_LIMIT_BURST: int = 200
    
    # CORS
    CORS_ORIGINS: List[str] = ["*"]
    CORS_ALLOW_CREDENTIALS: bool = True
    
    # Authentication
    MFA_REQUIRED: bool = True
    SESSION_DURATION_MINUTES: int = 60
    FAILED_LOGIN_DELAY: int = 3  # seconds
    MAX_FAILED_ATTEMPTS: int = 5
    LOCKOUT_DURATION_MINUTES: int = 15
    
    # API Security
    MAX_REQUEST_SIZE_MB: int = 10
    REQUEST_TIMEOUT_SECONDS: int = 30
    
    # Backup and Recovery
    BACKUP_ENABLED: bool = True
    BACKUP_INTERVAL_HOURS: int = 24
    BACKUP_RETENTION_DAYS: int = 30
    BACKUP_ENCRYPTION_KEY: Optional[str] = None
    
    # Monitoring
    ENABLE_METRICS: bool = True
    METRICS_PORT: int = 9090
    HEALTH_CHECK_INTERVAL: int = 60  # seconds
    
    class Config:
        case_sensitive = True

def load_config() -> Settings:
    """Load configuration from file and environment variables"""
    config_path = os.getenv("CONFIG_PATH", "config.yaml")
    
    # Default configuration
    config_dict = {
        "SECRET_KEY": os.urandom(32).hex(),
        "POSTGRES_SERVER": "localhost",
        "POSTGRES_USER": "secure_cell_vault",
        "POSTGRES_PASSWORD": "",
        "POSTGRES_DB": "secure_cell_vault",
        "REDIS_HOST": "localhost"
    }
    
    # Load from config file if it exists
    if os.path.exists(config_path):
        with open(config_path) as f:
            yaml_config = yaml.safe_load(f)
            if yaml_config:
                config_dict.update(yaml_config)
    
    # Create settings object
    settings = Settings(**config_dict)
    
    # Ensure required directories exist
    log_dir = Path(settings.AUDIT_LOG_PATH).parent
    log_dir.mkdir(parents=True, exist_ok=True)
    
    return settings

settings = load_config()