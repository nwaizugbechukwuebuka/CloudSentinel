"""
Configuration Management for CloudSentinel
Centralized configuration loading and validation for multi-cloud security scanning.
"""

import os
import json
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from pydantic import BaseSettings, Field, validator, EmailStr
from pydantic.networks import PostgresDsn, RedisDsn
import logging

logger = logging.getLogger(__name__)

class DatabaseSettings(BaseSettings):
    """Database configuration settings"""
    
    DATABASE_URL: Optional[PostgresDsn] = None
    DATABASE_HOST: str = "localhost"
    DATABASE_PORT: int = 5432
    DATABASE_NAME: str = "cloudsentinel"
    DATABASE_USER: str = "postgres"
    DATABASE_PASSWORD: str = ""
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 30
    DATABASE_ECHO: bool = False
    
    @validator('DATABASE_URL', pre=True)
    def assemble_db_connection(cls, v: Optional[str], values: Dict[str, Any]) -> Any:
        if isinstance(v, str):
            return v
        return PostgresDsn.build(
            scheme="postgresql",
            user=values.get("DATABASE_USER"),
            password=values.get("DATABASE_PASSWORD"),
            host=values.get("DATABASE_HOST"),
            port=str(values.get("DATABASE_PORT")),
            path=f"/{values.get('DATABASE_NAME') or ''}",
        )

class RedisSettings(BaseSettings):
    """Redis configuration for caching and Celery broker"""
    
    REDIS_URL: Optional[RedisDsn] = None
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    REDIS_PASSWORD: Optional[str] = None
    REDIS_SSL: bool = False
    
    @validator('REDIS_URL', pre=True)
    def assemble_redis_connection(cls, v: Optional[str], values: Dict[str, Any]) -> Any:
        if isinstance(v, str):
            return v
        
        scheme = "rediss" if values.get("REDIS_SSL") else "redis"
        password = values.get("REDIS_PASSWORD")
        auth = f":{password}@" if password else ""
        
        return f"{scheme}://{auth}{values.get('REDIS_HOST')}:{values.get('REDIS_PORT')}/{values.get('REDIS_DB')}"

class CelerySettings(BaseSettings):
    """Celery configuration for background tasks"""
    
    CELERY_BROKER_URL: Optional[str] = None
    CELERY_RESULT_BACKEND: Optional[str] = None
    CELERY_TASK_SERIALIZER: str = "json"
    CELERY_ACCEPT_CONTENT: List[str] = ["json"]
    CELERY_RESULT_SERIALIZER: str = "json"
    CELERY_TIMEZONE: str = "UTC"
    CELERY_ENABLE_UTC: bool = True
    CELERY_RESULT_EXPIRES: int = 3600
    CELERY_MAX_RETRIES: int = 3
    CELERY_RETRY_DELAY: int = 60
    
    @validator('CELERY_BROKER_URL', pre=True)
    def set_broker_url(cls, v: Optional[str], values: Dict[str, Any]) -> str:
        return v or f"redis://{os.getenv('REDIS_HOST', 'localhost')}:{os.getenv('REDIS_PORT', '6379')}/0"
    
    @validator('CELERY_RESULT_BACKEND', pre=True)
    def set_result_backend(cls, v: Optional[str], values: Dict[str, Any]) -> str:
        return v or f"redis://{os.getenv('REDIS_HOST', 'localhost')}:{os.getenv('REDIS_PORT', '6379')}/0"

class SecuritySettings(BaseSettings):
    """Security configuration settings"""
    
    SECRET_KEY: str = Field(..., min_length=32)
    JWT_SECRET_KEY: str = Field(..., min_length=32)
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    ENCRYPTION_KEY: str = Field(..., min_length=32)
    PASSWORD_MIN_LENGTH: int = 8
    SESSION_TIMEOUT_MINUTES: int = 60
    MAX_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_DURATION_MINUTES: int = 15
    WEBHOOK_SECRET: Optional[str] = None
    
    @validator('SECRET_KEY', 'JWT_SECRET_KEY', 'ENCRYPTION_KEY')
    def validate_keys(cls, v):
        if len(v) < 32:
            raise ValueError('Security keys must be at least 32 characters long')
        return v

class AWSSettings(BaseSettings):
    """AWS configuration for cloud scanning"""
    
    AWS_DEFAULT_REGION: str = "us-east-1"
    AWS_ACCESS_KEY_ID: Optional[str] = None
    AWS_SECRET_ACCESS_KEY: Optional[str] = None
    AWS_SESSION_TOKEN: Optional[str] = None
    AWS_PROFILE: Optional[str] = None
    AWS_ROLE_ARN: Optional[str] = None
    AWS_EXTERNAL_ID: Optional[str] = None
    AWS_MAX_RETRIES: int = 3
    AWS_RETRY_DELAY: float = 1.0
    AWS_TIMEOUT: int = 30
    
class AzureSettings(BaseSettings):
    """Azure configuration for cloud scanning"""
    
    AZURE_SUBSCRIPTION_ID: Optional[str] = None
    AZURE_TENANT_ID: Optional[str] = None
    AZURE_CLIENT_ID: Optional[str] = None
    AZURE_CLIENT_SECRET: Optional[str] = None
    AZURE_RESOURCE_GROUP: Optional[str] = None
    AZURE_TIMEOUT: int = 30
    AZURE_MAX_RETRIES: int = 3

class GCPSettings(BaseSettings):
    """GCP configuration for cloud scanning"""
    
    GCP_PROJECT_ID: Optional[str] = None
    GCP_SERVICE_ACCOUNT_PATH: Optional[str] = None
    GOOGLE_APPLICATION_CREDENTIALS: Optional[str] = None
    GCP_REGION: str = "us-central1"
    GCP_ZONE: str = "us-central1-a"
    GCP_TIMEOUT: int = 30
    GCP_MAX_RETRIES: int = 3

class EmailSettings(BaseSettings):
    """Email configuration for notifications"""
    
    SMTP_HOST: str = "localhost"
    SMTP_PORT: int = 587
    SMTP_USERNAME: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_USE_TLS: bool = True
    SMTP_USE_SSL: bool = False
    EMAIL_FROM: EmailStr = "noreply@cloudsentinel.com"
    EMAIL_TIMEOUT: int = 30

class SlackSettings(BaseSettings):
    """Slack configuration for notifications"""
    
    SLACK_BOT_TOKEN: Optional[str] = None
    SLACK_SIGNING_SECRET: Optional[str] = None
    SLACK_DEFAULT_CHANNEL: str = "#security-alerts"
    SLACK_WEBHOOK_URL: Optional[str] = None
    SLACK_TIMEOUT: int = 30

class PagerDutySettings(BaseSettings):
    """PagerDuty configuration for critical alerts"""
    
    PAGERDUTY_INTEGRATION_KEY: Optional[str] = None
    PAGERDUTY_API_TOKEN: Optional[str] = None
    PAGERDUTY_SERVICE_ID: Optional[str] = None
    PAGERDUTY_ESCALATION_POLICY_ID: Optional[str] = None

class LoggingSettings(BaseSettings):
    """Logging configuration"""
    
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"  # json, text
    LOG_FILE_PATH: Optional[str] = "/var/log/cloudsentinel/app.log"
    LOG_MAX_FILE_SIZE: str = "10MB"
    LOG_BACKUP_COUNT: int = 5
    LOG_ROTATION: str = "daily"  # daily, weekly, size
    ENABLE_STRUCTURED_LOGGING: bool = True
    ENABLE_REQUEST_LOGGING: bool = True

class ApplicationSettings(BaseSettings):
    """Main application configuration"""
    
    APP_NAME: str = "CloudSentinel"
    APP_VERSION: str = "1.0.0"
    APP_ENV: str = "development"  # development, staging, production
    DEBUG: bool = False
    API_HOST: str = "localhost"
    API_PORT: int = 8000
    API_PREFIX: str = "/api/v1"
    FRONTEND_URL: str = "http://localhost:3000"
    API_BASE_URL: str = "http://localhost:8000"
    
    # CORS Configuration
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:8080"]
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_ALLOW_METHODS: List[str] = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
    CORS_ALLOW_HEADERS: List[str] = ["*"]
    
    # Rate limiting
    RATE_LIMIT_PER_MINUTE: int = 100
    RATE_LIMIT_BURST: int = 200
    
    # File handling
    UPLOAD_MAX_SIZE: str = "10MB"
    REPORTS_STORAGE_PATH: str = "/var/cloudsentinel/reports"
    TEMP_STORAGE_PATH: str = "/tmp/cloudsentinel"
    
    # Performance
    MAX_CONCURRENT_SCANS: int = 5
    SCAN_TIMEOUT_MINUTES: int = 60
    
    # Monitoring
    PROMETHEUS_ENABLED: bool = True
    PROMETHEUS_PORT: int = 9090
    HEALTH_CHECK_INTERVAL: int = 30
    
    @validator('APP_ENV')
    def validate_environment(cls, v):
        allowed_envs = ['development', 'staging', 'production']
        if v not in allowed_envs:
            raise ValueError(f'APP_ENV must be one of {allowed_envs}')
        return v
    
    @validator('DEBUG', pre=True)
    def parse_debug(cls, v):
        if isinstance(v, str):
            return v.lower() in ('true', '1', 'yes', 'on')
        return bool(v)

class ComplianceSettings(BaseSettings):
    """Compliance framework configuration"""
    
    ENABLE_CIS_BENCHMARKS: bool = True
    ENABLE_NIST_FRAMEWORK: bool = True
    ENABLE_ISO27001: bool = True
    ENABLE_SOC2: bool = True
    ENABLE_GDPR_COMPLIANCE: bool = False
    ENABLE_HIPAA_COMPLIANCE: bool = False
    CUSTOM_COMPLIANCE_RULES_PATH: Optional[str] = None

class IntegrationSettings(BaseSettings):
    """Third-party integrations configuration"""
    
    VIRUSTOTAL_API_KEY: Optional[str] = None
    SHODAN_API_KEY: Optional[str] = None
    GITHUB_TOKEN: Optional[str] = None
    JIRA_URL: Optional[str] = None
    JIRA_USERNAME: Optional[str] = None
    JIRA_API_TOKEN: Optional[str] = None

class ReportSettings(BaseSettings):
    """Report generation configuration"""
    
    DEFAULT_REPORT_FORMAT: str = "pdf"  # pdf, json, excel, csv
    REPORT_LOGO_PATH: Optional[str] = None
    REPORT_COMPANY_NAME: str = "CloudSentinel Security"
    REPORT_RETENTION_DAYS: int = 90
    ENABLE_AUTOMATED_REPORTS: bool = True
    REPORT_SCHEDULE: str = "0 6 * * 1"  # Weekly on Monday at 6 AM

class BackupSettings(BaseSettings):
    """Backup and recovery configuration"""
    
    BACKUP_ENABLED: bool = True
    BACKUP_SCHEDULE: str = "0 2 * * *"  # Daily at 2 AM
    BACKUP_RETENTION_DAYS: int = 30
    BACKUP_STORAGE_PATH: str = "/var/backups/cloudsentinel"
    BACKUP_ENCRYPTION_ENABLED: bool = True

class CacheSettings(BaseSettings):
    """Cache configuration"""
    
    CACHE_TTL_SECONDS: int = 3600
    CACHE_MAX_SIZE: int = 1000
    ENABLE_QUERY_CACHE: bool = True
    ENABLE_RESULT_CACHE: bool = True

class FeatureFlags(BaseSettings):
    """Feature flags for enabling/disabling functionality"""
    
    FEATURE_MULTI_TENANT: bool = False
    FEATURE_API_VERSIONING: bool = True
    FEATURE_REAL_TIME_SCANNING: bool = True
    FEATURE_CUSTOM_POLICIES: bool = True
    FEATURE_ADVANCED_ANALYTICS: bool = True
    FEATURE_WEBHOOK_NOTIFICATIONS: bool = True

class Settings(BaseSettings):
    """Main settings class combining all configuration sections"""
    
    # Application settings
    app: ApplicationSettings = ApplicationSettings()
    
    # Database and caching
    database: DatabaseSettings = DatabaseSettings()
    redis: RedisSettings = RedisSettings()
    celery: CelerySettings = CelerySettings()
    cache: CacheSettings = CacheSettings()
    
    # Security
    security: SecuritySettings = SecuritySettings()
    
    # Cloud providers
    aws: AWSSettings = AWSSettings()
    azure: AzureSettings = AzureSettings()
    gcp: GCPSettings = GCPSettings()
    
    # Notifications
    email: EmailSettings = EmailSettings()
    slack: SlackSettings = SlackSettings()
    pagerduty: PagerDutySettings = PagerDutySettings()
    
    # Features and compliance
    compliance: ComplianceSettings = ComplianceSettings()
    integrations: IntegrationSettings = IntegrationSettings()
    reports: ReportSettings = ReportSettings()
    backup: BackupSettings = BackupSettings()
    features: FeatureFlags = FeatureFlags()
    
    # System settings
    logging: LoggingSettings = LoggingSettings()
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True
        env_nested_delimiter = "__"
        
        @classmethod
        def customise_sources(
            cls,
            init_settings,
            env_settings,
            file_secret_settings,
        ):
            return (
                init_settings,
                env_settings,
                file_secret_settings,
            )
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._validate_configuration()
        self._setup_directories()
    
    def _validate_configuration(self):
        """Validate configuration consistency"""
        
        # Validate cloud provider configurations
        if not any([
            self.aws.AWS_ACCESS_KEY_ID,
            self.azure.AZURE_CLIENT_ID,
            self.gcp.GCP_PROJECT_ID
        ]):
            logger.warning("No cloud provider credentials configured. Some features may not work.")
        
        # Validate notification settings
        if not any([
            self.email.SMTP_USERNAME,
            self.slack.SLACK_BOT_TOKEN,
            self.pagerduty.PAGERDUTY_INTEGRATION_KEY
        ]):
            logger.warning("No notification channels configured. Alerts will not be sent.")
        
        # Production environment checks
        if self.app.APP_ENV == "production":
            if self.app.DEBUG:
                raise ValueError("DEBUG must be False in production environment")
            
            if len(self.security.SECRET_KEY) < 32:
                raise ValueError("SECRET_KEY must be at least 32 characters in production")
    
    def _setup_directories(self):
        """Create necessary directories"""
        directories = [
            self.app.REPORTS_STORAGE_PATH,
            self.app.TEMP_STORAGE_PATH,
            self.backup.BACKUP_STORAGE_PATH,
        ]
        
        # Add log directory if specified
        if self.logging.LOG_FILE_PATH:
            log_dir = Path(self.logging.LOG_FILE_PATH).parent
            directories.append(str(log_dir))
        
        for directory in directories:
            if directory:
                Path(directory).mkdir(parents=True, exist_ok=True)
    
    def get_cloud_credentials(self, provider: str) -> Dict[str, Any]:
        """Get credentials for a specific cloud provider"""
        
        if provider.lower() == "aws":
            return {
                "access_key_id": self.aws.AWS_ACCESS_KEY_ID,
                "secret_access_key": self.aws.AWS_SECRET_ACCESS_KEY,
                "session_token": self.aws.AWS_SESSION_TOKEN,
                "region": self.aws.AWS_DEFAULT_REGION,
                "profile": self.aws.AWS_PROFILE,
                "role_arn": self.aws.AWS_ROLE_ARN,
                "external_id": self.aws.AWS_EXTERNAL_ID,
            }
        elif provider.lower() == "azure":
            return {
                "subscription_id": self.azure.AZURE_SUBSCRIPTION_ID,
                "tenant_id": self.azure.AZURE_TENANT_ID,
                "client_id": self.azure.AZURE_CLIENT_ID,
                "client_secret": self.azure.AZURE_CLIENT_SECRET,
                "resource_group": self.azure.AZURE_RESOURCE_GROUP,
            }
        elif provider.lower() == "gcp":
            return {
                "project_id": self.gcp.GCP_PROJECT_ID,
                "service_account_path": self.gcp.GCP_SERVICE_ACCOUNT_PATH,
                "credentials_path": self.gcp.GOOGLE_APPLICATION_CREDENTIALS,
                "region": self.gcp.GCP_REGION,
                "zone": self.gcp.GCP_ZONE,
            }
        else:
            raise ValueError(f"Unknown cloud provider: {provider}")
    
    def get_notification_config(self, channel: str) -> Dict[str, Any]:
        """Get notification configuration for a specific channel"""
        
        if channel.lower() == "email":
            return {
                "host": self.email.SMTP_HOST,
                "port": self.email.SMTP_PORT,
                "username": self.email.SMTP_USERNAME,
                "password": self.email.SMTP_PASSWORD,
                "use_tls": self.email.SMTP_USE_TLS,
                "use_ssl": self.email.SMTP_USE_SSL,
                "from_email": self.email.EMAIL_FROM,
                "timeout": self.email.EMAIL_TIMEOUT,
            }
        elif channel.lower() == "slack":
            return {
                "bot_token": self.slack.SLACK_BOT_TOKEN,
                "signing_secret": self.slack.SLACK_SIGNING_SECRET,
                "default_channel": self.slack.SLACK_DEFAULT_CHANNEL,
                "webhook_url": self.slack.SLACK_WEBHOOK_URL,
                "timeout": self.slack.SLACK_TIMEOUT,
            }
        elif channel.lower() == "pagerduty":
            return {
                "integration_key": self.pagerduty.PAGERDUTY_INTEGRATION_KEY,
                "api_token": self.pagerduty.PAGERDUTY_API_TOKEN,
                "service_id": self.pagerduty.PAGERDUTY_SERVICE_ID,
                "escalation_policy_id": self.pagerduty.PAGERDUTY_ESCALATION_POLICY_ID,
            }
        else:
            raise ValueError(f"Unknown notification channel: {channel}")
    
    def is_production(self) -> bool:
        """Check if running in production environment"""
        return self.app.APP_ENV == "production"
    
    def is_development(self) -> bool:
        """Check if running in development environment"""
        return self.app.APP_ENV == "development"
    
    def get_enabled_compliance_frameworks(self) -> List[str]:
        """Get list of enabled compliance frameworks"""
        frameworks = []
        if self.compliance.ENABLE_CIS_BENCHMARKS:
            frameworks.append("CIS")
        if self.compliance.ENABLE_NIST_FRAMEWORK:
            frameworks.append("NIST")
        if self.compliance.ENABLE_ISO27001:
            frameworks.append("ISO27001")
        if self.compliance.ENABLE_SOC2:
            frameworks.append("SOC2")
        if self.compliance.ENABLE_GDPR_COMPLIANCE:
            frameworks.append("GDPR")
        if self.compliance.ENABLE_HIPAA_COMPLIANCE:
            frameworks.append("HIPAA")
        return frameworks

# Global settings instance
settings = Settings()

# Helper functions for backward compatibility
def get_settings() -> Settings:
    """Get the global settings instance"""
    return settings

def get_database_url() -> str:
    """Get the database URL"""
    return str(settings.database.DATABASE_URL)

def get_redis_url() -> str:
    """Get the Redis URL"""
    return str(settings.redis.REDIS_URL)

def get_celery_broker_url() -> str:
    """Get the Celery broker URL"""
    return settings.celery.CELERY_BROKER_URL

def is_debug_enabled() -> bool:
    """Check if debug mode is enabled"""
    return settings.app.DEBUG

def get_secret_key() -> str:
    """Get the application secret key"""
    return settings.security.SECRET_KEY
