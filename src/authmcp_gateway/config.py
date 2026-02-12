"""Configuration management for AuthMCP Gateway authentication."""

import os
import secrets
import sys
from dataclasses import dataclass, field
from typing import List, Optional, Set

from dotenv import load_dotenv

# Load environment variables
load_dotenv()


def _env_bool(name: str, default: bool = False) -> bool:
    """Parse boolean from environment variable."""
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_list(name: str) -> List[str]:
    """Parse comma-separated list from environment variable."""
    value = os.getenv(name, "").strip()
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _env_set(name: str) -> Set[str]:
    """Parse comma-separated list into set from environment variable."""
    return set(_env_list(name))


def _env_int(name: str, default: int) -> int:
    """Parse integer from environment variable."""
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value.strip())
    except ValueError:
        return default


@dataclass
class JWTConfig:
    """JWT token configuration."""

    algorithm: str  # HS256 or RS256
    secret_key: Optional[str] = None
    private_key: Optional[str] = None
    public_key: Optional[str] = None
    access_token_expire_minutes: int = 30  # For MCP client access tokens
    refresh_token_expire_days: int = 7
    admin_token_expire_minutes: int = 480  # 8 hours for admin panel

    def __post_init__(self):
        """Validate JWT configuration."""
        if self.algorithm == "HS256":
            if not self.secret_key:
                # Auto-generate secret key
                self.secret_key = secrets.token_urlsafe(32)
                
                # Auto-create .env file if it doesn't exist
                env_path = '.env'
                if not os.path.exists(env_path):
                    try:
                        with open(env_path, 'w', encoding='utf-8') as f:
                            f.write(f'# AuthMCP Gateway Configuration\n')
                            f.write(f'# Auto-generated on first run\n\n')
                            f.write(f'JWT_SECRET_KEY={self.secret_key}\n\n')
                            f.write(f'# Uncomment to customize:\n')
                            f.write(f'# HOST=0.0.0.0\n')
                            f.write(f'# PORT=8000\n')
                            f.write(f'# AUTH_SQLITE_PATH=data/auth.db\n')
                            f.write(f'# PASSWORD_REQUIRE_SPECIAL=false\n')
                        print("\n" + "="*60, file=sys.stderr)
                        print("✓ Created .env file with generated JWT_SECRET_KEY", file=sys.stderr)
                        print("="*60 + "\n", file=sys.stderr)
                    except Exception as e:
                        print(f"\n⚠️  Warning: Could not create .env file: {e}", file=sys.stderr)
                        print(f"Please manually create .env with:", file=sys.stderr)
                        print(f"  JWT_SECRET_KEY={self.secret_key}\n", file=sys.stderr)
                else:
                    # .env exists but no JWT_SECRET_KEY - show warning
                    print("\n" + "="*60, file=sys.stderr)
                    print("⚠️  WARNING: Auto-generated JWT_SECRET_KEY", file=sys.stderr)
                    print("="*60, file=sys.stderr)
                    print("A random JWT secret key was generated automatically.", file=sys.stderr)
                    print("\nFor PRODUCTION use, please add to .env:", file=sys.stderr)
                    print(f"  JWT_SECRET_KEY={self.secret_key}", file=sys.stderr)
                    print("\nWithout a persistent key, all tokens will be invalidated", file=sys.stderr)
                    print("on server restart!", file=sys.stderr)
                    print("="*60 + "\n", file=sys.stderr)
        elif self.algorithm == "RS256":
            if not self.private_key or not self.public_key:
                raise ValueError("JWT_PRIVATE_KEY and JWT_PUBLIC_KEY are required when using RS256 algorithm")
        else:
            raise ValueError(f"Unsupported JWT algorithm: {self.algorithm}. Use HS256 or RS256.")


@dataclass
class AuthConfig:
    """Authentication and password policy configuration."""

    allow_registration: bool = False
    sqlite_path: str = "data/auth.db"
    password_min_length: int = 8
    password_require_uppercase: bool = True
    password_require_lowercase: bool = True
    password_require_digit: bool = True
    password_require_special: bool = True


@dataclass
class RateLimitConfig:
    """Rate limiting configuration."""

    enabled: bool = True
    login_limit: int = 5  # Max login attempts
    login_window: int = 60  # Seconds
    register_limit: int = 3  # Max registrations
    register_window: int = 300  # 5 minutes
    cleanup_interval: int = 3600  # Cleanup old entries every hour


@dataclass
class AppConfig:
    """Complete application configuration."""

    # JWT settings
    jwt: JWTConfig

    # Auth settings
    auth: AuthConfig

    # Rate limiting settings
    rate_limit: RateLimitConfig

    # MCP public URL
    mcp_public_url: str

    # Authentication enforcement
    auth_required: bool = True

    # Static bearer tokens (for backward compatibility or service accounts)
    static_bearer_tokens: List[str] = field(default_factory=list)

    # Trusted IPs (bypass auth for local services)
    trusted_ips: Set[str] = field(default_factory=set)

    # RAG backend configuration
    rag_api_base_url: str = "http://localhost:8004/api/v1"
    rag_api_bearer: Optional[str] = None
    rag_api_key: Optional[str] = None
    rag_api_username: Optional[str] = None
    rag_api_password: Optional[str] = None

    # Default knowledge base
    default_kb_id: Optional[str] = None

    # Network settings
    request_timeout_seconds: int = 60
    allow_insecure_http: bool = False
    allowed_origins: Set[str] = field(default_factory=set)
    disable_dns_rebinding: bool = True
    transport_allowed_hosts: List[str] = field(default_factory=list)
    transport_allowed_origins: List[str] = field(default_factory=list)

    # Retrieval config
    retrieval_config_path: Optional[str] = None
    retrieval_config_ttl_seconds: float = 2.0

    # Logging
    log_level: str = "INFO"

    @property
    def retrieval_config_ttl(self) -> float:
        """Alias for retrieval_config_ttl_seconds for backward compatibility."""
        return self.retrieval_config_ttl_seconds


def _load_jwt_keys(algorithm: str, private_key_path: Optional[str], public_key_path: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """Load RSA keys from file paths if using RS256."""
    if algorithm != "RS256":
        return None, None

    private_key = None
    public_key = None

    if private_key_path:
        try:
            with open(private_key_path, "r", encoding="utf-8") as f:
                private_key = f.read()
        except FileNotFoundError:
            raise ValueError(f"Private key file not found: {private_key_path}")
        except Exception as e:
            raise ValueError(f"Failed to read private key from {private_key_path}: {e}")

    if public_key_path:
        try:
            with open(public_key_path, "r", encoding="utf-8") as f:
                public_key = f.read()
        except FileNotFoundError:
            raise ValueError(f"Public key file not found: {public_key_path}")
        except Exception as e:
            raise ValueError(f"Failed to read public key from {public_key_path}: {e}")

    return private_key, public_key


def load_config() -> AppConfig:
    """Load configuration from environment variables.

    Returns:
        AppConfig: Complete application configuration

    Raises:
        ValueError: If required configuration is missing or invalid
    """
    # JWT Configuration
    jwt_algorithm = os.getenv("JWT_ALGORITHM", "HS256").strip().upper()
    jwt_secret_key = os.getenv("JWT_SECRET_KEY", "").strip() or None

    # Load RSA keys from file paths if RS256
    jwt_private_key_path = os.getenv("JWT_PRIVATE_KEY_PATH", "").strip() or None
    jwt_public_key_path = os.getenv("JWT_PUBLIC_KEY_PATH", "").strip() or None

    jwt_private_key, jwt_public_key = _load_jwt_keys(
        jwt_algorithm,
        jwt_private_key_path,
        jwt_public_key_path
    )

    jwt_config = JWTConfig(
        algorithm=jwt_algorithm,
        secret_key=jwt_secret_key,
        private_key=jwt_private_key,
        public_key=jwt_public_key,
        access_token_expire_minutes=_env_int("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", 10080),  # 7 days for MCP clients
        refresh_token_expire_days=_env_int("JWT_REFRESH_TOKEN_EXPIRE_DAYS", 7),
        admin_token_expire_minutes=_env_int("ADMIN_TOKEN_EXPIRE_MINUTES", 480),  # 8 hours for admin panel
    )

    # Auth Configuration
    auth_config = AuthConfig(
        allow_registration=_env_bool("ALLOW_REGISTRATION", False),
        sqlite_path=os.getenv("AUTH_SQLITE_PATH", "data/auth.db"),
        password_min_length=_env_int("PASSWORD_MIN_LENGTH", 8),
        password_require_uppercase=_env_bool("PASSWORD_REQUIRE_UPPERCASE", True),
        password_require_lowercase=_env_bool("PASSWORD_REQUIRE_LOWERCASE", True),
        password_require_digit=_env_bool("PASSWORD_REQUIRE_DIGIT", True),
        password_require_special=_env_bool("PASSWORD_REQUIRE_SPECIAL", True),
    )

    # Rate Limiting Configuration
    rate_limit_config = RateLimitConfig(
        enabled=_env_bool("RATE_LIMIT_ENABLED", True),
        login_limit=_env_int("RATE_LIMIT_LOGIN_MAX", 5),
        login_window=_env_int("RATE_LIMIT_LOGIN_WINDOW", 60),
        register_limit=_env_int("RATE_LIMIT_REGISTER_MAX", 3),
        register_window=_env_int("RATE_LIMIT_REGISTER_WINDOW", 300),
        cleanup_interval=_env_int("RATE_LIMIT_CLEANUP_INTERVAL", 3600),
    )

    # Application Configuration
    mcp_public_url = os.getenv("MCP_PUBLIC_URL", "http://localhost:8000").rstrip("/")

    app_config = AppConfig(
        jwt=jwt_config,
        auth=auth_config,
        rate_limit=rate_limit_config,
        mcp_public_url=mcp_public_url,
        auth_required=_env_bool("AUTH_REQUIRED", True),
        static_bearer_tokens=_env_list("STATIC_BEARER_TOKENS"),
        trusted_ips=_env_set("MCP_TRUSTED_IPS"),
        rag_api_base_url=os.getenv("RAG_API_BASE_URL", "http://localhost:8004/api/v1").rstrip("/"),
        rag_api_bearer=os.getenv("RAG_API_BEARER", "").strip() or None,
        rag_api_key=os.getenv("RAG_API_KEY", "").strip() or None,
        rag_api_username=os.getenv("RAG_API_USERNAME", "").strip() or None,
        rag_api_password=os.getenv("RAG_API_PASSWORD", "").strip() or None,
        default_kb_id=os.getenv("DEFAULT_KB_ID", "").strip() or None,
        request_timeout_seconds=_env_int("REQUEST_TIMEOUT_SECONDS", 60),
        allow_insecure_http=_env_bool("ALLOW_INSECURE_HTTP", False),
        allowed_origins=_env_set("ALLOWED_ORIGINS"),
        disable_dns_rebinding=_env_bool("DISABLE_DNS_REBINDING", True),
        transport_allowed_hosts=_env_list("TRANSPORT_ALLOWED_HOSTS"),
        transport_allowed_origins=_env_list("TRANSPORT_ALLOWED_ORIGINS"),
        retrieval_config_path=os.getenv("RETRIEVAL_CONFIG_PATH", "").strip() or None,
        retrieval_config_ttl_seconds=float(os.getenv("RETRIEVAL_CONFIG_TTL_SECONDS", "2.0")),
        log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
    )

    return app_config


# Global config instance (loaded once on import)
_config_instance: Optional[AppConfig] = None


def get_config() -> AppConfig:
    """Get the global configuration instance.

    Returns:
        AppConfig: The application configuration
    """
    global _config_instance
    if _config_instance is None:
        _config_instance = load_config()
    return _config_instance
