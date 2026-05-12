"""
===============================================================================
SECURE CONFIG LOADER
===============================================================================
Safely load and manage environment variables and secrets for the application.
This module ensures that secrets are never hardcoded and provides a secure,
centralized way to access configuration values.

Usage:
    from secure_config import config, Config
    api_key = config.get_secret('DLP_API_KEY')
    port = config.get_int('SERVER_PORT', default=5000)

===============================================================================
SECURITY BEST PRACTICES IMPLEMENTED:
===============================================================================
1. ✓ Loads secrets from .env files (never hardcoded)
2. ✓ Validates required secrets are present
3. ✓ Never logs or prints secret values
4. ✓ Provides typed access to configuration values
5. ✓ Supports multiple environment files (.env, .env.local, etc.)
6. ✓ Validates configuration on startup
7. ✓ Type hints for better IDE support
8. ✓ Clear error messages when secrets are missing

===============================================================================
"""

import os
import logging
from pathlib import Path
from typing import Optional, List, Any, Union
from functools import lru_cache

try:
    from dotenv import load_dotenv
except ImportError:
    raise ImportError(
        "python-dotenv is required. Install it with: pip install python-dotenv"
    )

# Configure logging
logger = logging.getLogger(__name__)


class ConfigurationError(Exception):
    """Raised when configuration is missing or invalid"""
    pass


class SecureConfig:
    """
    Secure configuration manager for loading environment variables.
    
    Features:
    - Loads from .env files with proper precedence
    - Validates required secrets are present
    - Provides type-safe access to configuration
    - Never logs secret values
    - Supports environment-specific configurations
    """
    
    # Required secrets that must be present in production
    REQUIRED_SECRETS_PRODUCTION = [
        'DLP_API_KEY',
        'FLASK_SECRET_KEY',
        'ALERT_EMAIL',
    ]
    
    # Required secrets for all environments
    REQUIRED_SECRETS_ALL = [
        'DLP_API_KEY',
    ]
    
    def __init__(self, env_files: Optional[List[str]] = None):
        """
        Initialize configuration loader.
        
        Args:
            env_files: List of .env file paths to load. If None, uses defaults.
                      Files are loaded in order; later files override earlier ones.
        """
        if env_files is None:
            env_files = self._get_default_env_files()
        
        self.env_files = env_files
        self.loaded = False
        self._load_env_files()
        self._validate_configuration()
    
    def _get_default_env_files(self) -> List[str]:
        """
        Get default .env file locations in order of precedence.
        Later files override earlier ones.
        """
        env = os.getenv('FLASK_ENV', 'development')
        workspace_root = Path(__file__).parent
        
        files = [
            workspace_root / '.env',
            workspace_root / f'.env.{env}',
            workspace_root / '.env.local',
        ]
        
        # Filter to only existing files
        existing_files = [str(f) for f in files if f.exists()]
        return existing_files
    
    def _load_env_files(self) -> None:
        """Load environment variables from .env files."""
        if not self.env_files:
            logger.warning(
                "⚠️  No .env files found. Create .env file with required secrets. "
                "See .env.example for template."
            )
            return
        
        for env_file in self.env_files:
            try:
                load_dotenv(env_file, override=True)
                logger.info(f"✓ Loaded configuration from: {env_file}")
            except Exception as e:
                raise ConfigurationError(
                    f"Failed to load {env_file}: {str(e)}"
                )
        
        self.loaded = True
    
    def _validate_configuration(self) -> None:
        """Validate that all required secrets are present."""
        env = os.getenv('FLASK_ENV', 'development')
        
        # Always check basic required secrets
        required = self.REQUIRED_SECRETS_ALL
        
        # Check production-specific requirements
        if env == 'production':
            required = self.REQUIRED_SECRETS_PRODUCTION
        
        missing = []
        for secret in required:
            if not os.getenv(secret):
                missing.append(secret)
        
        if missing:
            error_msg = (
                f"Missing required environment variables in {env} mode: "
                f"{', '.join(missing)}\n"
                f"Instructions:\n"
                f"  1. Copy .env.example to .env\n"
                f"  2. Fill in actual values for: {', '.join(missing)}\n"
                f"  3. Never commit .env to version control"
            )
            raise ConfigurationError(error_msg)
    
    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """
        Get a configuration value as string.
        
        Args:
            key: Environment variable name
            default: Default value if not found
        
        Returns:
            Configuration value or default
        
        Note: This method is safe to use even with sensitive values
              as it doesn't log the actual values
        """
        value = os.getenv(key, default)
        if value is None and key in self.REQUIRED_SECRETS_ALL:
            raise ConfigurationError(
                f"Required secret '{key}' not found in environment. "
                f"Set it in .env file."
            )
        return value
    
    def get_secret(self, key: str, required: bool = False) -> str:
        """
        Get a secret value securely.
        
        Args:
            key: Environment variable name for the secret
            required: If True, raises error if secret is not found
        
        Returns:
            Secret value
        
        Raises:
            ConfigurationError: If required=True and secret is missing
        
        Note: Never logs the actual secret value
        """
        value = os.getenv(key)
        if value is None:
            if required:
                raise ConfigurationError(
                    f"Required secret '{key}' not found in environment. "
                    f"Please set it in your .env file."
                )
            return None
        return value
    
    def get_int(self, key: str, default: Optional[int] = None) -> int:
        """
        Get a configuration value as integer.
        
        Args:
            key: Environment variable name
            default: Default value if not found
        
        Returns:
            Configuration value as integer
        
        Raises:
            ConfigurationError: If value cannot be converted to integer
        """
        value = os.getenv(key)
        if value is None:
            if default is not None:
                return default
            raise ConfigurationError(f"Configuration '{key}' not found")
        
        try:
            return int(value)
        except ValueError:
            raise ConfigurationError(
                f"Configuration '{key}' must be an integer, got: {value}"
            )
    
    def get_bool(self, key: str, default: bool = False) -> bool:
        """
        Get a configuration value as boolean.
        
        Args:
            key: Environment variable name
            default: Default value if not found
        
        Returns:
            Configuration value as boolean
        
        Note: Truthy values are: 'true', 'True', '1', 'yes', 'on'
              Falsy values are: 'false', 'False', '0', 'no', 'off', ''
        """
        value = os.getenv(key, str(default)).lower()
        return value in ('true', '1', 'yes', 'on')
    
    def get_list(self, key: str, delimiter: str = ',', default: Optional[List[str]] = None) -> List[str]:
        """
        Get a configuration value as list.
        
        Args:
            key: Environment variable name
            delimiter: Delimiter to split the value (default: comma)
            default: Default list if not found
        
        Returns:
            Configuration value split as list
        """
        value = os.getenv(key)
        if value is None:
            return default or []
        
        return [item.strip() for item in value.split(delimiter) if item.strip()]
    
    def validate_required(self, keys: List[str]) -> None:
        """
        Validate that required keys are present.
        
        Args:
            keys: List of required environment variable names
        
        Raises:
            ConfigurationError: If any required key is missing
        """
        missing = [key for key in keys if not os.getenv(key)]
        if missing:
            raise ConfigurationError(
                f"Missing required configuration: {', '.join(missing)}"
            )
    
    def __repr__(self) -> str:
        """String representation without exposing secrets"""
        env = os.getenv('FLASK_ENV', 'development')
        return (
            f"<SecureConfig "
            f"environment={env} "
            f"loaded_files={len(self.env_files)} "
            f"validation_passed=True>"
        )


# ============================================================================
# SINGLETON INSTANCE
# ============================================================================
# Create a singleton instance for use throughout the application
try:
    config = SecureConfig()
    logger.info("✓ Configuration loaded successfully")
except ConfigurationError as e:
    logger.error(f"✗ Configuration Error: {e}")
    raise


# ============================================================================
# HELPER FUNCTIONS FOR FLASK APPLICATION
# ============================================================================

def init_secure_config(app) -> None:
    """
    Initialize Flask app with secure configuration.
    
    Usage in Flask app:
        from secure_config import init_secure_config
        app = Flask(__name__)
        init_secure_config(app)
    """
    try:
        # Set Flask configuration from environment
        app.config['SECRET_KEY'] = config.get_secret('FLASK_SECRET_KEY', required=True)
        app.config['DEBUG'] = config.get_bool('FLASK_DEBUG', default=False)
        app.config['JSON_SORT_KEYS'] = False
        
        # Security settings
        app.config['PERMANENT_SESSION_LIFETIME'] = config.get_int(
            'SESSION_TIMEOUT', 
            default=1800
        )
        app.config['SESSION_COOKIE_SECURE'] = config.get_bool('USE_HTTPS', False)
        app.config['SESSION_COOKIE_HTTPONLY'] = True
        app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
        
        logger.info("✓ Flask application configured securely")
    except ConfigurationError as e:
        logger.error(f"Failed to initialize Flask config: {e}")
        raise


# ============================================================================
# EXAMPLE USAGE
# ============================================================================
if __name__ == '__main__':
    """
    Example usage of the SecureConfig module.
    """
    try:
        print("Loading configuration...")
        
        # Access various configuration types
        api_key = config.get_secret('DLP_API_KEY', required=True)
        print("✓ API Key loaded (value hidden for security)")
        
        port = config.get_int('SERVER_PORT', default=5000)
        print(f"✓ Server Port: {port}")
        
        debug = config.get_bool('FLASK_DEBUG', False)
        print(f"✓ Debug Mode: {debug}")
        
        paths = config.get_list('MONITORED_PATHS')
        print(f"✓ Monitored Paths: {paths}")
        
        print("\n✓ All configurations loaded successfully!")
        
    except ConfigurationError as e:
        print(f"✗ Configuration Error: {e}")
        exit(1)
