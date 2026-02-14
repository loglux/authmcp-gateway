"""Dynamic settings manager for auth configuration."""
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from threading import Lock

logger = logging.getLogger(__name__)

class SettingsManager:
    """Manages dynamic auth settings with hot-reload support."""
    
    def __init__(self, settings_path: str):
        """Initialize settings manager.
        
        Args:
            settings_path: Path to JSON settings file
        """
        self.settings_path = Path(settings_path)
        self._settings: Dict[str, Any] = {}
        self._lock = Lock()
        self._load_settings()
    
    def _load_settings(self) -> None:
        """Load settings from JSON file."""
        try:
            if self.settings_path.exists():
                with open(self.settings_path, 'r') as f:
                    self._settings = json.load(f)
                logger.info(f"Settings loaded from {self.settings_path}")
            else:
                logger.warning(f"Settings file not found: {self.settings_path}, using defaults")
                self._settings = self._get_defaults()
        except Exception as e:
            logger.error(f"Failed to load settings: {e}, using defaults")
            self._settings = self._get_defaults()
    
    def _get_defaults(self) -> Dict[str, Any]:
        """Get default settings."""
        return {
            "jwt": {
                "access_token_expire_minutes": 1440,  # 24 hours
                "refresh_token_expire_days": 7
            },
            "password_policy": {
                "min_length": 8,
                "require_uppercase": True,
                "require_lowercase": True,
                "require_digit": True,
                "require_special": False
            },
            "system": {
                "allow_registration": True,
                "allow_dcr": False,
                "auth_required": True
            }
        }
    
    def get(self, *keys: str, default: Any = None) -> Any:
        """Get a setting value by nested keys.
        
        Args:
            *keys: Nested keys to traverse (e.g., "jwt", "access_token_expire_minutes")
            default: Default value if key not found
            
        Returns:
            Setting value or default
            
        Example:
            >>> settings.get("jwt", "access_token_expire_minutes")
            1440
        """
        with self._lock:
            value = self._settings
            for key in keys:
                if isinstance(value, dict) and key in value:
                    value = value[key]
                else:
                    return default
            return value
    
    def set(self, value: Any, *keys: str) -> None:
        """Set a setting value by nested keys.
        
        Args:
            value: Value to set
            *keys: Nested keys to traverse
            
        Example:
            >>> settings.set(2880, "jwt", "access_token_expire_minutes")
        """
        with self._lock:
            # Navigate to the parent dict
            current = self._settings
            for key in keys[:-1]:
                if key not in current:
                    current[key] = {}
                current = current[key]
            
            # Set the value
            current[keys[-1]] = value
    
    def get_all(self) -> Dict[str, Any]:
        """Get all settings.
        
        Returns:
            Complete settings dictionary
        """
        with self._lock:
            return dict(self._settings)
    
    def update(self, settings: Dict[str, Any]) -> None:
        """Update settings with a dictionary.
        
        Args:
            settings: Dictionary of settings to merge
        """
        with self._lock:
            self._deep_update(self._settings, settings)
    
    def _deep_update(self, target: Dict, source: Dict) -> None:
        """Deep update target dict with source dict."""
        for key, value in source.items():
            if isinstance(value, dict) and key in target and isinstance(target[key], dict):
                self._deep_update(target[key], value)
            else:
                target[key] = value
    
    def save(self) -> None:
        """Save current settings to file."""
        with self._lock:
            try:
                # Ensure directory exists
                self.settings_path.parent.mkdir(parents=True, exist_ok=True)
                
                # Write with pretty formatting
                with open(self.settings_path, 'w') as f:
                    json.dump(self._settings, f, indent=2)
                
                logger.info(f"Settings saved to {self.settings_path}")
            except Exception as e:
                logger.error(f"Failed to save settings: {e}")
                raise
    
    def reload(self) -> None:
        """Reload settings from file."""
        self._load_settings()


# Global settings manager instance
_settings_manager: Optional[SettingsManager] = None


def get_settings_manager() -> SettingsManager:
    """Get the global settings manager instance.
    
    Returns:
        SettingsManager instance
        
    Raises:
        RuntimeError: If settings manager not initialized
    """
    if _settings_manager is None:
        raise RuntimeError("Settings manager not initialized. Call initialize_settings() first.")
    return _settings_manager


def initialize_settings(settings_path: str) -> SettingsManager:
    """Initialize the global settings manager.
    
    Args:
        settings_path: Path to JSON settings file
        
    Returns:
        SettingsManager instance
    """
    global _settings_manager
    _settings_manager = SettingsManager(settings_path)
    return _settings_manager
