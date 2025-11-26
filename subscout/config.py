
import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional

class Config:

    def __init__(self, config_file: str = "config.yaml"):
        
        self.config_file = Path(config_file)
        self.config: Dict[str, Any] = {}
        self.load_config()
    
    def load_config(self) -> None:

        if self.config_file.exists():
            with open(self.config_file, 'r') as f:
                self.config = yaml.safe_load(f) or {}
        else:
            self.config = self._default_config()
            self.save_config()
    
    def save_config(self) -> None:

        with open(self.config_file, 'w') as f:
            yaml.dump(self.config, f, default_flow_style=False)
    
    def _default_config(self) -> Dict[str, Any]:

        return {
            'api_keys': {
                'securitytrails': '',
                'virustotal': '',
                'shodan': '',
                'censys_id': '',
                'censys_secret': '',
                'binaryedge': '',
                'passivetotal_user': '',
                'passivetotal_key': '',
                'fullhunt': '',
                'netlas': ''
            },
            'settings': {
                'dns_resolvers': ['1.1.1.1', '8.8.8.8', '8.8.4.4', '9.9.9.9'],
                'passive_concurrency': 10,
                'active_concurrency': 100,
                'http_timeout': 10,
                'dns_timeout': 5,
                'retry_attempts': 3,
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        }
    
    def get_api_key(self, service: str) -> Optional[str]:
        
        env_var = f"SUBENUM_{service.upper()}"
        env_key = os.getenv(env_var)
        if env_key:
            return env_key
        
        api_keys = self.config.get('api_keys', {})
        key = api_keys.get(service, '')
        return key if key else None
    
    def has_api_key(self, service: str) -> bool:
        
        return self.get_api_key(service) is not None
    
    def get_setting(self, key: str, default: Any = None) -> Any:
        
        return self.config.get('settings', {}).get(key, default)
    
    def get_dns_resolvers(self) -> list:

        return self.get_setting('dns_resolvers', ['1.1.1.1', '8.8.8.8'])
    
    def get_passive_concurrency(self) -> int:

        return self.get_setting('passive_concurrency', 10)
    
    def get_active_concurrency(self) -> int:

        return self.get_setting('active_concurrency', 100)
    
    def get_http_timeout(self) -> int:

        return self.get_setting('http_timeout', 10)
    
    def get_dns_timeout(self) -> int:

        return self.get_setting('dns_timeout', 5)
    
    def get_retry_attempts(self) -> int:

        return self.get_setting('retry_attempts', 3)
    
    def get_user_agent(self) -> str:

        return self.get_setting('user_agent', 'SubdomainEnumerator/1.0')

_config: Optional[Config] = None

def get_config(config_file: str = "config.yaml") -> Config:
    
    global _config
    if _config is None:
        _config = Config(config_file)
    return _config
