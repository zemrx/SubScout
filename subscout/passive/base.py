from abc import ABC, abstractmethod
from typing import List
from ..utils.http_client import HTTPClient

class PassiveSource(ABC):
    def __init__(self, name: str):
        self.name = name
        self.requires_api_key = False
    
    @abstractmethod
    async def enumerate(self, domain: str, http_client: HTTPClient) -> List[str]:
        pass
    
    def is_available(self) -> bool:
        if self.requires_api_key:
            from ..config import get_config
            config = get_config()
            return config.has_api_key(self.name.lower())
        return True
