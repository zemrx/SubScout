
from typing import List
from .base import PassiveSource
from ..utils.http_client import HTTPClient
from ..config import get_config

class FullHunt(PassiveSource):

    def __init__(self):

        super().__init__("fullhunt")
        self.requires_api_key = True
    
    async def enumerate(self, domain: str, http_client: HTTPClient) -> List[str]:
        
        config = get_config()
        api_key = config.get_api_key('fullhunt')
        
        if not api_key:
            return []
        
        subdomains = []
        url = f"https://fullhunt.io/api/v1/domain/{domain}/subdomains"
        headers = {
            'X-API-KEY': api_key
        }
        
        try:
            data = await http_client.get_json(url, headers=headers)
            if data and 'hosts' in data:
                for host in data['hosts']:
                    subdomain = host.get('domain', '')
                    if subdomain and domain in subdomain:
                        subdomains.append(subdomain)
        except Exception as e:
            pass
        
        return subdomains
