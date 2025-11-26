
from typing import List
from passive.base import PassiveSource
from utils.http_client import HTTPClient
from config import get_config

class SecurityTrails(PassiveSource):

    def __init__(self):

        super().__init__("securitytrails")
        self.requires_api_key = True
    
    async def enumerate(self, domain: str, http_client: HTTPClient) -> List[str]:
        
        config = get_config()
        api_key = config.get_api_key('securitytrails')
        
        if not api_key:
            return []
        
        subdomains = []
        url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
        headers = {
            'APIKEY': api_key
        }
        
        try:
            data = await http_client.get_json(url, headers=headers)
            if data and 'subdomains' in data:
                for prefix in data['subdomains']:
                    subdomain = f"{prefix}.{domain}"
                    subdomains.append(subdomain)
        except Exception as e:
            pass
        
        return subdomains
