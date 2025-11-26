
from typing import List
from passive.base import PassiveSource
from utils.http_client import HTTPClient
from config import get_config

class Netlas(PassiveSource):

    def __init__(self):

        super().__init__("netlas")
        self.requires_api_key = True
    
    async def enumerate(self, domain: str, http_client: HTTPClient) -> List[str]:
        
        config = get_config()
        api_key = config.get_api_key('netlas')
        
        if not api_key:
            return []
        
        subdomains = []
        url = "https://app.netlas.io/api/domains/"
        headers = {
            'X-API-Key': api_key
        }
        params = {
            'q': f'domain:*.{domain}',
            'size': 100
        }
        
        try:
            data = await http_client.get_json(url, params=params, headers=headers)
            if data and 'items' in data:
                for item in data['items']:
                    subdomain = item.get('data', {}).get('domain', '')
                    if subdomain and domain in subdomain:
                        subdomains.append(subdomain)
        except Exception as e:
            pass
        
        return subdomains
