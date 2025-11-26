
from typing import List
from .base import PassiveSource
from ..utils.http_client import HTTPClient
from ..config import get_config

class VirusTotal(PassiveSource):

    def __init__(self):

        super().__init__("virustotal")
        self.requires_api_key = True
    
    async def enumerate(self, domain: str, http_client: HTTPClient) -> List[str]:
        
        config = get_config()
        api_key = config.get_api_key('virustotal')
        
        if not api_key:
            return []
        
        subdomains = []
        url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
        headers = {
            'x-apikey': api_key
        }
        
        try:
            cursor = None
            while True:
                params = {'limit': 40}
                if cursor:
                    params['cursor'] = cursor
                
                data = await http_client.get_json(url, params=params, headers=headers)
                if not data or 'data' not in data:
                    break
                
                for entry in data['data']:
                    subdomain = entry.get('id', '')
                    if subdomain:
                        subdomains.append(subdomain)
                
                cursor = data.get('meta', {}).get('cursor')
                if not cursor:
                    break
                
        except Exception as e:
            pass
        
        return subdomains
