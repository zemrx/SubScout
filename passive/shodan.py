
from typing import List
from passive.base import PassiveSource
from utils.http_client import HTTPClient
from config import get_config

class Shodan(PassiveSource):

    def __init__(self):

        super().__init__("shodan")
        self.requires_api_key = True
    
    async def enumerate(self, domain: str, http_client: HTTPClient) -> List[str]:
        
        config = get_config()
        api_key = config.get_api_key('shodan')
        
        if not api_key:
            return []
        
        subdomains = []
        url = "https://api.shodan.io/dns/domain/" + domain
        params = {'key': api_key}
        
        try:
            data = await http_client.get_json(url, params=params)
            if data and 'subdomains' in data:
                for prefix in data['subdomains']:
                    subdomain = f"{prefix}.{domain}"
                    subdomains.append(subdomain)
        except Exception as e:
            pass
        
        return subdomains
