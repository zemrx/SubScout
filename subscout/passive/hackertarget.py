
from typing import List
from .base import PassiveSource
from ..utils.http_client import HTTPClient

class HackerTarget(PassiveSource):

    def __init__(self):

        super().__init__("hackertarget")
        self.requires_api_key = False
    
    async def enumerate(self, domain: str, http_client: HTTPClient) -> List[str]:
        
        subdomains = []
        url = "https://api.hackertarget.com/hostsearch/"
        params = {'q': domain}
        
        try:
            response = await http_client.get(url, params=params)
            if response:
                for line in response.strip().split('\n'):
                    if ',' in line:
                        subdomain = line.split(',')[0].strip()
                        if subdomain and domain in subdomain:
                            subdomains.append(subdomain)
        except Exception as e:
            pass
        
        return subdomains
