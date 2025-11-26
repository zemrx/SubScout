
import re
from typing import List
from passive.base import PassiveSource
from utils.http_client import HTTPClient

class GoogleDork(PassiveSource):

    def __init__(self):

        super().__init__("googledork")
        self.requires_api_key = False
    
    async def enumerate(self, domain: str, http_client: HTTPClient) -> List[str]:
        
        subdomains = []
        

        return subdomains

class BingDork(PassiveSource):

    def __init__(self):

        super().__init__("bingdork")
        self.requires_api_key = False
    
    async def enumerate(self, domain: str, http_client: HTTPClient) -> List[str]:
        
        subdomains = []
        
        url = "https://www.bing.com/search"
        
        params = {
            'q': f'domain:{domain}',
            'first': 1
        }
        
        try:
 
            response = await http_client.get(url, params=params)
            if response:

                subdomain_pattern = r'https?://([a-zA-Z0-9.-]+\.' + re.escape(domain) + r')'
                matches = re.findall(subdomain_pattern, response)
                for match in matches:
                    if match.endswith('.' + domain) or match == domain:
                        subdomains.append(match)
        except Exception as e:
            pass
        
        return subdomains
