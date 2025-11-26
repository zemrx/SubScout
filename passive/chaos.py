
from typing import List
from passive.base import PassiveSource
from utils.http_client import HTTPClient

class Chaos(PassiveSource):

    def __init__(self):

        super().__init__("chaos")
        self.requires_api_key = False
    
    async def enumerate(self, domain: str, http_client: HTTPClient) -> List[str]:
        
        subdomains = []
        
        url = f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"
        
        try:
            data = await http_client.get_json(url)
            if data and 'subdomains' in data:
                for subdomain in data['subdomains']:
                    full_subdomain = f"{subdomain}.{domain}"
                    subdomains.append(full_subdomain)
            elif isinstance(data, list):
                for subdomain in data:
                    if isinstance(subdomain, str):
                        if '.' in subdomain:
                            subdomains.append(subdomain)
                        else:
                            subdomains.append(f"{subdomain}.{domain}")
        except Exception as e:
            pass
        
        return subdomains
