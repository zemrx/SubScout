
from typing import List
from passive.base import PassiveSource
from utils.http_client import HTTPClient

class CertSpotter(PassiveSource):

    def __init__(self):

        super().__init__("certspotter")
        self.requires_api_key = False
    
    async def enumerate(self, domain: str, http_client: HTTPClient) -> List[str]:
        
        subdomains = []
        url = f"https://api.certspotter.com/v1/issuances"
        params = {
            'domain': domain,
            'include_subdomains': 'true',
            'expand': 'dns_names'
        }
        
        try:
            data = await http_client.get_json(url, params=params)
            if data and isinstance(data, list):
                for entry in data:
                    dns_names = entry.get('dns_names', [])
                    for name in dns_names:
                        if domain in name:
                            name = name.replace('*.', '')
                            if name:
                                subdomains.append(name)
        except Exception as e:
            pass
        
        return subdomains
