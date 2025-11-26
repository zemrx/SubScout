from typing import List
from passive.base import PassiveSource
from utils.http_client import HTTPClient

class AlienVault(PassiveSource):

    def __init__(self):

        super().__init__("alienvault")
        self.requires_api_key = False
    
    async def enumerate(self, domain: str, http_client: HTTPClient) -> List[str]:
        
        subdomains = []
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        
        try:
            data = await http_client.get_json(url)
            if data and 'passive_dns' in data:
                for entry in data['passive_dns']:
                    hostname = entry.get('hostname', '')
                    if hostname and domain in hostname:
                        subdomains.append(hostname)
        except Exception as e:
            pass
        
        return subdomains
