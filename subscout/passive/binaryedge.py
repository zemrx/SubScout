
from typing import List
from .base import PassiveSource
from ..utils.http_client import HTTPClient
from ..config import get_config

class BinaryEdge(PassiveSource):

    def __init__(self):

        super().__init__("binaryedge")
        self.requires_api_key = True
    
    async def enumerate(self, domain: str, http_client: HTTPClient) -> List[str]:
        
        config = get_config()
        api_key = config.get_api_key('binaryedge')
        
        if not api_key:
            return []
        
        subdomains = []
        url = f"https://api.binaryedge.io/v2/query/domains/subdomain/{domain}"
        headers = {
            'X-Key': api_key
        }
        
        try:
            data = await http_client.get_json(url, headers=headers)
            if data and 'events' in data:
                for event in data['events']:
                    subdomain = event
                    if isinstance(subdomain, str) and domain in subdomain:
                        subdomains.append(subdomain)
        except Exception as e:
            pass
        
        return subdomains
