
from typing import List
from .base import PassiveSource
from ..utils.http_client import HTTPClient

class ThreatCrowd(PassiveSource):

    def __init__(self):

        super().__init__("threatcrowd")
        self.requires_api_key = False
    
    async def enumerate(self, domain: str, http_client: HTTPClient) -> List[str]:
        
        subdomains = []
        url = "https://www.threatcrowd.org/searchApi/v2/domain/report/"
        params = {'domain': domain}
        
        try:
            data = await http_client.get_json(url, params=params)
            if data and 'subdomains' in data:
                subdomains = data['subdomains']
        except Exception as e:
            pass
        
        return subdomains
