
from typing import List
from passive.base import PassiveSource
from utils.http_client import HTTPClient

class AnubisDB(PassiveSource):

    def __init__(self):

        super().__init__("anubisdb")
        self.requires_api_key = False
    
    async def enumerate(self, domain: str, http_client: HTTPClient) -> List[str]:
        
        subdomains = []
        url = f"https://jldc.me/anubis/subdomains/{domain}"
        
        try:
            data = await http_client.get_json(url)
            if data and isinstance(data, list):
                subdomains = [s for s in data if isinstance(s, str)]
        except Exception as e:
            pass
        
        return subdomains
