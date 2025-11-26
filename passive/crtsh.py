
import re
from typing import List
from passive.base import PassiveSource
from utils.http_client import HTTPClient

class CrtSh(PassiveSource):

    def __init__(self):

        super().__init__("crt.sh")
        self.requires_api_key = False
    
    async def enumerate(self, domain: str, http_client: HTTPClient) -> List[str]:
        
        subdomains = []
        url = "https://crt.sh/"
        params = {
            'q': f'%.{domain}',
            'output': 'json'
        }
        
        try:
            data = await http_client.get_json(url, params=params)
            if data:
                for entry in data:
                    name_value = entry.get('name_value', '')
                    for subdomain in name_value.split('\n'):
                        subdomain = subdomain.strip()
                        if subdomain and domain in subdomain:
                            subdomain = subdomain.replace('*.', '')
                            if subdomain:
                                subdomains.append(subdomain)
        except Exception as e:
            pass
        
        return subdomains
