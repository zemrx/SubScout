
from typing import List
from passive.base import PassiveSource
from utils.http_client import HTTPClient

class BufferOver(PassiveSource):

    def __init__(self):

        super().__init__("bufferover")
        self.requires_api_key = False
    
    async def enumerate(self, domain: str, http_client: HTTPClient) -> List[str]:
        
        subdomains = []
        
        url = f"https://rapiddns.io/subdomain/{domain}?full=1"
        
        try:
            response = await http_client.get(url)
            if response:
                import re
                pattern = r'<td>([a-zA-Z0-9][-a-zA-Z0-9]*\.)*' + re.escape(domain) + r'</td>'
                matches = re.findall(pattern, response)
                for match in matches:
                    subdomain = match.replace('<td>', '').replace('</td>', '').strip()
                    if subdomain:
                        subdomains.append(subdomain)
                
                simple_pattern = r'([a-zA-Z0-9][-a-zA-Z0-9\.]*\.' + re.escape(domain) + r')'
                simple_matches = re.findall(simple_pattern, response)
                for match in simple_matches:
                    if match and domain in match:
                        subdomains.append(match)
        except Exception as e:
            pass
        
        return subdomains

class RapidDNS(PassiveSource):

    def __init__(self):

        super().__init__("rapiddns")
        self.requires_api_key = False
    
    async def enumerate(self, domain: str, http_client: HTTPClient) -> List[str]:
        
        subdomains = []
        url = f"https://rapiddns.io/subdomain/{domain}?full=1#result"
        
        try:
            response = await http_client.get(url)
            if response:
                import re
                pattern = r'([a-zA-Z0-9][-a-zA-Z0-9]*\.)*([a-zA-Z0-9][-a-zA-Z0-9]*\.)?' + re.escape(domain)
                matches = re.findall(pattern, response)
                
                full_pattern = r'([a-zA-Z0-9][-a-zA-Z0-9\.]*\.' + re.escape(domain) + r')(?=["\s<])'
                full_matches = re.findall(full_pattern, response)
                for match in full_matches:
                    if match and domain in match:
                        subdomains.append(match)
        except Exception as e:
            pass
        
        return subdomains
