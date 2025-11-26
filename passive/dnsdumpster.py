
from typing import List
from passive.base import PassiveSource
from utils.http_client import HTTPClient
import re

class DNSdumpster(PassiveSource):

    def __init__(self):

        super().__init__("dnsdumpster")
        self.requires_api_key = False
    
    async def enumerate(self, domain: str, http_client: HTTPClient) -> List[str]:
        
        subdomains = []
        
        try:
            url = "https://dnsdumpster.com/"
            initial_response = await http_client.get(url)
            
            if not initial_response:
                return subdomains
            
            csrf_pattern = r'name=["\']csrfmiddlewaretoken["\'] value=["\']([^"\']+)["\']'
            csrf_match = re.search(csrf_pattern, initial_response)
            
            if not csrf_match:
                return subdomains
            
            csrf_token = csrf_match.group(1)
            
            post_data = {
                'csrfmiddlewaretoken': csrf_token,
                'targetip': domain,
                'user': 'free'
            }
            
            headers = {
                'Referer': 'https://dnsdumpster.com/',
                'Origin': 'https://dnsdumpster.com'
            }
            
            response = await http_client.post(url, data=post_data, headers=headers)
            
            if response:
                subdomain_pattern = r'([a-zA-Z0-9][-a-zA-Z0-9\.]*\.' + re.escape(domain) + r')(?=["\s<])'
                matches = re.findall(subdomain_pattern, response)
                
                for match in matches:
                    if match and domain in match:
                        clean_subdomain = match.strip()
                        if clean_subdomain.endswith('.' + domain) or clean_subdomain == domain:
                            subdomains.append(clean_subdomain)
        
        except Exception as e:
            pass
        
        return subdomains
