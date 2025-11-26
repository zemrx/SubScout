
from typing import List
from passive.base import PassiveSource
from utils.http_client import HTTPClient

class URLScan(PassiveSource):

    def __init__(self):

        super().__init__("urlscan")
        self.requires_api_key = False
    
    async def enumerate(self, domain: str, http_client: HTTPClient) -> List[str]:
        
        subdomains = []
        url = "https://urlscan.io/api/v1/search/"
        params = {
            'q': f'domain:{domain}',
            'size': 100
        }
        
        try:
            data = await http_client.get_json(url, params=params)
            if data and 'results' in data:
                for result in data['results']:
                    page_domain = result.get('page', {}).get('domain', '')
                    if page_domain and domain in page_domain:
                        subdomains.append(page_domain)
                    
                    task_domain = result.get('task', {}).get('domain', '')
                    if task_domain and domain in task_domain:
                        subdomains.append(task_domain)
        except Exception as e:
            pass
        
        return subdomains
