import random
import string
from typing import Optional, Set
from .resolver import DNSResolver

class WildcardDetector:
    def __init__(self, domain: str, resolver: DNSResolver):
        self.domain = domain
        self.resolver = resolver
        self.wildcard_ips: Set[str] = set()
        self.has_wildcard = False
    
    def _generate_random_subdomain(self) -> str:
        random_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=20))
        return f"{random_str}.{self.domain}"
    
    async def detect(self, num_tests: int = 5) -> bool:
        wildcard_responses = []
        
        for _ in range(num_tests):
            random_subdomain = self._generate_random_subdomain()
            ips = await self.resolver.resolve(random_subdomain)
            
            if ips:
                wildcard_responses.append(set(ips))
        
        if len(wildcard_responses) >= 2:
            first_set = wildcard_responses[0]
            if all(response == first_set for response in wildcard_responses[1:]):
                self.has_wildcard = True
                self.wildcard_ips = first_set
                return True
        
        return False
    
    def is_wildcard_response(self, ips: list) -> bool:

        if not self.has_wildcard:
            return False
        
        ip_set = set(ips)
        return bool(ip_set & self.wildcard_ips)
