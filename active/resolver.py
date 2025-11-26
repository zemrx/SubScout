import asyncio
import dns.resolver
import dns.asyncresolver
from typing import List, Optional, Set
from config import get_config

class DNSResolver:
    def __init__(self, resolvers: Optional[List[str]] = None):
        config = get_config()
        self.resolvers = resolvers or config.get_dns_resolvers()
        self.timeout = config.get_dns_timeout()
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.nameservers = self.resolvers
        self.resolver.timeout = self.timeout
        self.resolver.lifetime = self.timeout
    
    async def resolve(self, hostname: str, record_type: str = 'A') -> Optional[List[str]]:
        try:
            answers = await self.resolver.resolve(hostname, record_type)
            return [str(rdata) for rdata in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return None
        except dns.exception.Timeout:
            return None
        except Exception as e:
            return None
    
    async def resolve_multiple(self, hostname: str) -> Optional[dict]:
        results = {}
        
        a_records = await self.resolve(hostname, 'A')
        if a_records:
            results['A'] = a_records
        
        aaaa_records = await self.resolve(hostname, 'AAAA')
        if aaaa_records:
            results['AAAA'] = aaaa_records
        
        cname_records = await self.resolve(hostname, 'CNAME')
        if cname_records:
            results['CNAME'] = cname_records
        
        return results if results else None
    
    async def check_exists(self, hostname: str) -> bool:
        result = await self.resolve(hostname)
        return result is not None
