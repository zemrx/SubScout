import asyncio
from typing import List, Set, Optional
from pathlib import Path
from active.resolver import DNSResolver
from active.wildcard import WildcardDetector
from config import get_config

class BruteForcer:
    def __init__(self, domain: str, wordlist_path: str, concurrency: Optional[int] = None):

        self.domain = domain
        self.wordlist_path = Path(wordlist_path)
        config = get_config()
        self.concurrency = concurrency or config.get_active_concurrency()
        self.resolver = DNSResolver()
        self.wildcard_detector = WildcardDetector(domain, self.resolver)
        self.found_subdomains: Set[str] = set()
        self.total_words = 0
        self.processed = 0
    
    def load_wordlist(self) -> List[str]:

        words = []
        try:
            with open(self.wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    word = line.strip()
                    if word and not word.startswith('#'):
                        words.append(word)
        except Exception as e:
            raise Exception(f"Failed to load wordlist: {e}")
        
        return words
    
    async def check_subdomain(self, word: str) -> Optional[str]:

        subdomain = f"{word}.{self.domain}"
        
        ips = await self.resolver.resolve(subdomain)
        
        if ips:
            if self.wildcard_detector.is_wildcard_response(ips):
                return None
            return subdomain
        
        return None
    
    async def enumerate(self, progress_callback=None) -> List[str]:
        words = self.load_wordlist()
        self.total_words = len(words)
        
        if self.total_words == 0:
            raise Exception("Wordlist is empty")
        
        has_wildcard = await self.wildcard_detector.detect()
        
        semaphore = asyncio.Semaphore(self.concurrency)
        
        async def check_with_semaphore(word: str):
            async with semaphore:
                result = await self.check_subdomain(word)
                self.processed += 1
                
                if result:
                    self.found_subdomains.add(result)
                
                if progress_callback:
                    progress_callback(self.processed, self.total_words, result)
                
                return result
        
        tasks = [check_with_semaphore(word) for word in words]
        
        await asyncio.gather(*tasks)
        
        return sorted(list(self.found_subdomains))
