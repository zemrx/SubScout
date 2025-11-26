
import asyncio
from typing import List, Dict, Set, Tuple
from collections import defaultdict
from .http_client import HTTPClient

class AnomalyDetector:

    def __init__(self, main_domain: str, verbose: bool = False):
        self.main_domain = main_domain
        self.verbose = verbose
        self.content_length_map = defaultdict(list)
        self.status_code_map = defaultdict(list)
        self.redirect_targets = defaultdict(list)
        self.anomalies = {
            'wildcard_responses': [],
            'mass_redirects': [],
            'suspicious_patterns': []
        }
    
    async def probe_subdomain(self, subdomain: str, http_client: HTTPClient) -> Dict:
        
        result = {
            'subdomain': subdomain,
            'status_code': None,
            'content_length': None,
            'redirect_target': None,
            'is_anomaly': False,
            'accessible': False
        }
        
        url = f"http://{subdomain}"
        
        try:
            async with http_client.session.get(url, allow_redirects=False, timeout=5) as response:
                result['status_code'] = response.status
                result['content_length'] = response.headers.get('Content-Length')
                result['accessible'] = True
                
                if self.verbose:
                    print(f"[V] {subdomain} - HTTP {response.status}")
                
                if response.status in [301, 302, 303, 307, 308]:
                    result['redirect_target'] = response.headers.get('Location', '')
                    if self.verbose and result['redirect_target']:
                        print(f"[V]   → Redirects to: {result['redirect_target']}")
        except Exception as e:
            if self.verbose:
                print(f"[V] {subdomain} - No HTTP response")
        
        return result
    
    def _is_wildcard_pattern(self, subdomains_with_same_response: List[str], threshold: int = 5) -> bool:
        """
        Detect if multiple subdomains with identical responses indicate wildcard DNS
        Returns True if >= threshold subdomains have the same response
        """
        return len(subdomains_with_same_response) >= threshold
    
    def _is_legitimate_redirect(self, subdomain: str, redirect_target: str) -> bool:
        """
        Determine if a redirect is legitimate (e.g., HTTP->HTTPS, subdomain->www)
        """
        if not redirect_target:
            return False
        
        # Allow HTTP to HTTPS redirects
        if redirect_target.startswith('https://') and subdomain in redirect_target:
            return True
        
        # Allow redirects to www variant
        if f'www.{subdomain}' in redirect_target or subdomain.replace('www.', '') in redirect_target:
            return True
        
        # Allow redirects within same subdomain structure
        if subdomain.split('.')[0] in redirect_target:
            return True
        
        return False
    
    async def analyze_subdomains(self, subdomains: List[str], http_client: HTTPClient, 
                                 concurrency: int = 50) -> Tuple[List[str], Dict]:
        
        semaphore = asyncio.Semaphore(concurrency)
        
        async def probe_with_semaphore(subdomain: str):
            async with semaphore:
                return await self.probe_subdomain(subdomain, http_client)
        
        tasks = [probe_with_semaphore(sub) for sub in subdomains]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Group by response characteristics
        for result in results:
            if isinstance(result, Exception):
                continue
            
            if not result['accessible']:
                continue
            
            subdomain = result['subdomain']
            status_code = result['status_code']
            content_length = result['content_length']
            redirect_target = result['redirect_target']
            
            # Track status codes
            self.status_code_map[status_code].append(subdomain)
            
            # Track content lengths (only for successful responses)
            if status_code == 200 and content_length:
                self.content_length_map[content_length].append(subdomain)
            
            # Track redirects
            if redirect_target:
                self.redirect_targets[redirect_target].append(subdomain)
        
        # Detect wildcard DNS patterns (many subdomains with identical 200 responses)
        for length, subs in self.content_length_map.items():
            if self._is_wildcard_pattern(subs, threshold=10):
                self.anomalies['wildcard_responses'].extend(subs)
                if self.verbose:
                    print(f"[!] Detected wildcard pattern: {len(subs)} subdomains with {length} bytes response")
        
        # Detect mass redirects to same target (likely wildcard or catch-all)
        for target, subs in self.redirect_targets.items():
            if self._is_wildcard_pattern(subs, threshold=5):
                # Filter out legitimate redirects
                suspicious = [s for s in subs if not self._is_legitimate_redirect(s, target)]
                if suspicious:
                    self.anomalies['mass_redirects'].extend(suspicious)
                    if self.verbose:
                        print(f"[!] Detected mass redirect: {len(suspicious)} subdomains → {target}")
        
        # Detect suspicious patterns (many 403/404 with same content length)
        for status_code in [403, 404]:
            if status_code in self.status_code_map:
                subs_with_status = self.status_code_map[status_code]
                if self._is_wildcard_pattern(subs_with_status, threshold=10):
                    self.anomalies['suspicious_patterns'].extend(subs_with_status)
                    if self.verbose:
                        print(f"[!] Detected suspicious pattern: {len(subs_with_status)} subdomains with HTTP {status_code}")
        
        # Build set of all anomalies
        all_anomalies = set(
            self.anomalies['wildcard_responses'] +
            self.anomalies['mass_redirects'] +
            self.anomalies['suspicious_patterns']
        )
        
        # Clean subdomains are those that are accessible and not flagged as anomalies
        clean_subdomains = [
            r['subdomain'] for r in results 
            if not isinstance(r, Exception) and 
            r['accessible'] and 
            r['subdomain'] not in all_anomalies
        ]
        
        return clean_subdomains, self.anomalies
    
    def save_anomalies(self, filename: str):
        
        with open(filename, 'w') as f:
            f.write("# Anomalous Subdomains\n\n")
            f.write("This file contains subdomains that were filtered out due to suspicious patterns.\n")
            f.write("These are likely wildcard DNS entries, catch-all redirects, or error pages.\n\n")
            
            if self.anomalies['wildcard_responses']:
                f.write(f"## Wildcard DNS Responses ({len(set(self.anomalies['wildcard_responses']))} subdomains)\n")
                f.write("Multiple subdomains returning identical content (likely wildcard DNS)\n\n")
                for sub in sorted(set(self.anomalies['wildcard_responses'])):
                    f.write(f"{sub}\n")
                f.write("\n")
            
            if self.anomalies['mass_redirects']:
                f.write(f"## Mass Redirects ({len(set(self.anomalies['mass_redirects']))} subdomains)\n")
                f.write("Multiple subdomains redirecting to the same target (likely catch-all)\n\n")
                for sub in sorted(set(self.anomalies['mass_redirects'])):
                    f.write(f"{sub}\n")
                f.write("\n")
            
            if self.anomalies['suspicious_patterns']:
                f.write(f"## Suspicious Patterns ({len(set(self.anomalies['suspicious_patterns']))} subdomains)\n")
                f.write("Multiple subdomains with identical error responses\n\n")
                for sub in sorted(set(self.anomalies['suspicious_patterns'])):
                    f.write(f"{sub}\n")
