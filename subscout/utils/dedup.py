from typing import List, Set, Tuple

def normalize_subdomain(subdomain: str) -> str:
    return subdomain.lower().strip().rstrip('.')

def extract_wildcard_base(subdomain: str) -> Tuple[str, bool]:

    normalized = normalize_subdomain(subdomain)
    if normalized.startswith('*.'):
        return (normalized[2:], True) 
    return (normalized, False)

def deduplicate(subdomains: List[str]) -> List[str]:
    seen: Set[str] = set()
    unique: List[str] = []
    
    for subdomain in subdomains:
        base_domain, is_wildcard = extract_wildcard_base(subdomain)
        
        if base_domain and base_domain not in seen:
            seen.add(base_domain)
            unique.append(base_domain)
    
    return sorted(unique)

def filter_valid_subdomains(subdomains: List[str], domain: str) -> List[str]:
    domain = normalize_subdomain(domain)
    valid = []
    
    for subdomain in subdomains:
        base_domain, is_wildcard = extract_wildcard_base(subdomain)
        
        if base_domain.endswith('.' + domain) or base_domain == domain:
            valid.append(base_domain)
    
    return valid
