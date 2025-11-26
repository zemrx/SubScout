#!/usr/bin/env python3

import argparse
import asyncio
import sys
from pathlib import Path
from typing import List, Set
from .config import get_config
from .utils.output import OutputFormatter
from .utils.dedup import deduplicate, filter_valid_subdomains
from .utils.http_client import HTTPClient
from .utils.anomaly import AnomalyDetector
from .passive.crtsh import CrtSh
from .passive.virustotal import VirusTotal
from .passive.alienvault import AlienVault
from .passive.anubis import AnubisDB
from .passive.hackertarget import HackerTarget
from .passive.threatcrowd import ThreatCrowd
from .passive.certspotter import CertSpotter
from .passive.securitytrails import SecurityTrails
from .passive.shodan import Shodan
from .passive.dnsdumpster import DNSdumpster
from .passive.bufferover import BufferOver, RapidDNS
from .passive.urlscan import URLScan
from .passive.chaos import Chaos
from .passive.fullhunt import FullHunt
from .passive.binaryedge import BinaryEdge
from .passive.netlas import Netlas
from .active.bruteforce import BruteForcer
from .active.resolver import DNSResolver

class SubdomainEnumerator:
    def __init__(self, domain: str, mode: str, wordlist: str = None,
                 output_file: str = None, output_format: str = 'txt',
                 verbose: bool = False, sources: List[str] = None,
                 filter_anomalies: bool = False, anomalies_file: str = None,
                 resolve: bool = False):
        self.domain = domain
        self.mode = mode.lower()
        self.wordlist = wordlist
        self.output_file = output_file
        self.output_format = output_format
        self.output = OutputFormatter(verbose)
        self.filter_anomalies = filter_anomalies
        self.anomalies_file = anomalies_file or f"{domain}_anomalies.json"
        self.resolve = resolve
        self.all_subdomains: Set[str] = set()
        self.resolved_subdomains: dict = {}  
        self.stats = {
            'Passive Sources Used': 0,
            'Active Enumeration': 'No',
            'Total Subdomains': 0,
            'Anomalies Filtered': 0,
            'Resolved': 0,
            'Unresolved': 0
        }
        
        self.passive_sources = [
            CrtSh(), VirusTotal(), AlienVault(), AnubisDB(),
            HackerTarget(), ThreatCrowd(), CertSpotter(),
            SecurityTrails(), Shodan(), DNSdumpster(),
            BufferOver(), RapidDNS(), URLScan(), Chaos(),
            FullHunt(), BinaryEdge(), Netlas()
        ]
        
        if sources:
            source_names = [s.lower() for s in sources]
            self.passive_sources = [
                src for src in self.passive_sources
                if src.name.lower() in source_names
            ]
    
    async def run_passive(self):
        self.output.print_info(f"Starting passive enumeration for {self.domain}")
        
        async with HTTPClient() as http_client:
            tasks = []
            for source in self.passive_sources:
                if not source.is_available():
                    if source.requires_api_key:
                        self.output.print_warning(f"Skipping {source.name} - API key not configured")
                    continue
                
                self.output.print_verbose(f"Querying {source.name}...")
                tasks.append(self._query_source(source, http_client))
                self.stats['Passive Sources Used'] += 1
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    source_name = self.passive_sources[i].name
                    self.output.print_verbose(f"Error from {source_name}: {result}")
                elif result:
                    self.all_subdomains.update(result)
    
    async def _query_source(self, source, http_client):
        try:
            subdomains = await source.enumerate(self.domain, http_client)
            if subdomains:
                self.output.print_success(f"{source.name}: Found {len(subdomains)} subdomains")
            return subdomains
        except Exception as e:
            self.output.print_verbose(f"Error querying {source.name}: {e}")
            return []
    
    async def run_active(self):
        if not self.wordlist:
            self.output.print_error("Wordlist required for active enumeration")
            return
        
        wordlist_path = Path(self.wordlist)
        if not wordlist_path.exists():
            self.output.print_error(f"Wordlist not found: {self.wordlist}")
            return
        
        self.output.print_info(f"Starting active enumeration for {self.domain}")
        self.output.print_info(f"Wordlist: {self.wordlist}")
        self.output.print_info("Detecting wildcard DNS...")
        
        try:
            bruteforcer = BruteForcer(self.domain, self.wordlist)
            
            def progress_callback(processed, total, found):
                if found:
                    self.output.print_subdomain(found)
                if processed % 100 == 0 or processed == total:
                    self.output.print_verbose(f"Progress: {processed}/{total} ({processed*100//total}%)")
            
            subdomains = await bruteforcer.enumerate(progress_callback)
            self.all_subdomains.update(subdomains)
            self.stats['Active Enumeration'] = 'Yes'
            self.output.print_success(f"Active enumeration found {len(subdomains)} subdomains")
        except Exception as e:
            self.output.print_error(f"Active enumeration failed: {e}")
    
    async def run(self):
        self.output.print_banner()
        self.output.print_info(f"Target: {self.domain}")
        self.output.print_info(f"Mode: {self.mode}")
        
        if self.mode in ['passive', 'both']:
            await self.run_passive()
        
        if self.mode in ['active', 'both']:
            await self.run_active()
        
        subdomains_list = list(self.all_subdomains)
        subdomains_list = filter_valid_subdomains(subdomains_list, self.domain)
        subdomains_list = deduplicate(subdomains_list)
        
        if self.filter_anomalies:
            await self._filter_anomalies(subdomains_list)
        
        if self.resolve:
            await self._resolve_subdomains(subdomains_list)
        
        self.stats['Total Subdomains'] = len(subdomains_list)
        
        self.output.print_success(f"\nFound {len(subdomains_list)} unique subdomains:")
        print()
        for subdomain in subdomains_list:
            if self.resolve and subdomain in self.resolved_subdomains:
                ips = ', '.join(self.resolved_subdomains[subdomain])
                self.output.print_subdomain(f"{subdomain} [{ips}]")
            else:
                self.output.print_subdomain(subdomain)
        
        self.output.print_statistics(self.stats)
        
        if self.output_file:
            self._export_results(subdomains_list)
    
    async def _filter_anomalies(self, subdomains_list):
        self.output.print_info("Filtering anomalies (redirects and duplicates)...")
        
        async with HTTPClient() as http_client:
            detector = AnomalyDetector(self.domain, verbose=self.output.verbose)
            clean_subs, anomalies = await detector.analyze_subdomains(subdomains_list[:100], http_client)
            
            self.stats['Anomalies Filtered'] = len(subdomains_list) - len(clean_subs)
            
            if anomalies:
                detector.save_anomalies(self.anomalies_file)
                self.output.print_success(f"Anomalies saved to {self.anomalies_file}")
    
    async def _resolve_subdomains(self, subdomains_list: List[str]):
        self.output.print_info(f"Resolving {len(subdomains_list)} subdomains...")
        
        resolver = DNSResolver()
        resolved_count = 0
        unresolved_count = 0
        
        for i, subdomain in enumerate(subdomains_list, 1):
            if i % 10 == 0:
                self.output.print_verbose(f"Progress: {i}/{len(subdomains_list)}")
            
            ips = await resolver.resolve(subdomain, 'A')
            if ips:
                self.resolved_subdomains[subdomain] = ips
                resolved_count += 1
            else:
                unresolved_count += 1
            
            if i % 50 == 0:
                await asyncio.sleep(0.1)
        
        self.stats['Resolved'] = resolved_count
        self.stats['Unresolved'] = unresolved_count
        self.output.print_success(f"Resolved {resolved_count}/{len(subdomains_list)} subdomains")
    
    def _export_results(self, subdomains: List[str]):
        if self.output_format == 'json':
            if self.resolve:
                subdomains_with_ips = [
                    {
                        'subdomain': sub,
                        'ips': self.resolved_subdomains.get(sub, [])
                    }
                    for sub in subdomains
                ]
                data = {
                    'domain': self.domain,
                    'mode': self.mode,
                    'subdomains': subdomains_with_ips,
                    'statistics': self.stats
                }
            else:
                data = {
                    'domain': self.domain,
                    'mode': self.mode,
                    'subdomains': subdomains,
                    'statistics': self.stats
                }
            self.output.export_json(data, self.output_file)
        elif self.output_format == 'csv':
            if self.resolve:
                data_with_ips = [(sub, ','.join(self.resolved_subdomains.get(sub, []))) for sub in subdomains]
                self.output.export_csv(data_with_ips, self.output_file, headers=['Subdomain', 'IPs'])
            else:
                self.output.export_csv(subdomains, self.output_file)
        else:
            if self.resolve:
                lines = []
                for sub in subdomains:
                    if sub in self.resolved_subdomains:
                        ips = ', '.join(self.resolved_subdomains[sub])
                        lines.append(f"{sub} [{ips}]")
                    else:
                        lines.append(sub)
                self.output.export_txt(lines, self.output_file)
            else:
                self.output.export_txt(subdomains, self.output_file)
        
        self.output.print_success(f"Results exported to {self.output_file}")

def main():
    parser = argparse.ArgumentParser(
        description='SubScout - Advanced Subdomain Enumeration Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('domain', help='Target domain')
    parser.add_argument('-m', '--mode', choices=['passive', 'active', 'both'],
                       default='passive', help='Enumeration mode (default: passive)')
    parser.add_argument('-w', '--wordlist', help='Wordlist for active enumeration')
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('--format', choices=['txt', 'json', 'csv'],
                       default='txt', help='Output format (default: txt)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('--sources', help='Comma-separated list of sources to use')
    parser.add_argument('--config', default='config.yaml',
                       help='Config file path (default: config.yaml)')
    parser.add_argument('--filter-anomalies', action='store_true',
                       help='Filter anomalous subdomains (redirects, duplicates)')
    parser.add_argument('--resolve', action='store_true',
                       help='Resolve subdomains to IP addresses via DNS')
    parser.add_argument('--anomalies-file', help='File to save anomalies')
    
    args = parser.parse_args()
    
    if args.mode in ['active', 'both'] and not args.wordlist:
        default_wordlist = Path('wordlists/default.txt')
        if default_wordlist.exists():
            args.wordlist = str(default_wordlist)
        else:
            parser.error("Active mode requires --wordlist argument")
    
    sources = None
    if args.sources:
        sources = [s.strip() for s in args.sources.split(',')]
    
    enumerator = SubdomainEnumerator(
        domain=args.domain,
        mode=args.mode,
        wordlist=args.wordlist,
        output_file=args.output,
        output_format=args.format,
        verbose=args.verbose,
        sources=sources,
        filter_anomalies=args.filter_anomalies,
        anomalies_file=args.anomalies_file,
        resolve=args.resolve
    )
    
    try:
        asyncio.run(enumerator.run())
    except KeyboardInterrupt:
        print("\n\nEnumeration interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
