import json
from typing import List, Dict, Any
from colorama import Fore, Style, init

init(autoreset=True)

class OutputFormatter:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
    
    def print_banner(self):
        banner = f"""
{Fore.CYAN}========================================================
                    SubScout v1.0
        Advanced Subdomain Reconnaissance Tool
========================================================{Style.RESET_ALL}
"""
        print(banner)
    
    def print_info(self, message: str):
        print(f"{Fore.BLUE}[*]{Style.RESET_ALL} {message}")
    
    def print_success(self, message: str):
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {message}")
    
    def print_error(self, message: str):
        print(f"{Fore.RED}[-]{Style.RESET_ALL} {message}")
    
    def print_warning(self, message: str):
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {message}")
    
    def print_subdomain(self, subdomain: str):
        print(f"{Fore.GREEN}{subdomain}{Style.RESET_ALL}")
    
    def print_verbose(self, message: str):
        if self.verbose:
            print(f"{Fore.CYAN}[V]{Style.RESET_ALL} {message}")
    
    def print_statistics(self, stats: Dict[str, Any]):
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Statistics:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        for key, value in stats.items():
            print(f"  {Fore.YELLOW}{key}:{Style.RESET_ALL} {value}")
        
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    def export_txt(self, subdomains: List[str], filename: str):
        try:
            with open(filename, 'w') as f:
                for subdomain in subdomains:
                    f.write(f"{subdomain}\n")
            self.print_success(f"Exported {len(subdomains)} subdomains to {filename}")
        except Exception as e:
            self.print_error(f"Failed to export to {filename}: {e}")
    
    def export_json(self, data: Dict[str, Any], filename: str):
        try:
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
            self.print_success(f"Exported results to {filename}")
        except Exception as e:
            self.print_error(f"Failed to export to {filename}: {e}")
    
    def export_csv(self, data, filename: str, headers: List[str] = None):
        try:
            import csv
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                if headers:
                    writer.writerow(headers)
                else:
                    writer.writerow(['Subdomain'])
                
                for item in data:
                    if isinstance(item, (list, tuple)):
                        writer.writerow(item)
                    else:
                        writer.writerow([item])
            self.print_success(f"Exported {len(data)} items to {filename}")
        except Exception as e:
            self.print_error(f"Failed to export to {filename}: {e}")
