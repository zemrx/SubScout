"""
SubScout - Advanced Subdomain Enumeration Tool

A powerful subdomain enumeration tool that combines passive and active reconnaissance
techniques to discover subdomains for security testing and reconnaissance.
"""

__version__ = '1.0.0'
__author__ = 'Hussein Hady'
__license__ = 'MIT'

from .main import SubdomainEnumerator, main

__all__ = ['SubdomainEnumerator', 'main']
