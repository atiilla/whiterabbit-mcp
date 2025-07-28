#!/usr/bin/env python3
"""
Crt.sh Module
Provides functionality for discovering subdomains from SSL certificate logs using crt.sh.
"""

import asyncio
import json
import re
from typing import List, Dict, Any
import aiohttp

class CrtShResponse:
    """Response model for crt.sh API"""
    def __init__(self, data: Dict[str, Any]):
        self.issuer_ca_id: int = data.get('issuer_ca_id', 0)
        self.issuer_name: str = data.get('issuer_name', '')
        self.common_name: str = data.get('common_name', '')
        self.name_value: str = data.get('name_value', '')
        self.id: int = data.get('id', 0)
        self.entry_timestamp: str = data.get('entry_timestamp', '')
        self.not_before: str = data.get('not_before', '')
        self.not_after: str = data.get('not_after', '')
        self.serial_number: str = data.get('serial_number', '')
        self.result_count: int = data.get('result_count', 0)

async def send_req_crtsh(query: str) -> List[str]:
    """Send request to crt.sh API and get domain list"""
    try:
        url = f"https://crt.sh/?q={query}&output=json"
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if not response.ok:
                    return []
                
                crtsh_response_data = await response.json()
                domains: List[str] = []
                
                for crtsh_resp_data in crtsh_response_data:
                    crtsh_resp = CrtShResponse(crtsh_resp_data)
                    # Parse name_value and add domains to the list
                    name_values = parse_name_value(crtsh_resp.name_value)
                    domains.extend(name_values)
                
                return domains
                
    except Exception as e:
        print(f"Error fetching from crt.sh: {e}")
        return []

def parse_name_value(name_value: str) -> List[str]:
    """Parse name_value field and extract domain names"""
    # Split by \n character
    values = name_value.split("\n")
    
    # Filter out empty values
    result = [v for v in values if v.strip()]
    
    return result

def clear_result(result: List[str], name: str) -> List[str]:
    """Clean and filter results to get unique subdomains"""
    # Escape dots in domain name for regex
    escaped_name = name.replace(".", "\\.")
    
    # Create regex pattern to match subdomains
    pattern = re.compile(f"[^.]+\\.{escaped_name}\\b")
    
    unique = set()
    unique_list = []
    
    for val in result:
        if val not in unique:
            if pattern.search(val):
                unique.add(val)
                unique_list.append(val)
    
    return unique_list

async def get_crtsh(target: str) -> List[str]:
    """Main function to get subdomains from crt.sh"""
    subdomains = await send_req_crtsh(target)
    results = clear_result(subdomains, target)
    return results

async def ExecCrtsh(target: str) -> List[str]:
    """Discovers subdomains from SSL certificate logs
    
    Args:
        target: Target domain to analyze (e.g., example.com).
        
    Returns:
        List of discovered subdomains from SSL certificate logs
    """
    try:
        domains = await get_crtsh(target)
        return domains
    except Exception as e:
        print(f"Error querying crt.sh: {str(e)}")
        return []
