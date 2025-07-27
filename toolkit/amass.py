# INFORMATION:
# - Tool: Amass
# - Description: Advanced subdomain enumeration and reconnaissance tool
# - Usage: Performs subdomain discovery and mapping of target domains
# - Parameters: domain (required), subcommand (required), intel_whois (optional), intel_organization (optional),
#               enum_type (optional), enum_brute (optional), enum_brute_wordlist (optional)

import asyncio
import re
import subprocess
import logging
from typing import Any, Dict, List, Optional
import json
import uuid
from enum import Enum

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("amass-tool")

class AmassSubcommand(str, Enum):
    """Amass operation modes"""
    enum = "enum"
    intel = "intel"

class AmassEnumType(str, Enum):
    """Enumeration approach types"""
    active = "active"
    passive = "passive"

class Amass:
    """
    Amass wrapper class for subdomain enumeration and reconnaissance.
    """

    def __init__(self):
        """Initialize Amass wrapper."""
        self._check_installed()

    def _check_installed(self) -> None:
        """Verify Amass is installed."""
        try:
            subprocess.run(["amass", "-version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            logger.info("Amass installation verified.")
        except (subprocess.SubprocessError, FileNotFoundError):
            logger.warning("Amass not found or not correctly installed. Make sure it's in your PATH.")

    async def scan(
        self,
        subcommand: str,
        domain: Optional[str] = None,
        intel_whois: Optional[bool] = None,
        intel_organization: Optional[str] = None,
        enum_type: Optional[str] = None,
        enum_brute: Optional[bool] = None,
        enum_brute_wordlist: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Run Amass with the specified parameters.
        
        Args:
            subcommand: Operation mode (enum or intel)
            domain: Target domain for reconnaissance
            intel_whois: Whether to include WHOIS data in intelligence gathering
            intel_organization: Organization name to search for
            enum_type: Enumeration approach (active or passive)
            enum_brute: Whether to perform brute force subdomain discovery
            enum_brute_wordlist: Path to custom wordlist for brute force operations
            
        Returns:
            Dictionary containing scan results and metadata
        """
        # Initialize command arguments
        amass_args = [subcommand]
        
        # Handle different subcommands
        if subcommand == AmassSubcommand.enum.value:
            if not domain:
                return {"success": False, "error": "Domain parameter is required for 'enum' subcommand"}
            
            amass_args.extend(["-d", domain])
            
            # Handle enum type
            if enum_type == AmassEnumType.passive.value:
                amass_args.append("-passive")
            # Active is default for enum, no flag needed
            
            # Handle brute force options
            if enum_brute:
                amass_args.append("-brute")
                
                # Add custom wordlist if provided
                if enum_brute_wordlist:
                    amass_args.extend(["-w", enum_brute_wordlist])
                    
        elif subcommand == AmassSubcommand.intel.value:
            if not domain and not intel_organization:
                return {"success": False, "error": "Either domain or organization parameter is required for 'intel' subcommand"}
            
            # Add domain if provided
            if domain:
                amass_args.extend(["-d", domain])
            
            # Add organization if provided
            if intel_organization:
                amass_args.extend(["-org", intel_organization])
            
            # Add whois option if enabled
            if intel_whois:
                amass_args.append("-whois")
        else:
            return {"success": False, "error": f"Invalid subcommand: {subcommand}. Use 'enum' or 'intel'."}
        
        logger.info(f"Running amass command: amass {' '.join(amass_args)}")
        
        try:
            # Execute amass command
            process = await asyncio.create_subprocess_exec(
                "amass",
                *amass_args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Wait for completion and get output
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                results = stdout.decode().strip()
                # Process the output
                subdomains = [line for line in results.split('\n') if line.strip()]
                
                return {
                    "success": True,
                    "command": f"amass {' '.join(amass_args)}",
                    "results": subdomains,
                    "count": len(subdomains),
                    "domain": domain
                }
            else:
                error_message = stderr.decode().strip() or stdout.decode().strip()
                return {
                    "success": False, 
                    "error": f"Amass exited with code {process.returncode}: {error_message}",
                    "command": f"amass {' '.join(amass_args)}"
                }
                
        except Exception as e:
            logger.error(f"Error executing Amass: {str(e)}")
            return {"success": False, "error": f"Failed to execute Amass: {str(e)}"}


async def ExecAmass(
    subcommand: str,
    domain: Optional[str] = None,
    intel_whois: Optional[bool] = None,
    intel_organization: Optional[str] = None,
    enum_type: Optional[str] = None,
    enum_brute: Optional[bool] = None,
    enum_brute_wordlist: Optional[str] = None
) -> Dict[str, Any]:
    """
    Execute Amass scan with the specified parameters.
    
    Args:
        subcommand: Operation mode (enum or intel)
        domain: Target domain for reconnaissance
        intel_whois: Whether to include WHOIS data in intelligence gathering
        intel_organization: Organization name to search for
        enum_type: Enumeration approach (active or passive)
        enum_brute: Whether to perform brute force subdomain discovery
        enum_brute_wordlist: Path to custom wordlist for brute force operations
        
    Returns:
        Dictionary containing scan results and metadata
    """
    amass = Amass()
    return await amass.scan(
        subcommand=subcommand,
        domain=domain,
        intel_whois=intel_whois,
        intel_organization=intel_organization,
        enum_type=enum_type,
        enum_brute=enum_brute,
        enum_brute_wordlist=enum_brute_wordlist
    )

