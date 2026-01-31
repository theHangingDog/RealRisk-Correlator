"""
Real-Risk CVE Correlator
------------------------
A Risk-Based Vulnerability Management (RBVM) engine that prioritizes 
software vulnerabilities using Threat Intelligence.

Author: Arkaprava Goswami
License: MIT
"""

__version__ = "1.0.0"
__author__ = "Arkaprava Goswami"

# This allows you to import directly from src if you ever want to change main.py
# Example: from src import fetch_cisa_kev
from .collectors import fetch_cisa_kev, fetch_epss_data, fetch_nvd_metadata
from .processor import parse_input_file, enrich_data
from .risk_logic import calculate_priority, apply_prioritization
from .output import display_terminal_table