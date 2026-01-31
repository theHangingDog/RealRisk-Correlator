import pandas as pd
import re
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def parse_input_file(filepath):
    """Extract CVE IDs from a text or CSV file using regex."""
    if not os.path.exists(filepath):
        logging.error(f"File not found: {filepath}")
        return []

    cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
    found_cves = set()

    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            matches = cve_pattern.findall(content)
            found_cves.update(matches)
        return [cve.upper() for cve in found_cves]
    except Exception as e:
        logging.error(f"Could not parse file {filepath}: {e}")
        return []

def enrich_data(cve_list, cisa_df, epss_df):
    """Merge CVE list with CISA KEV and EPSS data."""
    if not cve_list:
        logging.warning("Empty CVE list provided for enrichment.")
        return pd.DataFrame()

    input_df = pd.DataFrame(cve_list, columns=['cveID'])

    # Merge with CISA KEV
    try:
        merged = input_df.merge(
            cisa_df[['cveID', 'dateAdded', 'vulnerabilityName']],
            on='cveID',
            how='left'
        )
        merged['in_cisa'] = merged['dateAdded'].notna()
    except Exception as e:
        logging.error(f"Error merging with CISA data: {e}")
        return pd.DataFrame()

    # Merge with EPSS
    try:
        merged = merged.merge(
            epss_df[['cve', 'epss', 'percentile']],
            left_on='cveID',
            right_on='cve',
            how='left'
        ).drop(columns=['cve'])

        merged['epss'] = merged['epss'].fillna(0.0)
        merged['percentile'] = merged['percentile'].fillna(0.0)
    except Exception as e:
        logging.error(f"Error merging with EPSS data: {e}")
        return pd.DataFrame()

    # Fill missing vulnerability names
    merged['vulnerabilityName'] = merged['vulnerabilityName'].fillna("Unknown / Not in CISA")

    return merged