import pandas as pd
import numpy as np

def calculate_priority(row):
    if row['in_cisa']:
        return "CRITICAL"
    if row['epss'] >= 0.2:  
        return "HIGH"
    if row['epss'] >= 0.05:
        return "MEDIUM"
    return "LOW"

def apply_prioritization(df):
    """Apply prioritization logic and sort CVEs by risk level and EPSS score."""
    if df.empty:
        return df

    # Apply risk calculation
    df['Real_Risk_level'] = df.apply(calculate_priority, axis=1)

    # Map risk levels to numeric sort keys
    priority_map = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3
    }
    df['sort_key'] = df['Real_Risk_level'].map(priority_map)

    # Sort by priority first, then by epss descending
    df = df.sort_values(by=['sort_key', 'epss'], ascending=[True, False])

    # Drop sort_key if not needed
    df = df.drop(columns=['sort_key'])

    return df