import requests
import pandas as pd
import os
import time
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_DIR = "data"
CISA_FILE = os.path.join(CACHE_DIR, "cisa_kev.json")

EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
EPSS_FILE = os.path.join(CACHE_DIR, "epss_scores.csv.gz")


def fetch_cisa_kev(force_update=False):
    """Fetch or load cached CISA KEV data."""
    os.makedirs(CACHE_DIR, exist_ok=True)

    if not force_update and os.path.exists(CISA_FILE):
        file_age = time.time() - os.path.getmtime(CISA_FILE)
        if file_age < 86400:  # 24 hours
            logging.info("Loading CISA data from local disk...")
            return load_cisa_data()

    logging.info("Fetching fresh data from CISA.gov...")
    try:
        response = requests.get(CISA_URL, timeout=10)
        response.raise_for_status()

        with open(CISA_FILE, "wb") as f:
            f.write(response.content)
        logging.info("CISA KEV Data cached successfully.")
        return load_cisa_data()

    except Exception as e:
        logging.error(f"Could not fetch CISA data: {e}")
        if os.path.exists(CISA_FILE):
            logging.warning("Falling back to cached CISA data...")
            return load_cisa_data()
        return pd.DataFrame()


def load_cisa_data():
    """Load cached CISA KEV JSON into a DataFrame."""
    try:
        data = pd.read_json(CISA_FILE)
        if "vulnerabilities" in data:
            return pd.json_normalize(data["vulnerabilities"])
        logging.error("CISA JSON missing 'vulnerabilities' key.")
        return pd.DataFrame()
    except Exception as e:
        logging.error(f"Failed to parse CISA JSON: {e}")
        return pd.DataFrame()


def fetch_epss_data(force_update=False):
    """Fetch or load cached EPSS scores."""
    os.makedirs(CACHE_DIR, exist_ok=True)

    if not force_update and os.path.exists(EPSS_FILE):
        file_age = time.time() - os.path.getmtime(EPSS_FILE)
        if file_age < 86400:  # 24 hours
            logging.info("Loading EPSS data from local disk...")
            return load_epss_data()

    logging.info("Fetching daily EPSS scores...")
    try:
        response = requests.get(EPSS_URL, stream=True, timeout=30)
        response.raise_for_status()

        with open(EPSS_FILE, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

        logging.info("EPSS data cached successfully.")
        return load_epss_data()
    except Exception as e:
        logging.error(f"Failed to download EPSS: {e}")
        return pd.DataFrame()


def load_epss_data():
    try:
        df = pd.read_csv(EPSS_FILE, compression='gzip', comment='#')
        df.columns = df.columns.str.lower()  # ✅ Add this line
        return df
    except Exception as e:
        print(f"[ERROR] Corrupt EPSS file: {e}")
        return pd.DataFrame()

def fetch_nvd_metadata(cve_list, api_key=None):
    """Placeholder for NVD metadata fetch."""
    return {}