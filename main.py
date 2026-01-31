import argparse
import os
import sys
from rich.console import Console
from src.collectors import fetch_cisa_kev, fetch_epss_data
from src.processor import parse_input_file, enrich_data
from src.risk_logic import apply_prioritization 
from src.output import display_terminal_table

console = Console()

def setup_argparser():
    """Defines the command-line arguments for the tool."""
    parser = argparse.ArgumentParser(
        description="Real-Risk CVE Correlator: Prioritize vulnerabilities using Threat Intel.",
        usage="python main.py [-i FILE] [--demo]"
    )
    
    parser.add_argument(
        "-i", "--input", 
        dest="filename",
        help="Path to the vulnerability scan file (CSV, TXT, JSON, etc.)",
        type=str
    )
    
    parser.add_argument(
        "--demo", 
        action="store_true",
        help="Generate a dummy file to test the tool immediately."
    )
    
    return parser

def create_demo_file():
    """Helper to create a dummy scan file for testing."""
    dummy_file = "demo_scan.csv"
    content = """CVE-2021-44228,Log4Shell,Critical
CVE-2023-23397,Outlook,Critical
CVE-2017-0144,EternalBlue,Critical
CVE-2020-0601,CurveBall,High
CVE-1999-0001,OldBug,Low"""
    with open(dummy_file, "w") as f:
        f.write(content)
    return dummy_file

def main():
    # 1. Parse Arguments
    parser = setup_argparser()
    args = parser.parse_args()

    console.print("\n[bold blue]🚀 Starting Real-Risk CVE Correlator...[/bold blue]")

    # Logic: Handle Input File Selection
    input_file = args.filename

    if args.demo:
        console.print("[yellow]🧪 Demo Mode: Generating 'demo_scan.csv'...[/yellow]")
        input_file = create_demo_file()
    
    # If no input provided and not in demo mode, warn user
    if not input_file:
        console.print("[bold red]❌ Error: No input file provided.[/bold red]")
        console.print("Usage: python main.py -i <filename> OR python main.py --demo")
        sys.exit(1)

    # Validate File Exists
    if not os.path.exists(input_file):
        console.print(f"[bold red]❌ Error: File '{input_file}' not found.[/bold red]")
        sys.exit(1)

    # --- Fetch Intelligence ---
    with console.status("[bold green]Fetching Intelligence Feeds (CISA & EPSS)..."):
        cisa_df = fetch_cisa_kev()
        epss_df = fetch_epss_data()

    # --- Read User Input ---
    console.print(f"[yellow]📂 Reading input file: {input_file}...[/yellow]")
    user_cves = parse_input_file(input_file)
    
    if not user_cves:
        console.print("[bold red]❌ No valid CVEs found in input file. Exiting.[/bold red]")
        sys.exit(1)
        
    console.print(f"   Found {len(user_cves)} unique CVEs.")

    # --- Data Enrichment ---
    console.print("[yellow]🧠 Correlating data...[/yellow]")
    enriched_df = enrich_data(user_cves, cisa_df, epss_df)

    # --- STEP 4: Apply Risk Logic ---
    console.print("[yellow]⚖️  Calculating Real-Risk Scores...[/yellow]")
    final_df = apply_prioritization(enriched_df)

    # --- Output Results ---
    display_terminal_table(final_df)

if __name__ == "__main__":
    main()