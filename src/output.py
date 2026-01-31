from rich.console import Console
from rich.table import Table

console = Console()

def display_terminal_table(df):
    """Display CVE prioritization results in a styled Rich table."""
    if df.empty:
        console.print("[bold red]❌ No data to display.[/bold red]")
        return

    table = Table(title="🛡️  FINAL PRIORITIZED RISK REPORT")

    # Define Columns
    table.add_column("Rank", style="dim", justify="right")
    table.add_column("CVE ID", style="cyan", no_wrap=True)
    table.add_column("Real Risk", style="bold white")
    table.add_column("Context", style="white")
    table.add_column("Action", style="italic green")

    rank = 1
    for _, row in df.iterrows():
        # Dynamic Formatting based on Risk Level
        risk_level = row['Real_Risk_level']  # ✅ fixed naming

        # Default Styles
        risk_style = "green"
        action = "Patch next cycle"

        # Logic for colors and actions
        if risk_level == "CRITICAL":
            risk_style = "bold red"
            action = "PATCH IMMEDIATELY (Active Exploit)"
        elif risk_level == "HIGH":
            risk_style = "bold orange3"
            action = "Patch within 7 days"
        elif risk_level == "MEDIUM":
            risk_style = "yellow"
            action = "Monitor / Patch within 30 days"

        # CISA Status Icon (Fire for active exploit)
        cisa_icon = "🔥" if row['in_cisa'] else "  "

        # Truncate vulnerability name safely
        vuln_name = row['vulnerabilityName']
        if len(vuln_name) > 30:
            vuln_name = vuln_name[:30] + "..."

        # Add Row
        table.add_row(
            str(rank),
            f"{cisa_icon} {row['cveID']}",
            f"[{risk_style}]{risk_level}[/{risk_style}]",
            f"EPSS: {row['epss']:.2%} | {vuln_name}",
            action
        )
        rank += 1

    console.print(table)
    console.print("\n[dim]🔥 = Listed in CISA KEV (Known Exploited Vulnerabilities)[/dim]")