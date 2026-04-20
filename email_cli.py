import smtplib
import dns.resolver
import re
import argparse
from rich.console import Console
from rich.table import Table
from rich.progress import track

console = Console()

def verify_email(email):
    # 1. Syntax Check (Regex)
    regex = r'^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$'
    if not re.match(regex, email, re.I):
        return "Invalid Syntax"

    domain = email.split('@')[1]

    # 2. DNS MX Record Check
    try:
        records = dns.resolver.resolve(domain, 'MX')
        mx_record = str(records[0].exchange)
    except Exception:
        return "No MX Record (Domain Invalid)"

    # 3. SMTP Handshake
    try:
        # Connect to the mail server
        server = smtplib.SMTP(timeout=10)
        server.set_debuglevel(0)
        server.connect(mx_record)
        server.helo(server.local_hostname)
        server.mail('test@example.com')
        code, message = server.rcpt(email)
        server.quit()

        if code == 250:
            return "Valid"
        else:
            return f"Invalid ({code})"
    except Exception as e:
        return f"SMTP Error: {str(e)[:20]}"

def main():
    parser = argparse.ArgumentParser(description="Professional Email Verifier CLI")
    parser.add_argument("-e", "--email", help="Single email to verify")
    parser.add_argument("-f", "--file", help="File containing list of emails")
    args = parser.parse_args()

    table = Table(title="Email Verification Report")
    table.add_column("Email", style="cyan")
    table.add_column("Status", style="bold green")

    if args.email:
        status = verify_email(args.email)
        table.add_row(args.email, status)
        console.print(table)
    
    elif args.file:
        with open(args.file, 'r') as f:
            emails = [line.strip() for line in f if line.strip()]
        
        for email in track(emails, description="Verifying..."):
            status = verify_email(email)
            table.add_row(email, status)
        
        console.print(table)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()