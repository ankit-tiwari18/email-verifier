from flask import Flask, render_template, request, jsonify, send_file
import re
import dns.resolver
import os
import smtplib
import socket
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__)
SAVE_FILE = "valid_emails.txt"

def verify_logic(email):
    email = email.strip()
    if not email: return None
    
    report = {
        "email": email, 
        "status": "Undeliverable", 
        "color": "red", 
        "syntax": "✅", 
        "dns": "❌", 
        "smtp": "❌"
    }

    # 1. Regex Validation (Improved for modern domains)
    if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        report["syntax"] = "❌"
        return report
    
    try:
        # 2. DNS Lookup
        domain = email.split('@')[1]
        records = dns.resolver.resolve(domain, 'MX')
        # Sort MX records by priority (lowest number first)
        mx_records = sorted(records, key=lambda r: r.preference)
        mx_record = str(mx_records[0].exchange)
        report["dns"] = "✅"
        
        # 3. SMTP Handshake with Port Fallback (SOC Optimized)
        try:
            host = socket.getfqdn() 
        except:
            host = "verification-bot.local"

        success = False
        # Try 25 (Standard), then 587 (Submission), then 465 (Legacy SSL)
        for port in [25, 587, 465]:
            try:
                # Use SMTP_SSL for port 465, regular SMTP for others
                if port == 465:
                    server = smtplib.SMTP_SSL(mx_record, port, timeout=7)
                else:
                    server = smtplib.SMTP(mx_record, port, timeout=7)
                
                server.helo(host)
                
                # Upgrade to TLS if using Port 587 (Required by Google/Outlook)
                if port == 587:
                    server.starttls()
                    server.helo(host)

                # Identify as an audit bot
                server.mail('audit-bot@' + host)
                code, message = server.rcpt(str(email))
                server.quit()

                # 250 = Success, 251 = User not local but will forward
                if code in [250, 251]:
                    success = True
                    break
            except:
                continue

        if success:
            report["smtp"] = "✅"
            report["status"] = "Deliverable"
            report["color"] = "green"
            with open(SAVE_FILE, "a") as f:
                f.write(email + "\n")
        else:
            report["status"] = "SMTP Handshake Failed / Inbox Full"
            
    except Exception as e:
        report["status"] = "Domain/MX Not Found"
        
    return report

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/verify-single', methods=['POST'])
def single_verify():
    data = request.json
    return jsonify(verify_logic(data.get('email', '')))

@app.route('/bulk-verify', methods=['POST'])
def bulk_verify():
    if 'file' not in request.files:
        return jsonify({"error": "No file"}), 400
    
    emails = request.files['file'].read().decode('utf-8').splitlines()
    
    # 50 Workers for high-speed SOC processing
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = list(executor.map(verify_logic, emails))
    
    valid_count = sum(1 for r in results if r and r['color'] == 'green')
    return jsonify({"valid": valid_count, "total": len(results), "results": results})

@app.route('/download')
def download():
    if os.path.exists(SAVE_FILE):
        return send_file(SAVE_FILE, as_attachment=True)
    return "No records found", 404

if __name__ == '__main__':
    # Running on 5003 as discussed to avoid conflict with RECON-X
    app.run(host='0.0.0.0', port=5003, debug=True)