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

    # 1. Regex Validation
    if not re.match(r'^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$', email):
        report["syntax"] = "❌"
        return report
    
    try:
        # 2. DNS Lookup
        domain = email.split('@')[1]
        records = dns.resolver.resolve(domain, 'MX')
        mx_record = str(records[0].exchange)
        report["dns"] = "✅"
        
        # 3. SMTP Handshake (Universal Production Logic)
        # We dynamically get the server's hostname to appear legitimate
        try:
            host = socket.getfqdn() 
        except:
            host = "verification-bot.local"

        success = False
        # Professional servers try 25 first, then 587
        for port in [25, 587]:
            try:
                server = smtplib.SMTP(timeout=7)
                server.connect(mx_record, port)
                server.helo(host)
                
                # Required for Microsoft/Google on Port 587
                if port == 587:
                    server.starttls()
                    server.helo(host)

                # Using a generic 'from' address that matches your bot's purpose
                server.mail('audit-bot@' + host)
                code, message = server.rcpt(str(email))
                server.quit()

                if code == 250:
                    success = True
                    break
            except:
                continue

        if success:
            report["smtp"] = "✅"
            report["status"] = "Deliverable"
            report["color"] = "green"
            # Append to file for your records
            with open(SAVE_FILE, "a") as f:
                f.write(email + "\n")
        else:
            report["status"] = "Server Unreachable / No Mailbox"
            
    except Exception as e:
        report["status"] = "Domain Not Found"
        
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
    
    # 50 Workers to handle 'Everyone' using the site at once
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = list(executor.map(verify_logic, emails))
    
    valid_count = sum(1 for r in results if r and r['color'] == 'green')
    return jsonify({"valid": valid_count, "total": len(results)})

@app.route('/download')
def download():
    if os.path.exists(SAVE_FILE):
        return send_file(SAVE_FILE, as_attachment=True)
    return "No records found", 404

if __name__ == '__main__':
    # Use 0.0.0.0 to allow public internet access
    app.run(host='0.0.0.0', port=5000)