# Automated DNS Containment Playbook — Critical Severity Incidents

**Tujuan:** Isolasi otomatis IP VM dan subdomain yang terindikasi serangan kritis (malware, backdoor, abuse report) dalam hitungan detik menggunakan DNS manipulation (Cloudflare API atau BIND RPZ), terintegrasi ke SOAR incident response.

**Use case:**
- Malware atau C2 backdoor terdeteksi di IP/VM tertentu → DNS record langsung point ke sinkhole IP
- Subdomain tertular → immediate DNS takeover tanpa perlu shutdown VM (VM tetap berjalan untuk forensik)
- IP dilaporkan abuse/compromised → block di WAF + redirect traffic

---

## Arsitektur Pendekatan

```
[Alert dari EDR/SIEM - Severity P1] 
    ↓
[SOAR Playbook: Verify Severity & Ownership]
    ↓
[IF CONFIRMED: Trigger Containment Action]
    ├─→ [Cloudflare API] → DNS redirect / WAF block / Page rule
    ├─→ [BIND DNS]      → RPZ rule inject / Zone file update
    ├─→ [Ticketing]     → Log action timestamp & approval
    └─→ [Notify IC & CISO] → Real-time Slack alert
    ↓
[FORENSIC PHASE: IP/Subdomain stay powered but isolated]
```

---

## 1. Cloudflare Automated Containment (Recommended)

### Prerequisites
- Cloudflare account dengan API token (minimal Zone.Edit + Cache Purge permissions)
- Domain terkelola di Cloudflare
- Python 3.8+, requests library

### 1a. Cloudflare API Token Setup

**Di Cloudflare dashboard:**
1. User Profile → API Tokens → Create Token
2. Template: "Edit Zone DNS" (atau custom)
3. Permissions: 
   - `zone:edit` (DNS record manipulation)
   - `cache:purge` (instant cache clear)
   - `firewall:read` (read WAF rules)
   - `account:read` (read account info)
4. Zone Resources: Select domain kamu
5. Generate token, copy dan save ke **secure vault** (jangan hardcode di script)

**Environment variable / Secrets Manager:**
```bash
export CLOUDFLARE_API_TOKEN="your_token_here"
export CLOUDFLARE_ZONE_ID="your_zone_id_here"  # Lihat di Zone dashboard
export CLOUDFLARE_ACCOUNT_ID="your_account_id_here"
```

### 1b. Python Script — Automated DNS Containment

```python
#!/usr/bin/env python3
"""
Cloudflare Automated DNS Containment for Critical Severity Incidents
Author: Security Operations Team
Usage: python3 cf_containment.py --action <action> --target <subdomain|ip> --reason <ticket_id>
"""

import os
import sys
import json
import requests
import logging
import argparse
from datetime import datetime
from typing import Dict, List, Optional, Tuple

# === Configuration ===
CLOUDFLARE_API_TOKEN = os.getenv("CLOUDFLARE_API_TOKEN")
CLOUDFLARE_ZONE_ID = os.getenv("CLOUDFLARE_ZONE_ID")
SINKHOLE_IP = os.getenv("SINKHOLE_IP", "192.0.2.1")  # RFC 5737 test IP, ganti dengan IP sinkhole real
CF_API_BASE = "https://api.cloudflare.com/client/v4"
INCIDENT_LOG_FILE = "/var/log/cf_containment_incidents.log"
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK_URL")  # Optional: Slack notification

# === Logging Setup ===
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(INCIDENT_LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# === Cloudflare API Helper ===
class CloudflareAPI:
    def __init__(self, token: str, zone_id: str):
        self.token = token
        self.zone_id = zone_id
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

    def get_dns_record(self, name: str) -> Optional[Dict]:
        """Fetch existing DNS record by name."""
        url = f"{CF_API_BASE}/zones/{self.zone_id}/dns_records"
        params = {"name": name, "type": "A"}
        try:
            resp = requests.get(url, headers=self.headers, params=params, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            if data.get("result"):
                return data["result"][0]
            return None
        except Exception as e:
            logger.error(f"Failed to fetch DNS record {name}: {e}")
            return None

    def update_dns_record(self, record_id: str, name: str, ip: str, ttl: int = 60) -> bool:
        """Update existing A record to new IP (sinkhole)."""
        url = f"{CF_API_BASE}/zones/{self.zone_id}/dns_records/{record_id}"
        payload = {
            "type": "A",
            "name": name,
            "content": ip,
            "ttl": ttl,  # 60 seconds = quick failover
            "proxied": False  # Disable Cloudflare proxy to ensure direct sinkhole routing
        }
        try:
            resp = requests.put(url, headers=self.headers, json=payload, timeout=10)
            resp.raise_for_status()
            logger.info(f"DNS record updated: {name} → {ip} (TTL: {ttl}s)")
            return True
        except Exception as e:
            logger.error(f"Failed to update DNS record {name}: {e}")
            return False

    def create_waf_rule(self, rule_name: str, ip_list: List[str], action: str = "block") -> Optional[str]:
        """
        Create WAF IP restriction rule. 
        action: "block", "challenge", "log"
        """
        url = f"{CF_API_BASE}/zones/{self.zone_id}/firewall/rules"
        
        # Build IP expression
        ip_expr = " or ".join([f"ip.src == {ip}" for ip in ip_list])
        
        payload = {
            "name": rule_name,
            "description": f"Automated containment for critical incident - {datetime.now().isoformat()}",
            "filter": {
                "expression": ip_expr
            },
            "action": action
        }
        try:
            resp = requests.post(url, headers=self.headers, json=payload, timeout=10)
            resp.raise_for_status()
            rule_id = resp.json().get("result", {}).get("id")
            logger.info(f"WAF rule created: {rule_name} ({rule_id}) - IPs: {ip_list}")
            return rule_id
        except Exception as e:
            logger.error(f"Failed to create WAF rule: {e}")
            return None

    def create_page_rule(self, url_pattern: str, action: str = "disable_security") -> Optional[str]:
        """
        Create page rule for subdomain (redirect or block).
        action: "disable_security", "cache_bypass", "disable_performance"
        """
        url = f"{CF_API_BASE}/zones/{self.zone_id}/page_rules"
        payload = {
            "targets": [{"target": "url", "constraint": {"operator": "matches", "value": url_pattern}}],
            "actions": [
                {"id": action, "value": "on"},
                {"id": "security_level", "value": "under_attack"}
            ],
            "priority": 1,
            "status": "active"
        }
        try:
            resp = requests.post(url, headers=self.headers, json=payload, timeout=10)
            resp.raise_for_status()
            rule_id = resp.json().get("result", {}).get("id")
            logger.info(f"Page rule created: {url_pattern} ({rule_id})")
            return rule_id
        except Exception as e:
            logger.error(f"Failed to create page rule: {e}")
            return None

    def purge_cache_by_url(self, urls: List[str]) -> bool:
        """Instantly purge cache untuk memaksa reload DNS/rules."""
        url = f"{CF_API_BASE}/zones/{self.zone_id}/purge_cache"
        payload = {"files": urls}
        try:
            resp = requests.post(url, headers=self.headers, json=payload, timeout=10)
            resp.raise_for_status()
            logger.info(f"Cache purged for {len(urls)} URLs")
            return True
        except Exception as e:
            logger.error(f"Failed to purge cache: {e}")
            return False

# === Slack Notification ===
def notify_slack(message: str, color: str = "danger") -> bool:
    """Send incident alert to Slack."""
    if not SLACK_WEBHOOK:
        return False
    payload = {
        "attachments": [{
            "color": color,
            "title": "🚨 Automated DNS Containment Action",
            "text": message,
            "ts": int(datetime.now().timestamp())
        }]
    }
    try:
        resp = requests.post(SLACK_WEBHOOK, json=payload, timeout=10)
        resp.raise_for_status()
        return True
    except Exception as e:
        logger.error(f"Failed to send Slack notification: {e}")
        return False

# === Containment Actions ===
def isolate_subdomain_to_sinkhole(subdomain: str, reason: str, ticket_id: str) -> Tuple[bool, str]:
    """
    Titik kontrol utama: Redirect subdomain terinfeksi ke sinkhole IP.
    Subdomain otomatis unreachable, VM tetap hidup untuk forensik.
    """
    logger.info(f"[CONTAINMENT] Isolating subdomain: {subdomain} (Reason: {reason}, Ticket: {ticket_id})")
    
    cf = CloudflareAPI(CLOUDFLARE_API_TOKEN, CLOUDFLARE_ZONE_ID)
    
    # Cek apakah DNS record exists
    record = cf.get_dns_record(subdomain)
    if not record:
        msg = f"DNS record not found: {subdomain}"
        logger.error(msg)
        return False, msg
    
    original_ip = record.get("content")
    record_id = record.get("id")
    
    # Log untuk audit trail
    action_log = {
        "timestamp": datetime.now().isoformat(),
        "action": "isolate_subdomain",
        "subdomain": subdomain,
        "original_ip": original_ip,
        "sinkhole_ip": SINKHOLE_IP,
        "reason": reason,
        "ticket_id": ticket_id
    }
    logger.info(json.dumps(action_log))
    
    # Update DNS ke sinkhole IP dengan TTL pendek (60 detik)
    success = cf.update_dns_record(record_id, subdomain, SINKHOLE_IP, ttl=60)
    
    if success:
        # Purge cache untuk instant effect
        cf.purge_cache_by_url([f"http://{subdomain}/*", f"https://{subdomain}/*"])
        
        # Notify
        msg = (f"Subdomain {subdomain} isolated to sinkhole {SINKHOLE_IP}\n"
               f"Original IP: {original_ip}\n"
               f"Reason: {reason}\n"
               f"Ticket: {ticket_id}")
        notify_slack(msg, color="danger")
        
        return True, f"Subdomain {subdomain} isolated successfully"
    else:
        msg = f"Failed to isolate subdomain: {subdomain}"
        notify_slack(msg, color="warning")
        return False, msg

def block_ip_at_waf(ip_list: List[str], reason: str, ticket_id: str) -> Tuple[bool, str]:
    """
    Block IP di Cloudflare WAF. Traffic dari IP langsung di-reject dengan HTTP 403.
    Lebih aggressive dari DNS redirect, cocok untuk active compromise.
    """
    logger.info(f"[CONTAINMENT] Blocking IPs at WAF: {ip_list} (Ticket: {ticket_id})")
    
    cf = CloudflareAPI(CLOUDFLARE_API_TOKEN, CLOUDFLARE_ZONE_ID)
    rule_name = f"incident-block-{ticket_id}"
    
    rule_id = cf.create_waf_rule(rule_name, ip_list, action="block")
    
    if rule_id:
        msg = (f"IPs blocked at WAF: {', '.join(ip_list)}\n"
               f"Reason: {reason}\n"
               f"Rule ID: {rule_id}\n"
               f"Ticket: {ticket_id}")
        notify_slack(msg, color="danger")
        return True, f"WAF rule created: {rule_id}"
    else:
        return False, f"Failed to create WAF rule for IPs: {ip_list}"

def redirect_to_maintenance_page(subdomain: str, reason: str, ticket_id: str) -> Tuple[bool, str]:
    """
    Redirect traffic ke maintenance/block page.
    Lebih user-friendly daripada sinkhole, untuk kasus saat perlu retain user communication.
    """
    logger.info(f"[CONTAINMENT] Redirecting {subdomain} to maintenance page (Ticket: {ticket_id})")
    
    cf = CloudflareAPI(CLOUDFLARE_API_TOKEN, CLOUDFLARE_ZONE_ID)
    
    # Create page rule
    url_pattern = f"{subdomain}/*"
    rule_id = cf.create_page_rule(url_pattern, action="disable_security")
    
    if rule_id:
        msg = (f"Subdomain {subdomain} configured for maintenance page\n"
               f"Reason: {reason}\n"
               f"Page Rule ID: {rule_id}\n"
               f"Ticket: {ticket_id}")
        notify_slack(msg, color="warning")
        return True, f"Page rule created: {rule_id}"
    else:
        return False, f"Failed to create page rule for {subdomain}"

# === Main CLI ===
def main():
    parser = argparse.ArgumentParser(
        description="Cloudflare Automated DNS Containment for Critical Incidents"
    )
    parser.add_argument(
        "--action",
        required=True,
        choices=["isolate_subdomain", "block_ip_waf", "redirect_maintenance"],
        help="Containment action type"
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Subdomain (api.example.com) or IP (192.168.1.10) to isolate"
    )
    parser.add_argument(
        "--reason",
        required=True,
        help="Incident reason (malware, backdoor, abuse_report, c2_detected, etc)"
    )
    parser.add_argument(
        "--ticket_id",
        required=True,
        help="Incident ticket ID for audit trail"
    )
    parser.add_argument(
        "--ip_list",
        help="Comma-separated IP list for WAF block (if action=block_ip_waf)"
    )
    
    args = parser.parse_args()
    
    if not CLOUDFLARE_API_TOKEN or not CLOUDFLARE_ZONE_ID:
        logger.error("Missing CLOUDFLARE_API_TOKEN or CLOUDFLARE_ZONE_ID environment variables")
        sys.exit(1)
    
    # Validate severity cutoff (manual, sebaiknya dari SOAR webhook param)
    logger.info(f"Executing action: {args.action} | Target: {args.target} | Ticket: {args.ticket_id}")
    
    if args.action == "isolate_subdomain":
        success, msg = isolate_subdomain_to_sinkhole(args.target, args.reason, args.ticket_id)
    elif args.action == "block_ip_waf":
        if not args.ip_list:
            logger.error("--ip_list required for block_ip_waf action")
            sys.exit(1)
        ips = [ip.strip() for ip in args.ip_list.split(",")]
        success, msg = block_ip_at_waf(ips, args.reason, args.ticket_id)
    elif args.action == "redirect_maintenance":
        success, msg = redirect_to_maintenance_page(args.target, args.reason, args.ticket_id)
    
    print(f"{'✓' if success else '✗'} {msg}")
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
```

### 1c. Cloudflare Script Usage Examples

```bash
# Isolate malware-infected subdomain ke sinkhole
python3 cf_containment.py \
  --action isolate_subdomain \
  --target api.example.com \
  --reason "malware_detected_edr" \
  --ticket_id "INC-2024-001"

# Block IP di WAF (attacker source)
python3 cf_containment.py \
  --action block_ip_waf \
  --target 192.168.1.10 \
  --ip_list "203.0.113.45,203.0.113.46" \
  --reason "active_c2_compromise" \
  --ticket_id "INC-2024-001"

# Redirect ke maintenance page
python3 cf_containment.py \
  --action redirect_maintenance \
  --target payment.example.com \
  --reason "db_exfil_detected" \
  --ticket_id "INC-2024-001"
```

---

## 2. BIND DNS Automated Containment (Alternative On-Premises)

Untuk organisasi yang mengelola DNS on-premises menggunakan BIND, gunakan Response Policy Zone (RPZ) untuk real-time blocking.

### 2a. BIND RPZ Configuration

**File: `/etc/bind/named.conf.local`**

```bind
// Response Policy Zone untuk automated incident response
zone "rpz.incident.local" {
    type master;
    file "/etc/bind/zones/db.rpz.incident";
    allow-query { any; };
};

// Untuk setiap zone yang akan diproteksi
zone "example.com" {
    type master;
    file "/etc/bind/zones/db.example.com";
    response-policy { zone "rpz.incident.local"; };
};
```

**File: `/etc/bind/zones/db.rpz.incident`** (RPZ Zone File)

```bind
$ORIGIN rpz.incident.local.
$TTL 60

@   IN  SOA ns1.example.com. hostmaster.example.com. (
            2024010101  ; serial
            3600        ; refresh
            1800        ; retry
            604800      ; expire
            86400 )     ; minimum
    IN  NS  ns1.example.com.

; Catch-all sinkhole untuk subdomain terinfeksi
; Syntax: <subdomain>.rpz.incident.local IN A <sinkhole_ip>
api-infected.example.com.rpz.incident.local IN A 192.0.2.1

; Block berdasarkan IP asal (jika tahu attacker IP)
; Syntax: <ip>.rpz.ip IN A <sinkhole_ip>  (IP perlu di-reverse order)
45.113.0.203.rpz.ip IN A 192.0.2.1

; NXDOMAIN response (DNS REFUSED untuk domain tertentu)
payments-backdoor.example.com.rpz.incident.local IN CNAME .

; Log semua query ke zone RPZ
* IN TXT "Logged by RPZ for incident response"
```

### 2b. Python Script untuk BIND RPZ Auto-Update

```python
#!/usr/bin/env python3
"""
BIND RPZ Automated Update for DNS Containment
Modify zone file + reload BIND tanpa downtime
"""

import os
import subprocess
import logging
from datetime import datetime

RPZ_ZONE_FILE = "/etc/bind/zones/db.rpz.incident"
SINKHOLE_IP = "192.0.2.1"
BIND_RELOAD_CMD = "systemctl reload bind9"  # atau 'rndc reload' untuk BIND9 managed

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def add_rpz_rule(subdomain: str, sinkhole_ip: str = SINKHOLE_IP) -> bool:
    """Add subdomain ke RPZ zone file."""
    rule_line = f"{subdomain}.rpz.incident.local IN A {sinkhole_ip}\n"
    
    try:
        with open(RPZ_ZONE_FILE, "a") as f:
            f.write(rule_line)
        logger.info(f"Added RPZ rule: {subdomain} → {sinkhole_ip}")
        
        # Increment SOA serial untuk trigger zone transfer
        increment_zone_serial(RPZ_ZONE_FILE)
        
        # Reload BIND
        subprocess.run([BIND_RELOAD_CMD], shell=True, check=True)
        logger.info("BIND reloaded successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to add RPZ rule: {e}")
        return False

def increment_zone_serial(zone_file: str) -> bool:
    """Increment SOA serial number untuk trigger zone update."""
    try:
        with open(zone_file, "r") as f:
            lines = f.readlines()
        
        # Cari serial line (biasanya line ketiga)
        for i, line in enumerate(lines):
            if "serial" in line and i > 0:
                # Ambil nomor sebelumnya
                prev_serial = int(lines[i-1].strip().split()[0])
                new_serial = prev_serial + 1
                lines[i-1] = f"            {new_serial}  ; serial\n"
                break
        
        with open(zone_file, "w") as f:
            f.writelines(lines)
        logger.info(f"Zone serial incremented")
        return True
    except Exception as e:
        logger.error(f"Failed to increment serial: {e}")
        return False

if __name__ == "__main__":
    # Test: Add infected subdomain to RPZ
    add_rpz_rule("api-infected.example.com", SINKHOLE_IP)
```

---

## 3. SOAR Playbook Integration

Contoh bagaimana mengintegrasikan script DNS containment ke SOAR (Splunk SOAR / Cortex Xsoar / ServiceNow).

### 3a. Splunk SOAR Playbook (JSON)

```json
{
  "name": "Critical Incident - Automated DNS Containment",
  "description": "P1 severity: Auto-isolate compromised subdomain via Cloudflare API",
  "type": "automation",
  "trigger": {
    "source": "webhook",
    "webhook_url": "/api/soar/webhook/incident_critical",
    "payload_schema": {
      "severity": "string",
      "subdomain": "string",
      "incident_type": "string",
      "ticket_id": "string",
      "reason": "string"
    }
  },
  "steps": [
    {
      "step_id": "1_validate_severity",
      "type": "decision",
      "description": "Only proceed if severity == P1",
      "condition": "payload.severity == 'P1'",
      "on_true": "step_2_confirm_subdomain",
      "on_false": "step_9_notify_manual_review"
    },
    {
      "step_id": "2_confirm_subdomain",
      "type": "query",
      "description": "Verify subdomain in DNS & CMDB",
      "action": "dns_lookup",
      "input": {"subdomain": "payload.subdomain"},
      "on_success": "step_3_execute_containment",
      "on_failure": "step_9_notify_manual_review"
    },
    {
      "step_id": "3_execute_containment",
      "type": "http_request",
      "description": "Call Cloudflare containment script",
      "method": "POST",
      "url": "http://localhost:8000/api/containment/cloudflare",
      "headers": {"Authorization": "Bearer $SOAR_AUTH_TOKEN"},
      "body": {
        "action": "isolate_subdomain",
        "target": "payload.subdomain",
        "reason": "payload.reason",
        "ticket_id": "payload.ticket_id"
      },
      "on_success": "step_4_log_action",
      "on_failure": "step_8_escalate_manual"
    },
    {
      "step_id": "4_log_action",
      "type": "database",
      "description": "Log containment action untuk audit trail",
      "action": "insert",
      "table": "incident_containment_log",
      "fields": {
        "ticket_id": "payload.ticket_id",
        "action": "dns_isolation",
        "target": "payload.subdomain",
        "timestamp": "now()",
        "executor": "SOAR_AUTOMATION",
        "status": "success"
      },
      "on_success": "step_5_update_ticket"
    },
    {
      "step_id": "5_update_ticket",
      "type": "ticket_update",
      "description": "Update incident ticket",
      "ticket_system": "jira",
      "ticket_id": "payload.ticket_id",
      "updates": {
        "status": "containment_in_progress",
        "comment": "Automated DNS isolation executed: ${payload.subdomain} → sinkhole",
        "custom_field_containment_method": "dns_cloudflare"
      },
      "on_success": "step_6_notify_slack"
    },
    {
      "step_id": "6_notify_slack",
      "type": "slack_notify",
      "channel": "#security-incidents",
      "message": "🚨 P1 DNS Containment Executed\nTicket: ${payload.ticket_id}\nTarget: ${payload.subdomain}\nReason: ${payload.reason}\nStatus: In Progress"
    },
    {
      "step_id": "7_set_escalation_timer",
      "type": "timer",
      "description": "Set 1-hour timer for escalation if not manually resolved",
      "duration": "3600",
      "on_timeout": "step_10_escalate_if_unresolved"
    },
    {
      "step_id": "8_escalate_manual",
      "type": "notification",
      "description": "Notify IC untuk manual intervention",
      "recipients": ["incident_commander@example.com"],
      "method": "email_phone_call",
      "subject": "URGENT: Automated containment failed - manual action required",
      "body": "Ticket: ${payload.ticket_id}\nTarget: ${payload.subdomain}\nError: Containment script failed\nImmediate action required."
    },
    {
      "step_id": "9_notify_manual_review",
      "type": "notification",
      "description": "Notify analyst untuk manual review jika severity bukan P1",
      "recipients": ["on_call_analyst@example.com"],
      "subject": "Containment action flagged for manual review",
      "body": "Ticket: ${payload.ticket_id} - Severity: ${payload.severity}\nAutomation rule tidak triggered. Manual assessment needed."
    },
    {
      "step_id": "10_escalate_if_unresolved",
      "type": "notification",
      "description": "Escalate jika incident belum ditutup 1 jam setelah containment",
      "recipients": ["ciso@example.com"],
      "method": "phone_call",
      "subject": "Critical: Containment in progress >1hr - escalation required"
    }
  ]
}
```

### 3b. Webhook Trigger dari SIEM/EDR

```bash
# Contoh curl trigger (dari SIEM alert automation):
curl -X POST http://soar.example.com/api/soar/webhook/incident_critical \
  -H "Content-Type: application/json" \
  -d '{
    "severity": "P1",
    "subdomain": "api.example.com",
    "incident_type": "malware_detected",
    "ticket_id": "INC-2024-001",
    "reason": "CobaltStrike beacon C2 communication detected on 192.168.1.50"
  }'
```

---

## 4. Sinkhole IP Setup Best Practice

### 4a. Dedicated Sinkhole Server

Sinkhole IP harus respond dengan cara tertentu supaya tidak bikin noise / false traffic:

```bash
# Setup di sinkhole server (192.0.2.1)
# Capture semua traffic ke any port, log untuk forensik

# iptables rules
iptables -I INPUT -j LOG --log-prefix "SINKHOLE: "
iptables -A INPUT -p tcp -j REJECT --reject-with tcp-reset
iptables -A INPUT -p udp -j REJECT --reject-with icmp-port-unreachable

# Logging
tail -f /var/log/kern.log | grep SINKHOLE: > /var/log/sinkhole_traffic.log
```

### 4b. Sinkhole dengan Web Response

```python
#!/usr/bin/env python3
"""
Simple Sinkhole HTTP Server - Log semua request & respond 403
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import logging

logging.basicConfig(filename='/var/log/sinkhole_http.log', level=logging.INFO)

class SinkholeHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        logging.info(f"Sinkhole hit: {self.client_address[0]} -> {self.path} | User-Agent: {self.headers.get('User-Agent')}")
        self.send_response(403)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"<h1>Access Denied</h1>")
    
    def do_POST(self):
        self.do_GET()

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 80), SinkholeHandler)
    print("Sinkhole server running on :80")
    server.serve_forever()
```

---

## 5. Timeline: SLA Mapping untuk Critical Incidents

**Dari runbook yang sebelumnya (section 2: Tahap B — Containment):**

| Tahap | SLA Target | Action | Tool |
|---|---|---|---|
| **Acknowledge** | 5 menit | On-call analyst buka ticket | SOAR/Ticketing |
| **Confirm Severity P1** | 5 menit | Analyst verify P1 → trigger playbook | Manual review |
| **DNS Containment Execute** | 15 menit | Automated script isolate subdomain | Cloudflare API / BIND RPZ |
| **WAF Block (if needed)** | 15 menit | Block source IPs | Cloudflare WAF |
| **Full Containment (network isolation, etc)** | 1 jam | Manual containment steps | Network team + EDR |
| **Recovery** | 8 jam | Restore clean VM atau redirect traffic | Ops team |

**Contoh timeline P1:**
- T+0min: Alert triggered (malware detected on api.example.com)
- T+3min: SOAR playbook receives incident via webhook
- T+5min: Automated DNS isolation executed (api.example.com → sinkhole)
- T+5min: Slack notification sent to IC + CISO
- T+15min: If still unresolved, escalate untuk full network isolation
- T+1hr: Containment penuh harus tercapai (atau manual escalation)

---

## 6. False Positive Handling & Rollback

**PENTING:** Automated DNS changes bisa salah isolasi IP/subdomain yang sebenarnya clean.

### Automated Rollback Criteria

```python
# Dalam playbook, set automatic rollback jika:

ROLLBACK_TRIGGERS = {
    "false_positive_confirmed": {
        "condition": "analyst_flag == 'false_positive'",
        "action": "restore_original_dns_record",
        "timeout": "5_minutes"  # Max 5 menit setelah dimark false positive
    },
    "no_threat_evidence_after_1hr": {
        "condition": "forensic_analysis_complete AND no_malware_found",
        "action": "prompt_analyst_for_rollback",
        "timeout": "1_hour"
    },
    "ticket_cancelled": {
        "condition": "ticket.status == 'cancelled'",
        "action": "immediate_rollback"
    }
}
```

### Manual Rollback Script

```bash
#!/bin/bash
# Manual rollback DNS record

SUBDOMAIN=$1
ORIGINAL_IP=$2

python3 cf_containment.py \
  --action "restore_dns" \
  --target "$SUBDOMAIN" \
  --new_ip "$ORIGINAL_IP" \
  --reason "false_positive_confirmed" \
  --ticket_id "$TICKET_ID"
```

---

## 7. Audit & Compliance Log

Semua automation actions harus tercatat untuk compliance (GDPR, ISO27001, dsb):

```json
{
  "timestamp": "2024-01-15T14:32:01Z",
  "incident_id": "INC-2024-001",
  "severity": "P1",
  "action_type": "dns_isolation",
  "target": "api.example.com",
  "original_ip": "203.0.113.100",
  "sinkhole_ip": "192.0.2.1",
  "executor": "SOAR_Playbook_AutomatedContainment",
  "approval_required": false,
  "approval_obtained": null,
  "status": "success",
  "duration_ms": 2340,
  "affected_users": "~500 concurrent users redirected to sinkhole",
  "rollback_at": "2024-01-15T14:42:00Z",
  "rollback_reason": "false_positive - malware detector error"
}
```

---

## Quick Start Checklist

- [ ] Setup Cloudflare API token dengan permissions yang tepat
- [ ] Deploy `cf_containment.py` ke server SOAR dengan proper secret management
- [ ] Configure Slack webhook untuk notifications
- [ ] Setup sinkhole IP server (192.0.2.1 atau IP test RFC5737 lainnya)
- [ ] Test Cloudflare API connection: `python3 cf_containment.py --help`
- [ ] Create SOAR playbook dari contoh JSON di section 3a
- [ ] Setup webhook receiver di SOAR untuk incoming alerts
- [ ] Test end-to-end: Alert SIEM → Webhook → Playbook → DNS isolation
- [ ] Document rollback procedure & train analyst team
- [ ] Run tabletop exercise dengan team untuk validasi timeline SLA
