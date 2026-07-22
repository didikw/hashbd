# Deployment & Setup Guide — Automated DNS Containment

**Target audience:** DevSecOps, SOC engineers, incident response coordinators
**Time to deploy:** 1-2 hours for complete setup (testing included)

---

## Prerequisites Checklist

- [ ] Cloudflare account with domain managed
- [ ] API token access to generate (Zone.Edit + Cache Purge permissions)
- [ ] Python 3.8+ installed on SOAR/automation server
- [ ] Network access to `api.cloudflare.com` (outbound HTTPS)
- [ ] Slack workspace with webhook URL (optional but recommended)
- [ ] Access to SOAR platform (Splunk SOAR, TheHive, ServiceNow, dsb)
- [ ] Sinkhole IP server configured (or use RFC 5737 test IP 192.0.2.1 untuk testing)

---

## Step 1: Cloudflare API Token Setup

### 1.1 Create API Token

1. Login ke Cloudflare dashboard
2. Go to **Profile → API Tokens**
3. Click **Create Token**
4. Choose template atau buat custom dengan permissions:
   - ✓ `zone:edit` (DNS record manipulation)
   - ✓ `cache:purge` (instant cache clear)
   - ✓ `firewall:read` (read WAF rules)
   - ✓ `account:read` (read account)
5. Select **Zone Resources → Include → Specific zone → [your domain]**
6. Click **Create Token**
7. **COPY token langsung** (tidak bisa di-retrieve ulang)

### 1.2 Get Zone ID

1. Di Cloudflare dashboard, pilih domain kamu
2. Klik tab **Overview**
3. Scroll ke bawah → find **Zone ID** (UUID format)
4. Copy zone ID

### 1.3 Store Credentials Securely

**Option A: Environment variables (development/testing)**
```bash
export CLOUDFLARE_API_TOKEN="token_here"
export CLOUDFLARE_ZONE_ID="zone_id_here"
export CLOUDFLARE_ACCOUNT_ID="account_id_here"
export SINKHOLE_IP="192.0.2.1"
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
```

**Option B: Secrets manager (production recommended)**

Gunakan HashiCorp Vault, AWS Secrets Manager, atau Azure Key Vault:

```bash
# Example dengan Vault
vault kv put secret/cloudflare \
  api_token="token_here" \
  zone_id="zone_id_here" \
  sinkhole_ip="192.0.2.1"

# Dalam script, load dari Vault:
CREDS=$(vault kv get -format=json secret/cloudflare)
export CLOUDFLARE_API_TOKEN=$(echo $CREDS | jq -r '.data.data.api_token')
```

**Option C: `.env` file (development only, add to .gitignore)**
```bash
# .env
CLOUDFLARE_API_TOKEN="token_here"
CLOUDFLARE_ZONE_ID="zone_id_here"
SINKHOLE_IP="192.0.2.1"
```

Load via: `python3 -m python_dotenv cf_containment.py` atau `source .env && python3 cf_containment.py`

---

## Step 2: Install Dependencies

```bash
# Install Python package
pip install requests

# Verify installation
python3 -c "import requests; print('✓ requests installed')"

# Make script executable
chmod +x cf_containment.py
```

---

## Step 3: Test Connectivity & Authentication

```bash
# Set credentials
export CLOUDFLARE_API_TOKEN="your_token_here"
export CLOUDFLARE_ZONE_ID="your_zone_id_here"

# Run authentication test
python3 cf_containment.py --action isolate_subdomain \
  --target test.example.com \
  --reason "test_auth" \
  --ticket_id "TEST-001" \
  --dry_run

# Expected output:
# ✓ Successfully isolated test.example.com to 192.0.2.1
# (Dry run mode - no API calls executed)
```

---

## Step 4: Real Test (Non-Destructive)

### 4.1 Setup Test Subdomain

Buat subdomain khusus untuk testing yang **tidak production-critical**:

```bash
# Di Cloudflare dashboard, create A record:
test-incident.example.com → 10.0.1.100 (test VM)
```

### 4.2 Execute Real Containment Action

```bash
python3 cf_containment.py \
  --action isolate_subdomain \
  --target test-incident.example.com \
  --reason "test_containment_workflow" \
  --ticket_id "TEST-INCIDENT-001"

# Expected:
# ✓ Successfully isolated test-incident.example.com to 192.0.2.1
```

### 4.3 Verify DNS Update

```bash
# Check DNS resolution
nslookup test-incident.example.com
# Should return: 192.0.2.1

# Check TTL (should be 60 seconds for quick fallback)
dig test-incident.example.com +noall +answer
# test-incident.example.com. 60 IN A 192.0.2.1
```

### 4.4 Test Slack Notification

Jika SLACK_WEBHOOK_URL configured, kamu harus menerima message di channel.

### 4.5 Rollback Test

```bash
python3 cf_containment.py \
  --action restore_dns \
  --target test-incident.example.com \
  --original_ip 10.0.1.100 \
  --reason "test_rollback" \
  --ticket_id "TEST-INCIDENT-001"

# Verify restored
nslookup test-incident.example.com
# Should return: 10.0.1.100
```

---

## Step 5: Configure Sinkhole Server

### 5.1 Setup Dedicated Sinkhole IP (if using non-RFC5737)

Sinkhole server purpose: log semua traffic yang attempt connect ke isolated subdomain, untuk forensic analysis.

```bash
# On sinkhole server (192.0.2.1 atau IP asli sinkhole kamu)

# 1. Enable logging
iptables -I INPUT 1 -j LOG --log-prefix "SINKHOLE: " --log-level 7

# 2. Drop TCP/UDP
iptables -A INPUT -p tcp -j REJECT --reject-with tcp-reset
iptables -A INPUT -p udp -j REJECT --reject-with icmp-port-unreachable

# 3. Monitor logs (real-time)
tail -f /var/log/kern.log | grep SINKHOLE:
```

### 5.2 Optional: HTTP Sinkhole Service

```bash
# Save file: /opt/sinkhole/server.py
#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import logging

logging.basicConfig(filename='/var/log/sinkhole_http.log', level=logging.INFO)

class SinkholeHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        logging.info(f"{self.client_address[0]} → {self.path}")
        self.send_response(403)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(b"Access Denied")
    
    def do_POST(self):
        self.do_GET()
    
    def log_message(self, format, *args):
        pass  # Suppress default logging

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 80), SinkholeHandler)
    print("Sinkhole HTTP server running on :80")
    server.serve_forever()

# Run as service
chmod +x /opt/sinkhole/server.py
sudo systemctl start sinkhole  # atau nohup python3 /opt/sinkhole/server.py &
```

---

## Step 6: Integration dengan SOAR

### 6.1 Splunk SOAR Integration

**Setup playbook webhook receiver:**

1. Splunk SOAR → Cloud Platform Settings → Webhooks
2. Create new webhook endpoint: `/api/soar/webhook/incident_critical`
3. Add playbook trigger: HTTP POST → execute playbook "Critical Incident - Automated DNS Containment"
4. Set webhook to accept payload:
   ```json
   {
     "severity": "P1",
     "subdomain": "api.example.com",
     "incident_type": "malware_detected",
     "ticket_id": "INC-2024-001",
     "reason": "CobaltStrike beacon detected"
   }
   ```

**Create HTTP action di playbook untuk call Python script:**

```
Action: Execute shell command
Command: python3 /opt/cf_containment/cf_containment.py \
  --action isolate_subdomain \
  --target {subdomain} \
  --reason {incident_type} \
  --ticket_id {ticket_id}
```

### 6.2 TheHive Integration

**Setup Cortex Responder untuk DNS containment:**

```json
{
  "name": "CloudflareContain",
  "description": "Isolate subdomain to Cloudflare sinkhole",
  "dataType": "domain",
  "command": "python3 /opt/cf_containment/cf_containment.py --action isolate_subdomain --target {} --reason malware --ticket_id {ticket_id}",
  "output": "text"
}
```

### 6.3 ServiceNow SecOps Integration

**Create Flow untuk trigger containment:**

1. ServiceNow → Workflow Editor
2. Trigger: Alert created with severity=P1
3. Add action: "Run script"
4. Script:
   ```
   python3 /opt/cf_containment/cf_containment.py \
     --action isolate_subdomain \
     --target $(get_affected_subdomain) \
     --reason $(get_incident_reason) \
     --ticket_id $(get_incident_id)
   ```

---

## Step 7: Logging & Audit Trail

### 7.1 Log Location

Logs tersimpan di:
- **Incidents log:** `/var/log/cf_containment/incidents.log` (structured JSON)
- **Error log:** `/var/log/cf_containment/errors.log` (detailed errors)

### 7.2 Audit Trail Sample

```
2024-01-15 14:32:01 - INFO - Starting subdomain isolation: api.example.com
2024-01-15 14:32:02 - INFO - Cloudflare API authentication verified
2024-01-15 14:32:03 - INFO - DNS updated: api.example.com → 192.0.2.1 (TTL: 60s)
2024-01-15 14:32:04 - INFO - Cache purged for 2 URLs
2024-01-15 14:32:05 - INFO - Slack notification sent successfully
```

### 7.3 Query Logs (Production Monitoring)

```bash
# Find all containment actions for incident
grep "INC-2024-001" /var/log/cf_containment/incidents.log

# Find all DNS updates
grep "DNS updated" /var/log/cf_containment/incidents.log

# Find failed actions
tail -20 /var/log/cf_containment/errors.log
```

---

## Step 8: Production Deployment

### 8.1 Systemd Service Setup (Optional)

Jika ingin run script sebagai service:

```bash
# /etc/systemd/system/cf-containment.service
[Unit]
Description=Cloudflare DNS Containment API
After=network.target

[Service]
Type=simple
User=soar
WorkingDirectory=/opt/cf_containment
ExecStart=/usr/bin/python3 /opt/cf_containment/cf_containment.py --listen 0.0.0.0:8000
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Deploy:
```bash
sudo cp cf_containment.py /opt/cf_containment/
sudo chown soar:soar /opt/cf_containment/cf_containment.py
sudo systemctl enable cf-containment
sudo systemctl start cf-containment
```

### 8.2 Docker Deployment (Alternative)

```dockerfile
# Dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY cf_containment.py .
RUN pip install requests

ENV CLOUDFLARE_API_TOKEN=""
ENV CLOUDFLARE_ZONE_ID=""

ENTRYPOINT ["python3", "cf_containment.py"]
```

Build & run:
```bash
docker build -t cf-containment:latest .
docker run --rm \
  -e CLOUDFLARE_API_TOKEN="token_here" \
  -e CLOUDFLARE_ZONE_ID="zone_id_here" \
  -v /var/log/cf_containment:/var/log/cf_containment \
  cf-containment:latest \
  --action isolate_subdomain \
  --target api.example.com \
  --reason malware_detected \
  --ticket_id INC-2024-001
```

---

## Step 9: Monitoring & Alerting

### 9.1 Monitor Script Execution

```bash
# Splunk query untuk monitor containment actions
index=main sourcetype="cf_containment" 
| stats count by action, status
| where status="failed"
```

### 9.2 Alert jika SLA terlampaui

```bash
# Jika tidak ada successful containment dalam 15 menit untuk P1
index=main severity="P1" action="isolate_subdomain"
| stats latest(status) as last_status by ticket_id
| search last_status="failed"
| alert
```

### 9.3 Metrics to Track

- **Execution time:** How long dari webhook diterima sampai DNS updated
- **Success rate:** % berhasil vs failed containment attempts
- **False positive rate:** % rollback due to false positive
- **Time to rollback:** How fast analyst bisa rollback jika false positive

---

## Troubleshooting

### Issue: "Authentication failed"

**Solution:**
```bash
# Verify token is valid
curl -s "https://api.cloudflare.com/client/v4/user/tokens/verify" \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" | jq

# Should return: {"success": true}
```

### Issue: "DNS record not found"

**Solution:**
```bash
# Verify subdomain exists
python3 -c "
from cf_containment import CloudflareAPI
cf = CloudflareAPI('$CLOUDFLARE_API_TOKEN', '$CLOUDFLARE_ZONE_ID')
print(cf.get_dns_record('api.example.com'))
"

# If returns None, DNS record doesn't exist - create it first di Cloudflare
```

### Issue: "Cache purge failed" (API rate limit)

**Solution:** Cloudflare rate limit adalah 20 requests/detik. Jika sering kena limit, tambahkan retry logic:

```python
import time
for attempt in range(3):
    success, msg = cf.purge_cache_by_url(urls)
    if success:
        break
    time.sleep(2 ** attempt)  # Exponential backoff
```

### Issue: Slack notification tidak terkirim

**Solution:**
```bash
# Test webhook URL
curl -X POST "$SLACK_WEBHOOK_URL" \
  -H 'Content-type: application/json' \
  -d '{"text":"Test message"}'

# Should return: ok
```

---

## Rollout Plan (Recommended)

1. **Week 1: Development & Testing**
   - Setup credentials
   - Test dengan non-production subdomain
   - Train team dengan playbook

2. **Week 2: Staging**
   - Deploy ke staging SOAR
   - Dry-run playbook execution
   - Test rollback procedures

3. **Week 3-4: Production**
   - Enable automation untuk P1 incidents hanya
   - Monitor untuk 2 minggu
   - Escalate ke P2/P3 setelah stable

4. **Ongoing**
   - Weekly review dari SLA metrics
   - Quarterly playbook update
   - Tabletop exercise setiap 6 bulan

---

## Security Best Practices

- ✓ Rotate API token setiap 90 hari
- ✓ Use secrets manager, jangan hardcode credentials
- ✓ Enable API token IP allowlist (Cloudflare) untuk limit dari SOAR server IP saja
- ✓ Log semua containment actions untuk audit
- ✓ Require manual approval untuk restore_dns action (rollback)
- ✓ Monitor failed API calls — bisa indikasi credential compromise
- ✓ Use different token untuk production & staging

---

## Support & Documentation

- Cloudflare API docs: https://developers.cloudflare.com/api/
- NIST SP 800-61 incident handling: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf
- Python requests docs: https://requests.readthedocs.io/
