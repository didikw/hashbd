# DNS Containment Playbook — QUICK REFERENCE

**Print this and post on SOC wallboard**

---

## 🚨 P1 CRITICAL INCIDENT — AUTOMATED DNS CONTAINMENT

| SLA Time | Action | Owner | Status |
|---|---|---|---|
| T+0 min | **Alert triggered** | Detection (SIEM/EDR) | |
| T+5 min | **Verify P1 severity** | On-call analyst | |
| T+5 min | **CONTAINMENT EXECUTED** | SOAR playbook (auto) | ✓ DNS isolated |
| T+15 min | **Confirmation & monitoring** | Analyst | |
| T+60 min | **Escalate if uncontained** | IC / CISO | |

---

## STEP-BY-STEP: Manual Containment (if SOAR fails)

### Step 1: Verify Incident is P1
```
Checklist:
☐ Confirmed malware/backdoor (not false positive)?
☐ Active compromise or C2 beacon detected?
☐ Data exfiltration evidence?
☐ Compromised account has privileged access?

YES to any above = P1 ✓ Proceed with containment
NO to all = Escalate to senior analyst first
```

### Step 2: Gather Information
```bash
# What to collect BEFORE isolation:
- Subdomain: ________________
- Current IP: ________________
- Affected systems: ________________
- Incident ticket ID: ________________
- Incident type: ☐ malware  ☐ backdoor  ☐ c2_beacon  ☐ abuse  ☐ other
- Approval (IC/CISO): ☐ Yes  ☐ Verbal OK (note time)
```

### Step 3: Execute Containment (Choose one)

#### Option A: Automated via CLI
```bash
# Set env vars
export CLOUDFLARE_API_TOKEN="..."
export CLOUDFLARE_ZONE_ID="..."

# Run containment
python3 /opt/cf_containment/cf_containment.py \
  --action isolate_subdomain \
  --target <SUBDOMAIN> \
  --reason <INCIDENT_TYPE> \
  --ticket_id <TICKET_ID>

# Wait 10-30 seconds, verify DNS updated
nslookup <SUBDOMAIN>
# Should return: 192.0.2.1 (sinkhole IP)
```

#### Option B: Via SOAR Playbook
```
Log into SOAR → Incident → Click "Critical Incident - Automated DNS Containment"
Fill fields:
  - Subdomain: api.example.com
  - Incident type: malware_detected
  - Ticket ID: INC-2024-001
  - Reason: CobaltStrike beacon detected
Click EXECUTE
```

#### Option C: Manual Cloudflare Dashboard (Last resort, slower)
```
1. Cloudflare → DNS → Find record
2. Edit A record → Change IP to: 192.0.2.1
3. Set TTL to: 60 seconds
4. Purge cache
5. Wait 60s for DNS propagation
```

### Step 4: Verify Containment
```bash
# DNS resolution (should point to sinkhole)
nslookup <SUBDOMAIN>
# Result: 192.0.2.1 ✓

# Check TTL (should be 60 seconds)
dig <SUBDOMAIN> +noall +answer

# Check Slack notification was sent
# (Check #security-incidents channel)

# Log action in ticket
# Copy stdout/log output to incident ticket for audit trail
```

### Step 5: Document & Notify
```
Incident ticket update:
- Status: CONTAINMENT_IN_PROGRESS
- Comment: "DNS isolation executed at 14:32 UTC
  Subdomain: api.example.com → 192.0.2.1
  Executor: SOAR Playbook / Manual CLI"
- Alert IC/CISO in Slack
```

### Step 6: Proceed to Forensics
```
☐ Isolate VM from network (if needed)
☐ Take forensic snapshot/memory dump
☐ Check logs for lateral movement
☐ Identify other compromised systems
☐ Plan eradication steps
```

---

## 🔄 ROLLBACK (if False Positive)

**Conditions for rollback:**
- Forensic analysis confirms: NO malware found
- Analyst judgment: this was false positive
- Within 5 minutes of isolation (minimize user impact)

### Rollback Steps
```bash
# Step 1: Get original IP from incident ticket
Original IP: ________________

# Step 2: Execute rollback
python3 /opt/cf_containment/cf_containment.py \
  --action restore_dns \
  --target <SUBDOMAIN> \
  --original_ip <ORIGINAL_IP> \
  --reason false_positive_confirmed \
  --ticket_id <TICKET_ID>

# Step 3: Verify DNS restored
nslookup <SUBDOMAIN>
# Should return: <ORIGINAL_IP> ✓

# Step 4: Update ticket
Comment: "Rollback executed at HH:MM UTC
Reason: False positive - no malware detected"
```

---

## ⚠️ CRITICAL ALERTS (SLA Breach Actions)

| SLA Breach | Trigger | Action |
|---|---|---|
| **Acknowledge timeout (5 min)** | Alert not acknowledged by analyst | 🔴 Page on-call lead (SMS/call) |
| **Analysis timeout (15 min)** | Severity not confirmed as P1 | 🔴 Escalate to IC automatically |
| **Containment timeout (15 min)** | DNS not isolated after confirmed P1 | 🔴 CISO paging + war room |
| **Full containment timeout (1 hr)** | Still open after 1 hour | 🔴 Escalate to executive leadership |
| **Rollback not approved (5 min)** | Analyst requests rollback, IC not responding | 🟡 Attempt to contact via alternate channel |

---

## 📞 ESCALATION CHAIN

```
Level 1 (5 min): On-call Analyst
   ↓ (if no response in 5 min)
Level 2 (15 min): Senior Analyst / Team Lead
   ↓ (if no response in 15 min)
Level 3 (30 min): Incident Commander (IC)
   ↓ (if no response in 30 min)
Level 4 (60 min): CISO / VP Security
```

---

## 🔒 Important: Approval Required Actions

✓ **Auto-approved (P1):** DNS isolation to sinkhole
✓ **Auto-approved (P1):** WAF IP block
⚠️ **Requires manual approval:** Network-wide containment (firewall changes)
⚠️ **Requires manual approval:** Shutdown VM (forensics may be lost)
⚠️ **Requires manual approval:** DNS rollback (only in false positive case)

---

## 📊 SLA Dashboard Link

Check real-time containment metrics:
```
SOAR: https://soar.example.com/dashboard/incident_sla
Splunk: https://splunk.example.com/app/search/incident_metrics
ServiceNow: https://servicenow.example.com/incident_dashboard
```

---

## 📝 Logging Checklist

```
☐ Ticket ID documented?
☐ Original IP recorded?
☐ Sinkhole IP confirmed (192.0.2.1)?
☐ Timestamp of isolation logged?
☐ Slack notification received?
☐ Forensic snapshot taken (before/after)?
☐ Escalation log recorded if any?
```

---

## 🚀 Quick Commands (Copy-Paste)

### Isolate subdomain
```bash
python3 /opt/cf_containment/cf_containment.py \
  --action isolate_subdomain \
  --target api.example.com \
  --reason malware_detected \
  --ticket_id INC-2024-001
```

### Block IP at WAF
```bash
python3 /opt/cf_containment/cf_containment.py \
  --action block_ip_waf \
  --ip_list "203.0.113.45,203.0.113.46" \
  --reason active_c2 \
  --ticket_id INC-2024-001
```

### Restore DNS (rollback)
```bash
python3 /opt/cf_containment/cf_containment.py \
  --action restore_dns \
  --target api.example.com \
  --original_ip 10.0.1.50 \
  --reason false_positive \
  --ticket_id INC-2024-001
```

### Check DNS status
```bash
nslookup api.example.com
dig api.example.com +noall +answer
```

### View logs
```bash
# Recent incidents
tail -20 /var/log/cf_containment/incidents.log

# Errors
tail -10 /var/log/cf_containment/errors.log

# Search for specific ticket
grep "INC-2024-001" /var/log/cf_containment/incidents.log
```

---

## ⏱️ Expected Timings

| Action | Time |
|---|---|
| Alert → SOAR webhook received | 5-10 sec |
| Webhook → API call executed | 2-5 sec |
| DNS update → Cache purge | 2-3 sec |
| **Total (alert to isolated)** | **< 30 seconds** |
| DNS propagation (full) | 60 sec |
| Slack notification sent | 5-10 sec |

---

## 🔍 Post-Incident Review Checklist

After incident closed:
```
☐ Collect all logs & screenshots
☐ Document timeline (T+0, T+5, T+15, etc)
☐ Calculate SLA compliance (MTTD/MTTR/MTTC)
☐ Identify false positives (if any)
☐ Review playbook effectiveness
☐ Schedule RCA meeting (within 5 days)
☐ Update playbook based on learnings
☐ Brief team on improvements
```

---

## 📞 24/7 Support Contacts

```
SOC On-call:       +1-XXX-SOC-ONCALL (or PagerDuty)
Incident Commander: [IC phone/pager]
CISO:              [CISO email]
Cloudflare Support: https://support.cloudflare.com (email within 1 hour)
Network Team:      [Network team channel]
```

---

## 🎯 Target SLAs (Set Expectations)

```
Detection → P1 Confirmed:     15 minutes (or auto-escalate)
Confirmed → Containment:       15 minutes (or auto-escalate)
Containment → Full response:   1 hour (or escalate to exec)
Full response → Recovery:      8 hours (or business continuity)
Recovery → RCA completed:      5 days
```

**Remember:** Every minute of delay = more potential data exfil / lateral movement.
Faster containment = smaller blast radius. **Speed wins.**

---

**Last updated:** 2024-01-15
**Next review:** 2024-04-15 (quarterly)
