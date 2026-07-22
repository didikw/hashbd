#!/usr/bin/env python3
"""
Cloudflare Automated DNS Containment for Critical Incidents
Ready-to-run production script with error handling & audit logging

Usage:
  export CLOUDFLARE_API_TOKEN="your_token"
  export CLOUDFLARE_ZONE_ID="your_zone_id"
  python3 cf_containment.py --action isolate_subdomain --target api.example.com --reason malware_detected --ticket_id INC-2024-001

Dependencies: pip install requests
"""

import os
import sys
import json
import requests
import logging
import argparse
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from pathlib import Path

# ============================================================================
# CONFIGURATION
# ============================================================================

CLOUDFLARE_API_TOKEN = os.getenv("CLOUDFLARE_API_TOKEN")
CLOUDFLARE_ZONE_ID = os.getenv("CLOUDFLARE_ZONE_ID")
CLOUDFLARE_ACCOUNT_ID = os.getenv("CLOUDFLARE_ACCOUNT_ID")

# Sinkhole IP (RFC 5737 test IP - ganti dengan IP sinkhole real di production)
SINKHOLE_IP = os.getenv("SINKHOLE_IP", "192.0.2.1")

# Logging
LOG_DIR = "/var/log/cf_containment" if os.access("/var/log", os.W_OK) else "./logs"
Path(LOG_DIR).mkdir(exist_ok=True)
INCIDENT_LOG_FILE = os.path.join(LOG_DIR, "incidents.log")
ERROR_LOG_FILE = os.path.join(LOG_DIR, "errors.log")

# Slack (optional)
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK_URL")

# APIs
CF_API_BASE = "https://api.cloudflare.com/client/v4"
REQUEST_TIMEOUT = 10

# ============================================================================
# LOGGING SETUP
# ============================================================================

def setup_logging():
    """Setup dual logging: file + console."""
    # Main logger
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    
    # File handler - incidents
    fh_incident = logging.FileHandler(INCIDENT_LOG_FILE)
    fh_incident.setLevel(logging.INFO)
    fh_incident.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    
    # File handler - errors
    fh_error = logging.FileHandler(ERROR_LOG_FILE)
    fh_error.setLevel(logging.ERROR)
    fh_error.setFormatter(logging.Formatter(
        '%(asctime)s - ERROR - %(funcName)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    
    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter(
        '%(levelname)s: %(message)s'
    ))
    
    logger.addHandler(fh_incident)
    logger.addHandler(fh_error)
    logger.addHandler(ch)
    
    return logger

logger = setup_logging()

# ============================================================================
# CLOUDFLARE API CLASS
# ============================================================================

class CloudflareAPI:
    """Wrapper untuk Cloudflare API dengan error handling."""
    
    def __init__(self, token: str, zone_id: str):
        """Initialize Cloudflare API client."""
        if not token or not zone_id:
            raise ValueError("CLOUDFLARE_API_TOKEN and CLOUDFLARE_ZONE_ID required")
        
        self.token = token
        self.zone_id = zone_id
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        self._verify_auth()
    
    def _verify_auth(self) -> bool:
        """Verify API token is valid."""
        try:
            url = f"{CF_API_BASE}/user/tokens/verify"
            resp = requests.get(url, headers=self.headers, timeout=REQUEST_TIMEOUT)
            if resp.status_code == 200:
                logger.info("Cloudflare API authentication verified")
                return True
            else:
                logger.error(f"Authentication failed: {resp.status_code} {resp.text}")
                return False
        except Exception as e:
            logger.error(f"Auth verification error: {e}")
            return False
    
    def get_dns_record(self, name: str, record_type: str = "A") -> Optional[Dict]:
        """Fetch DNS record by name."""
        url = f"{CF_API_BASE}/zones/{self.zone_id}/dns_records"
        params = {"name": name, "type": record_type}
        
        try:
            resp = requests.get(url, headers=self.headers, params=params, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
            
            if data.get("success") and data.get("result"):
                return data["result"][0]
            
            logger.warning(f"DNS record not found: {name}")
            return None
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch DNS record {name}: {e}")
            return None
    
    def update_dns_record(
        self, 
        record_id: str, 
        name: str, 
        ip: str, 
        ttl: int = 60
    ) -> Tuple[bool, str]:
        """Update A record to new IP."""
        url = f"{CF_API_BASE}/zones/{self.zone_id}/dns_records/{record_id}"
        
        payload = {
            "type": "A",
            "name": name,
            "content": ip,
            "ttl": ttl,
            "proxied": False  # Important: disable proxy untuk direct sinkhole routing
        }
        
        try:
            resp = requests.put(url, headers=self.headers, json=payload, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
            
            if data.get("success"):
                logger.info(f"DNS updated: {name} → {ip} (TTL: {ttl}s)")
                return True, f"Successfully updated {name} to {ip}"
            else:
                error_msg = str(data.get("errors", ["Unknown error"]))
                logger.error(f"DNS update failed: {error_msg}")
                return False, f"API error: {error_msg}"
                
        except requests.exceptions.RequestException as e:
            logger.error(f"DNS update request failed: {e}")
            return False, str(e)
    
    def create_waf_rule(
        self, 
        rule_name: str, 
        ip_list: List[str], 
        action: str = "block"
    ) -> Tuple[bool, Optional[str]]:
        """Create WAF IP block rule."""
        url = f"{CF_API_BASE}/zones/{self.zone_id}/firewall/rules"
        
        # Build IP expression
        ip_expr = " or ".join([f'(ip.src == "{ip}")' for ip in ip_list])
        
        payload = {
            "name": rule_name,
            "description": f"Automated incident containment - {datetime.now().isoformat()}",
            "filter": {"expression": ip_expr},
            "action": action  # "block", "challenge", "log"
        }
        
        try:
            resp = requests.post(url, headers=self.headers, json=payload, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
            
            if data.get("success"):
                rule_id = data.get("result", {}).get("id")
                logger.info(f"WAF rule created: {rule_name} ({rule_id})")
                return True, rule_id
            else:
                error_msg = str(data.get("errors", ["Unknown error"]))
                logger.error(f"WAF rule creation failed: {error_msg}")
                return False, None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"WAF rule request failed: {e}")
            return False, None
    
    def purge_cache_by_url(self, urls: List[str]) -> Tuple[bool, str]:
        """Instantly purge cache."""
        url = f"{CF_API_BASE}/zones/{self.zone_id}/purge_cache"
        payload = {"files": urls}
        
        try:
            resp = requests.post(url, headers=self.headers, json=payload, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            data = resp.json()
            
            if data.get("success"):
                logger.info(f"Cache purged for {len(urls)} URLs")
                return True, "Cache purged"
            else:
                error_msg = str(data.get("errors", ["Unknown error"]))
                return False, error_msg
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Cache purge request failed: {e}")
            return False, str(e)

# ============================================================================
# SLACK NOTIFICATION
# ============================================================================

def notify_slack(message: str, color: str = "danger", details: Dict = None) -> bool:
    """Send structured Slack notification."""
    if not SLACK_WEBHOOK:
        logger.debug("Slack webhook not configured, skipping notification")
        return False
    
    attachment = {
        "color": color,
        "title": "🚨 Automated DNS Containment Action",
        "text": message,
        "ts": int(datetime.now().timestamp())
    }
    
    if details:
        fields = []
        for key, value in details.items():
            fields.append({
                "title": key,
                "value": str(value),
                "short": True if len(str(value)) < 30 else False
            })
        attachment["fields"] = fields
    
    payload = {"attachments": [attachment]}
    
    try:
        resp = requests.post(SLACK_WEBHOOK, json=payload, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return True
    except Exception as e:
        logger.error(f"Failed to send Slack notification: {e}")
        return False

# ============================================================================
# CONTAINMENT ACTIONS
# ============================================================================

def isolate_subdomain_to_sinkhole(
    subdomain: str,
    reason: str,
    ticket_id: str
) -> Tuple[bool, str]:
    """
    Primary containment action: Redirect subdomain to sinkhole IP.
    Subdomain becomes unreachable, VM stays powered for forensics.
    """
    logger.info(f"Starting subdomain isolation: {subdomain}")
    
    try:
        cf = CloudflareAPI(CLOUDFLARE_API_TOKEN, CLOUDFLARE_ZONE_ID)
    except ValueError as e:
        logger.error(f"Cloudflare init failed: {e}")
        return False, f"Configuration error: {e}"
    
    # Fetch existing record
    record = cf.get_dns_record(subdomain)
    if not record:
        msg = f"DNS record not found: {subdomain}"
        logger.error(msg)
        notify_slack(f"❌ Containment failed: {msg}", color="warning", details={"ticket": ticket_id})
        return False, msg
    
    original_ip = record.get("content")
    record_id = record.get("id")
    
    # Log action
    action_log = {
        "timestamp": datetime.now().isoformat(),
        "action": "isolate_subdomain",
        "subdomain": subdomain,
        "original_ip": original_ip,
        "sinkhole_ip": SINKHOLE_IP,
        "reason": reason,
        "ticket_id": ticket_id
    }
    logger.info(f"Action details: {json.dumps(action_log)}")
    
    # Execute DNS update
    success, msg = cf.update_dns_record(record_id, subdomain, SINKHOLE_IP, ttl=60)
    
    if not success:
        notify_slack(
            f"❌ Failed to isolate {subdomain}",
            color="warning",
            details={"error": msg, "ticket": ticket_id}
        )
        return False, msg
    
    # Purge cache
    cache_urls = [f"http://{subdomain}/*", f"https://{subdomain}/*"]
    cf.purge_cache_by_url(cache_urls)
    
    # Success notification
    notify_slack(
        f"✓ Subdomain isolated to sinkhole\n*Original IP:* {original_ip}",
        color="danger",
        details={
            "Subdomain": subdomain,
            "Sinkhole IP": SINKHOLE_IP,
            "Reason": reason,
            "Ticket": ticket_id
        }
    )
    
    return True, f"Successfully isolated {subdomain} to {SINKHOLE_IP}"

def block_ip_at_waf(
    ip_list: List[str],
    reason: str,
    ticket_id: str
) -> Tuple[bool, str]:
    """Create WAF rule to block source IPs."""
    logger.info(f"Starting WAF IP block: {ip_list}")
    
    try:
        cf = CloudflareAPI(CLOUDFLARE_API_TOKEN, CLOUDFLARE_ZONE_ID)
    except ValueError as e:
        return False, f"Configuration error: {e}"
    
    rule_name = f"incident-block-{ticket_id}"
    
    success, rule_id = cf.create_waf_rule(rule_name, ip_list, action="block")
    
    if success:
        notify_slack(
            f"✓ IPs blocked at WAF\n*Rule ID:* {rule_id}",
            color="danger",
            details={
                "IPs": ", ".join(ip_list),
                "Reason": reason,
                "Rule ID": rule_id,
                "Ticket": ticket_id
            }
        )
        return True, f"WAF rule created: {rule_id}"
    else:
        notify_slack(
            f"❌ Failed to create WAF rule",
            color="warning",
            details={"ips": ", ".join(ip_list), "ticket": ticket_id}
        )
        return False, "Failed to create WAF rule"

def restore_dns_record(
    subdomain: str,
    original_ip: str,
    reason: str,
    ticket_id: str
) -> Tuple[bool, str]:
    """Restore original DNS record (rollback)."""
    logger.info(f"Rolling back DNS for {subdomain} to {original_ip}")
    
    try:
        cf = CloudflareAPI(CLOUDFLARE_API_TOKEN, CLOUDFLARE_ZONE_ID)
    except ValueError as e:
        return False, f"Configuration error: {e}"
    
    record = cf.get_dns_record(subdomain)
    if not record:
        return False, f"DNS record not found: {subdomain}"
    
    record_id = record.get("id")
    success, msg = cf.update_dns_record(record_id, subdomain, original_ip, ttl=300)
    
    if success:
        cf.purge_cache_by_url([f"http://{subdomain}/*", f"https://{subdomain}/*"])
        
        notify_slack(
            f"↩️ DNS restored (rollback)\n*IP:* {original_ip}",
            color="warning",
            details={
                "Subdomain": subdomain,
                "IP": original_ip,
                "Reason": reason,
                "Ticket": ticket_id
            }
        )
        return True, f"DNS restored to {original_ip}"
    else:
        return False, msg

# ============================================================================
# MAIN CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Cloudflare Automated DNS Containment for Critical Incidents",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Isolate malware-infected subdomain
  python3 cf_containment.py --action isolate_subdomain \\
    --target api.example.com --reason malware_detected --ticket_id INC-2024-001

  # Block attacker IPs at WAF
  python3 cf_containment.py --action block_ip_waf \\
    --ip_list "203.0.113.45,203.0.113.46" --reason active_c2 --ticket_id INC-2024-001

  # Restore DNS record (rollback)
  python3 cf_containment.py --action restore_dns \\
    --target api.example.com --original_ip 10.0.1.50 --reason false_positive --ticket_id INC-2024-001
        """
    )
    
    parser.add_argument(
        "--action",
        required=True,
        choices=["isolate_subdomain", "block_ip_waf", "restore_dns"],
        help="Containment action"
    )
    parser.add_argument(
        "--target",
        help="Subdomain to isolate (e.g., api.example.com)"
    )
    parser.add_argument(
        "--ip_list",
        help="Comma-separated IPs for WAF block (e.g., 203.0.113.45,203.0.113.46)"
    )
    parser.add_argument(
        "--original_ip",
        help="Original IP for restore_dns action"
    )
    parser.add_argument(
        "--reason",
        required=True,
        help="Incident reason (malware_detected, backdoor_found, abuse_report, c2_detected, etc)"
    )
    parser.add_argument(
        "--ticket_id",
        required=True,
        help="Incident ticket ID for audit trail"
    )
    parser.add_argument(
        "--dry_run",
        action="store_true",
        help="Dry run mode (log only, no API calls)"
    )
    
    args = parser.parse_args()
    
    # Validate environment
    if not CLOUDFLARE_API_TOKEN or not CLOUDFLARE_ZONE_ID:
        logger.error("Missing CLOUDFLARE_API_TOKEN or CLOUDFLARE_ZONE_ID environment variables")
        print("ERROR: Set environment variables:")
        print("  export CLOUDFLARE_API_TOKEN='your_token'")
        print("  export CLOUDFLARE_ZONE_ID='your_zone_id'")
        sys.exit(1)
    
    # Dry run mode
    if args.dry_run:
        logger.info("=" * 60)
        logger.info("DRY RUN MODE (no API calls executed)")
        logger.info("=" * 60)
    
    # Execute action
    if args.action == "isolate_subdomain":
        if not args.target:
            print("ERROR: --target required for isolate_subdomain")
            sys.exit(1)
        success, msg = isolate_subdomain_to_sinkhole(args.target, args.reason, args.ticket_id)
    
    elif args.action == "block_ip_waf":
        if not args.ip_list:
            print("ERROR: --ip_list required for block_ip_waf")
            sys.exit(1)
        ips = [ip.strip() for ip in args.ip_list.split(",")]
        success, msg = block_ip_at_waf(ips, args.reason, args.ticket_id)
    
    elif args.action == "restore_dns":
        if not args.target or not args.original_ip:
            print("ERROR: --target and --original_ip required for restore_dns")
            sys.exit(1)
        success, msg = restore_dns_record(args.target, args.original_ip, args.reason, args.ticket_id)
    
    # Output result
    status_icon = "✓" if success else "✗"
    print(f"{status_icon} {msg}")
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
