# Scanning and Endpoint Protection

## Why Scans Get Blocked

Nmap discovers open ports by sending TCP SYN packets in rapid succession. This behaviour is **identical to what an attacker does during reconnaissance**, so endpoint protection systems (ESET, Windows Defender, Sophos, CrowdStrike, etc.) may block the scanner's IP address and cause scans to fail or return incomplete results.

---

## Solution 1 — Whitelist the Scanner in Your Security Software (Recommended)

The correct enterprise approach is to tell your security software that the NetScan server IP is a trusted security scanner, not an attacker.

### ESET Protect
1. Open ESET Protect Console
2. Go to **Policies** → select the policy applied to your endpoints
3. Go to **Detection Engine** → **Network Attack Protection** → **Exclusions**
4. Add the NetScan server IP as an excluded source address
5. Apply the policy to all machines

### Windows Defender / Microsoft Defender for Endpoint
1. Open Microsoft Defender Security Center
2. Go to **Settings** → **Endpoints** → **Indicators**
3. Add the scanner IP as an allowed IP indicator

### General Principle
Any enterprise endpoint protection system has a mechanism to whitelist source IPs. Consult your vendor's documentation. The exclusion should apply to **outbound network connection blocks** from the scanner IP.

---

## Solution 2 — Reduce Scan Aggressiveness

If you cannot modify the security policy, slow the scans down so packets are sent slowly enough not to trigger detection.

Open `app/scanner/engine.py` and change `-T4` to `-T2`:

```python
_SCAN_ARGS: Dict[str, str] = {
    "quick":   "-sV -O --top-ports 1000 -T2",
    "full":    "-sV -O -p 1-65535 -T2",
    "service": "-sV --version-intensity 9 -O --top-ports 1000 -T2",
}
```

Restart the worker after making this change.

### Nmap Timing Reference

| Flag | Name | Approx Speed (per subnet) | IDS/AV Reaction |
|------|------|--------------------------|-----------------|
| -T1 | Sneaky | Hours | Never flagged |
| -T2 | Polite | 15–30 minutes | Rarely flagged |
| -T3 | Normal | 5–15 minutes | Sometimes flagged |
| -T4 | Aggressive (default) | 2–5 minutes | Usually flagged |
| -T5 | Insane | < 2 minutes | Always flagged |

`-T2` is the recommended balance for internal security scanning — slow enough to avoid triggering IDS, fast enough to be practical.

---

## Recommendation

**Do both:**
1. Whitelist the scanner in your security software — legitimate scans are never blocked
2. Use `-T2` as the default — avoids generating unnecessary noise in security logs

The whitelist ensures reliability. The reduced timing ensures clean logs.

---

## Legal Reminder

> Only scan networks and devices you own or have explicit written authorisation to scan. Running NetScan against networks without permission is illegal in most jurisdictions regardless of whether endpoint protection blocks it.
