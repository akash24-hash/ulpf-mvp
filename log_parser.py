import re
import pandas as pd
from datetime import datetime

# Regex patterns for the 3 supported formats
APACHE_REGEX = r'(?P<src_ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<timestamp>.*?)\] "(?P<action>[A-Z]+) (?P<url>.*?) HTTP/.*?" (?P<status>\d+) .*'
SYSLOG_REGEX = r'(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+) (?P<hostname>\S+) (?P<process>[a-zA-Z0-9_-]+)\[?(?P<pid>\d*)\]?: (?P<message>.*)'
APP_LOG_REGEX = r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z|\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<severity>INFO|WARN|ERROR|DEBUG) (?P<message>.*)'

def detect_and_parse(line):
    """Detect format and extract fields."""
    line = line.strip()
    
    # Base schema matching the required unified format
    record = {
        "timestamp": None, "severity": None, "src_ip": None, "dst_ip": None,
        "src_port": None, "dst_port": None, "action": None, "url": None,
        "event_template": None, "message": None, "raw_log": line,
        "source_type": None, "parse_status": "unmapped",
        "anomaly": False, "anomaly_reason": None
    }

    if not line:
        return None

    # Try Apache
    apache_match = re.match(APACHE_REGEX, line)
    if apache_match:
        d = apache_match.groupdict()
        record.update({
            "source_type": "apache",
            "parse_status": "ok",
            "src_ip": d.get("src_ip"),
            "action": d.get("action"),
            "url": d.get("url"),
            "severity": "ERROR" if int(d.get("status", 200)) >= 400 else "INFO",
            "timestamp": normalize_timestamp(d.get("timestamp"), "apache"),
            "message": line
        })
        return generate_template(record)

    # Try Syslog
    syslog_match = re.match(SYSLOG_REGEX, line)
    if syslog_match:
        d = syslog_match.groupdict()
        msg = d.get("message", "")
        # Basic IP extraction from message for demo
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', msg)
        src_ip = ip_match.group(1) if ip_match else None
        
        record.update({
            "source_type": "syslog",
            "parse_status": "ok",
            "timestamp": normalize_timestamp(d.get("timestamp"), "syslog"),
            "message": msg,
            "src_ip": src_ip,
            "action": "DENY" if "failure" in msg.lower() or "failed" in msg.lower() else "ALLOW",
            "severity": "ERROR" if "fail" in msg.lower() else "INFO"
        })
        return generate_template(record)

    # Try App Log
    app_match = re.match(APP_LOG_REGEX, line)
    if app_match:
        d = app_match.groupdict()
        msg = d.get("message", "")
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', msg)
        
        record.update({
            "source_type": "app",
            "parse_status": "ok",
            "timestamp": normalize_timestamp(d.get("timestamp"), "app"),
            "severity": d.get("severity"),
            "message": msg,
            "src_ip": ip_match.group(1) if ip_match else None
        })
        return generate_template(record)

    return record

def normalize_timestamp(ts_str, source_type):
    """Normalize various timestamps to ISO 8601 string for UI rendering."""
    try:
        if source_type == "apache":
            dt = datetime.strptime(ts_str.split(' ')[0], "%d/%b/%Y:%H:%M:%S")
            return dt.isoformat() + "Z"
        elif source_type == "syslog":
            # Append current year for syslog missing year
            dt = datetime.strptime(f"2026 {ts_str}", "%Y %b %d %H:%M:%S")
            return dt.isoformat() + "Z"
        elif source_type == "app":
            if "T" in ts_str:
                return ts_str
            dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
            return dt.isoformat() + "Z"
    except Exception:
        return ts_str
    return ts_str

def generate_template(record):
    """Extract event template by masking IPs and numbers."""
    if not record["message"]:
        return record
    temp = re.sub(r'\d+\.\d+\.\d+\.\d+', '<IP>', record["message"])
    temp = re.sub(r'\b\d+\b', '<NUM>', temp)
    record["event_template"] = temp
    return record

def process_logs(raw_lines):
    """Process a list of log lines, detect duplicates, and flag anomalies."""
    records = []
    seen_hashes = set()
    duplicates = 0

    for line in raw_lines:
        parsed = detect_and_parse(line)
        if not parsed:
            continue
        
        # Simple duplicate detection based on raw string
        if line in seen_hashes:
            duplicates += 1
            continue
        seen_hashes.add(line)
        records.append(parsed)

    df = pd.DataFrame(records)
    if df.empty:
        return [], 0
    
    # Rule-based Anomaly Detection: High failure rate from a single IP
    # Identifies possible brute-force scans
    if 'src_ip' in df.columns and 'severity' in df.columns:
        # Count errors per IP
        error_counts = df[df['severity'] == 'ERROR'].groupby('src_ip').size()
        suspicious_ips = error_counts[error_counts > 3].index.tolist()
        
        for idx, row in df.iterrows():
            if row['src_ip'] in suspicious_ips and row['severity'] == 'ERROR':
                df.at[idx, 'anomaly'] = True
                df.at[idx, 'anomaly_reason'] = "high_failure_rate"

    # Fill NaNs for JSON serialization
    df = df.fillna("")
    return df.to_dict(orient="records"), duplicates