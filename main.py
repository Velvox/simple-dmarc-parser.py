import time
from dotenv import dotenv_values
from imap_tools import MailBox, AND
import xml.etree.ElementTree as ET
from pathlib import Path
import smtplib
from email.message import EmailMessage
import gzip
import traceback
from typing import List
import dns.resolver
from datetime import datetime, timedelta
import json
from pathlib import Path
import urllib.request
import ssl
import io
import zipfile


# ─── Configuration ────────────────────────────────────────────────────────────
config = dotenv_values(".env")
HOST               = config.get("IMAP_HOST")
PORT               = int(config.get("IMAP_PORT", 993))
USER               = config.get("IMAP_USER")
PASSWD             = config.get("IMAP_PASS")
SOURCE_FOLDER      = config.get("SOURCE_FOLDER", "INBOX")
PROCESSED_FOLDER   = config.get("PROCESSED_FOLDER", "INBOX.Email-LOG-Processed")
RAW_XML_BASE       = config.get("RAW_XML_DIR", "raw_xml")

ALERT_EMAIL        = config.get("ALERT_EMAIL")
SMTP_HOST          = config.get("SMTP_HOST")
SMTP_PORT          = int(config.get("SMTP_PORT", 587))
SMTP_USER          = config.get("SMTP_USER")
SMTP_PASS          = config.get("SMTP_PASS")
SMTP_FROM_NAME     = config.get("SMTP_FROM_NAME", SMTP_USER)

POLL_INTERVAL      = int(config.get("POLL_INTERVAL", 300))  # seconds

NOTIFY_ON_OK = config.get("NOTIFY_ON_OK", "False").lower() == "true"

# DNS check settings
DNS_CHECK_INTERVAL = 6 * 60 * 60
CONFIG_PATH = Path("config.json")
LAST_RESULTS_PATH = Path("last_results.json")

def debug(msg: str):
    print(f"[DEBUG] {msg}")


def send_alert(subject: str, body: str, attachments: List[Path] = None):
    debug(f"Preparing to send alert: {subject}")
    msg = EmailMessage()
    # Format the From header with optional name
    msg["From"] = f"{SMTP_FROM_NAME} <{SMTP_USER}>"
    msg["To"] = ALERT_EMAIL
    msg["Subject"] = subject
    msg.set_content(body)

    # Attach any XML files
    if attachments:
        for file_path in attachments:
            try:
                debug(f"Attaching file: {file_path}")
                data = file_path.read_bytes()
                msg.add_attachment(
                    data,
                    maintype='application',
                    subtype='xml',
                    filename=file_path.name
                )
            except Exception as e:
                debug(f"Failed to attach {file_path}: {e}")

    try:
        # choose SSL or STARTTLS based on port
        if SMTP_PORT == 465:
            debug("Using SMTP_SSL on port 465")
            server = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT)
        else:
            debug(f"Connecting to SMTP server {SMTP_HOST}:{SMTP_PORT}")
            server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
            server.set_debuglevel(1)
            debug("Performing EHLO...")
            server.ehlo()
            debug("Starting TLS...")
            server.starttls()
            server.ehlo()
        debug("Logging into SMTP server...")
        server.login(SMTP_USER, SMTP_PASS)
        debug("Sending email message...")
        server.send_message(msg)
        server.quit()
        debug("Alert sent successfully.")
    except Exception as e:
        debug(f"Failed to send alert: {e}")
        debug(traceback.format_exc())


def process_mailbox():
    debug("Opening IMAP connection...")
    with MailBox(HOST, port=PORT).login(USER, PASSWD) as mailbox:
        debug("IMAP login successful.")

        # Ensure processed folder exists
        try:
            debug(f"Ensuring folder '{PROCESSED_FOLDER}' exists...")
            mailbox.folder.create(PROCESSED_FOLDER)
        except Exception:
            debug("Processed folder already exists or creation failed.")

        mailbox.folder.set(SOURCE_FOLDER)
        messages = list(mailbox.fetch(AND(seen=False)))
        debug(f"Found {len(messages)} unseen message(s).")

        for msg in messages:
            debug(f"Processing message UID={msg.uid}, Subject={msg.subject}")
            xml_attachments, failures = [], []

            for att in msg.attachments:
                filename = att.filename or "<no_name>"
                debug(f" Found attachment: {filename}")

                # Prepare list of XMLs
                xml_files: List[tuple] = []

                # .xml.gz
                if filename.lower().endswith('.xml.gz'):
                    debug("  Detected .xml.gz, decompressing...")
                    try:
                        data = gzip.decompress(att.payload)
                        xml_files.append((filename[:-3], data))
                    except Exception as e:
                        debug(f"  Failed to decompress {filename}: {e}")
                        continue

                # .xml
                elif filename.lower().endswith('.xml'):
                    debug("  Detected .xml, using raw bytes")
                    xml_files.append((filename, att.payload))

                # .zip
                elif filename.lower().endswith('.zip'):
                    debug("  Detected .zip, extracting XML files...")
                    try:
                        # ensure output directory
                        dt = msg.date
                        out_dir = Path(RAW_XML_BASE) / str(dt.year) / f"{dt.month:02d}"
                        out_dir.mkdir(parents=True, exist_ok=True)

                        # save raw zip
                        zip_path = out_dir / filename
                        debug(f" Writing ZIP to: {zip_path}")
                        zip_path.write_bytes(att.payload)

                        # extract XMLs
                        with zipfile.ZipFile(io.BytesIO(att.payload)) as zf:
                            for member in zf.infolist():
                                inner = Path(member.filename).name
                                if not inner.lower().endswith('.xml'):
                                    debug(f"    Skipping non-XML in zip: {inner}")
                                    continue
                                debug(f"    Extracting XML: {inner}")
                                data = zf.read(member)
                                xml_files.append((inner, data))
                    except Exception as e:
                        debug(f"  Failed to process zip {filename}: {e}")
                        continue
                else:
                    debug("  Skipping non-XML attachment.")
                    continue

                # Save & parse each XML
                for xml_name, xml_bytes in xml_files:
                    # save
                    dt = msg.date
                    out_dir = Path(RAW_XML_BASE) / str(dt.year) / f"{dt.month:02d}"
                    out_dir.mkdir(parents=True, exist_ok=True)
                    xml_path = out_dir / xml_name
                    debug(f" Writing XML to: {xml_path}")
                    xml_path.write_bytes(xml_bytes)
                    xml_attachments.append(xml_path)

                    # parse
                    debug(" Parsing XML payload...")
                    try:
                        root = ET.fromstring(xml_bytes)
                    except ET.ParseError as pe:
                        debug(f"  XML parse error in {xml_name}: {pe}")
                        continue
                    for rec in root.findall('.//record'):
                        spf  = rec.findtext('.//spf')
                        dkim = rec.findtext('.//dkim')
                        if spf != 'pass' or dkim != 'pass':
                            ip = rec.findtext('.//source_ip')
                            failures.append(f"IP:{ip} SPF:{spf} DKIM:{dkim}")

            # Send alert or test report
            if failures:
                debug(f"  Detected {len(failures)} failure(s). Preparing failure alert.")
                subject = f"DMARC FAIL {dt.date()}"
                body = "Failed records:\n" + '\n'.join(failures)
                send_alert(subject, body, attachments=xml_attachments)
            else:
                debug("  All records passed.")
                if NOTIFY_ON_OK:
                    debug("  NOTIFY_ON_OK is True. Preparing success report.")
                    subject = f"DMARC OK {dt.date()}"
                    body = "All DMARC records passed successfully."
                    send_alert(subject, body, attachments=xml_attachments)
                else:
                    debug("  NOTIFY_ON_OK is False. Skipping success report.")


            # Move message to processed folder
            debug(f"Moving UID={msg.uid} to {PROCESSED_FOLDER}")
            try:
                mailbox.move(msg.uid, PROCESSED_FOLDER)
                debug(" Message moved.")
            except Exception as e:
                debug(f" Failed to move message: {e}")


# ─── DMARC, SPF, DKIM, MTA-STS, TLS-RTP & BIMI Checks ────────────────────────────────────────────────────────────

# Helper function to load JSON data
def load_json(path):
    if path.exists():
        return json.loads(path.read_text())
    return {}

# Helper function to save JSON data
def save_json(data, path):
    path.write_text(json.dumps(data, indent=2))

# Function to fetch DNS TXT records
def get_dns_txt(domain):
    try:
        return sorted([r.to_text().strip('"') for r in dns.resolver.resolve(domain, 'TXT')])
    except Exception as e:
        debug(f"Failed to resolve TXT for {domain}: {e}")
        return []

# Function to fetch MTA-STS policy
def fetch_mta_sts(domain):
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    context = ssl.create_default_context()
    try:
        with urllib.request.urlopen(url, context=context, timeout=10) as response:
            lines = response.read().decode("utf-8").splitlines()
            result = {}
            for line in lines:
                if not line.strip() or ":" not in line:
                    continue
                key, value = line.strip().split(":", 1)
                key = key.strip().lower()
                value = value.strip()
                if key == "mx":
                    result.setdefault("mx", []).append(value)
                elif key == "max_age":
                    result[key] = int(value)
                else:
                    result[key] = value
            return result
    except Exception as e:
        debug(f"Failed to fetch MTA-STS policy from {url}: {e}")
        return {}

# Filter out Google Site Verification from SPF records
def filter_spf(spf_records):
    return [record for record in spf_records if record.startswith("v=spf")]

# Fetch DNS state for the domain
def fetch_dns_state(domain, expected):
    result = {}
    for record_type, val in expected.items():
        if record_type == "SPF":
            spf_records = get_dns_txt(domain)
            result["SPF"] = filter_spf(spf_records)  # Filter out Google Site Verification
        elif record_type == "DKIM":
            dkim_results = {}
            for selector in val:
                dkim_domain = f"{selector}._domainkey.{domain}"
                dkim_results[selector] = get_dns_txt(dkim_domain)
            result["DKIM"] = dkim_results
        elif record_type == "DMARC":
            result["DMARC"] = get_dns_txt(f"_dmarc.{domain}")
        elif record_type == "MTA-STS":
            result["MTA-STS"] = fetch_mta_sts(domain)
        elif record_type == "TLS-RPT":
            result["TLS-RPT"] = get_dns_txt(f"_smtp._tls.{domain}")
        elif record_type == "BIMI":
            result["BIMI"] = get_dns_txt(f"default._bimi.{domain}")
    return result

# Compare DNS states
def compare_dns_states(old, new):
    changes = {}
    for domain in new:
        changes[domain] = {}
        for record in new[domain]:
            old_val = old.get(domain, {}).get(record, [])
            new_val = new[domain][record]

            # Check if values are different, except for Google Site Verification
            if old_val != new_val:
                if record == "SPF":
                    old_val = filter_spf(old_val)  # Filter out Google Site Verification from old records
                    new_val = filter_spf(new_val)  # Filter out Google Site Verification from new records
                if old_val != new_val:
                    changes[domain][record] = {
                        "old": old_val,
                        "new": new_val
                    }
        if not changes[domain]:
            del changes[domain]  # No changes for this domain
    return changes

def compare_with_expected(current, expected):
    mismatches = {}
    for domain in expected:
        mismatches[domain] = {}
        for record in expected[domain]:
            expected_val = expected[domain][record]
            current_val = current.get(domain, {}).get(record, None)
            if expected_val != current_val:
                mismatches[domain][record] = {
                    "expected": expected_val,
                    "found": current_val
                }
        if not mismatches[domain]:
            del mismatches[domain]
    return mismatches

# Function to run DNS check
def run_dns_check():
    expected_config = load_json(CONFIG_PATH)
    last_results = load_json(LAST_RESULTS_PATH)

    debug("Fetching current DNS records...")
    current_results = {
        domain: fetch_dns_state(domain, expected)
        for domain, expected in expected_config.items()
    }

    debug("Comparing DNS states...")
    changes = compare_dns_states(last_results, current_results)
    mismatches = compare_with_expected(current_results, expected_config)

    if changes or mismatches:
        debug("Changes or mismatches detected")
        now = datetime.utcnow().isoformat()
        body = f"DNS configuration changes detected at {now} UTC:\n\n"
        if changes:
            for domain, records in changes.items():
                body += f"\nDomain: {domain} (CHANGES)\n"
                for record_type, diff in records.items():
                    body += f"  {record_type}:\n"
                    body += f"    OLD: {diff['old']}\n"
                    body += f"    NEW: {diff['new']}\n"
        if mismatches:
            for domain, records in mismatches.items():
                body += f"\nDomain: {domain} (MISMATCH)\n"
                for record_type, diff in records.items():
                    body += f"  {record_type}:\n"
                    body += f"    EXPECTED: {diff['expected']}\n"
                    body += f"    FOUND: {diff['found']}\n"
        send_alert("DNS Change or Mismatch Detected", body)
    else:
        debug("No DNS changes or mismatches detected.")

    save_json(current_results, LAST_RESULTS_PATH)



def main():
    debug("Starting DMARC and DNS monitor.")
    print(f'Bot started successfully')
    last_dns_check = datetime.utcnow() - timedelta(seconds=DNS_CHECK_INTERVAL)

    while True:
        try:
            # Always run the DMARC mail check
            process_mailbox()
        except Exception as e:
            print(f"[ERROR] during mailbox check: {e}")

        # Run the DNS checker if enough time has passed
        now = datetime.utcnow()
        if (now - last_dns_check).total_seconds() >= DNS_CHECK_INTERVAL:
            try:
                debug("Running DNS check...")
                run_dns_check()
                last_dns_check = now
            except Exception as e:
                print(f"[ERROR] during DNS check: {e}")

        debug(f"Sleeping for {POLL_INTERVAL} seconds...")
        time.sleep(POLL_INTERVAL)

if __name__ == '__main__':
    main()
