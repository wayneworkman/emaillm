#!/usr/bin/env python3
"""
SPF Diagnostic Tool - Find a specific email and diagnose SPF failures.

Uses the same config and credentials as emaillm.py to locate an email
by sender and subject, then performs deep SPF analysis including:
- All authentication headers present on the email
- DNS lookup of the sender's SPF TXT record
- Manual pyspf check with detailed results
- Explanation of why SPF is passing or failing

Usage:
    python spf_diagnose.py --sender user@example.com --subject "Partial subject"
    python spf_diagnose.py --sender user@example.com --subject "Partial subject" --inbox primary_email
    python spf_diagnose.py --sender user@example.com --message-id "<abc123@domain.com>"
"""

import argparse
import imaplib
import json
import logging
import os
import re
import subprocess
import sys
from email import policy, message_from_bytes
from email.header import decode_header
from email.utils import parseaddr
from pathlib import Path

import dns.resolver
import spf
import tldextract

logger = logging.getLogger(__name__)


def load_config(config_path: str) -> dict:
    """Load configuration from JSON file."""
    config_path = os.path.expanduser(config_path)
    abs_path = os.path.abspath(config_path)
    canonical_path = Path(abs_path).resolve(strict=False)

    with open(canonical_path, 'r') as f:
        return json.load(f)


def get_keepassxc_credential(database: str, entry_name: str, password_file: str) -> dict:
    """Retrieve credentials from KeePassXC using keepassxc-cli."""
    password_file = os.path.expanduser(password_file)
    kpx_password = None
    try:
        with open(password_file, 'r') as f:
            kpx_password = f.read().strip()
    except FileNotFoundError:
        raise FileNotFoundError(f"KeePassXC password file not found: {password_file}")

    if not kpx_password:
        raise ValueError(f"KeePassXC password file is empty: {password_file}")

    # Get username
    username_cmd = [
        'keepassxc-cli', 'show', '--attributes', 'username',
        database, entry_name
    ]
    result = subprocess.run(username_cmd, input=kpx_password.encode(),
                            capture_output=True, timeout=30)
    if result.returncode != 0:
        raise Exception(f"Failed to retrieve username: {result.stderr.decode()}")
    username = result.stdout.decode().strip()

    # Get password
    password_cmd = [
        'keepassxc-cli', 'show', '--attributes', 'password',
        database, entry_name
    ]
    result = subprocess.run(password_cmd, input=kpx_password.encode(),
                            capture_output=True, timeout=30)
    if result.returncode != 0:
        raise Exception(f"Failed to retrieve password: {result.stderr.decode()}")
    password = result.stdout.decode().strip()

    # Get host from custom attributes
    custom_attrs_cmd = [
        'keepassxc-cli', 'show', '--all', database, entry_name
    ]
    result = subprocess.run(custom_attrs_cmd, input=kpx_password.encode(),
                            capture_output=True, timeout=30)
    host = ''
    if result.returncode == 0:
        custom_data = result.stdout.decode()
        if custom_data.strip().startswith('{'):
            try:
                custom_json = json.loads(custom_data)
                custom_attributes = custom_json.get('attributes', {})
                if isinstance(custom_attributes, str):
                    custom_attributes = json.loads(custom_attributes)
                if isinstance(custom_attributes, dict):
                    host = custom_attributes.get('host', '')
                elif isinstance(custom_attributes, list):
                    for attr in custom_attributes:
                        if attr.get('key') == 'host':
                            host = attr.get('value', '')
                            break
            except json.JSONDecodeError:
                pass
        else:
            for line in custom_data.split('\n'):
                if line.strip().startswith('host:'):
                    host = line.strip()[5:].strip()
                    break

    kpx_password = ''
    if not all([username, password, host]):
        raise Exception(f"Missing fields: username={bool(username)}, password={bool(password)}, host={bool(host)}")

    return {'username': username, 'password': password, 'host': host}


def find_inbox_config(config: dict, inbox_name: str = None):
    """Find the inbox config entry to use."""
    inboxes = config.get('inboxes', [])
    if not inboxes:
        raise ValueError("No inboxes configured")
    if inbox_name:
        for inbox in inboxes:
            if inbox['name'] == inbox_name:
                return inbox
        raise ValueError(f"Inbox '{inbox_name}' not found. Available: {[i['name'] for i in inboxes]}")
    # Default to first inbox
    return inboxes[0]


def extract_domain(email_addr: str) -> str:
    """Extract the registered domain from an email address."""
    if '@' not in email_addr:
        return email_addr
    domain = email_addr.split('@')[-1]
    extracted = tldextract.extract(domain)
    return extracted.top_domain_under_public_suffix or domain


def extract_ip_from_received(received_header: str) -> str:
    """Extract IP address from Received header."""
    # Look for IP addresses in brackets or after "from" patterns
    match = re.search(r'\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?', received_header)
    if match:
        return match.group(1)
    return ''


def decode_header_value(raw_value: str) -> str:
    """Decode an encoded email header value."""
    if not raw_value:
        return ''
    decoded_parts = decode_header(raw_value)
    return ''.join(
        part.decode(encoding or 'utf-8', errors='replace')
        if isinstance(part, bytes) else str(part)
        for part, encoding in decoded_parts
    )


def lookup_spf_record(domain: str) -> str:
    """Look up the SPF TXT record for a domain via DNS."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 10
    resolver.lifetime = 10
    try:
        answers = resolver.resolve(domain, 'TXT')
        txt_records = []
        for rdata in answers:
            record_text = ''
            for piece in rdata.strings:
                if isinstance(piece, bytes):
                    record_text += piece.decode('utf-8', errors='replace')
                else:
                    record_text += str(piece)
            txt_records.append(record_text)
        for record in txt_records:
            if record.startswith('v=spf1'):
                return record
        # Return all TXT records if no SPF record found
        return txt_records if txt_records else []
    except dns.resolver.NXDOMAIN:
        return 'NXDOMAIN - domain does not exist'
    except dns.resolver.NoAnswer:
        return 'No TXT records found'
    except dns.resolver.NoNameservers:
        return 'DNS query failed - no nameservers responded'
    except dns.resolver.LifetimeTimeout:
        return 'DNS query timed out'
    except Exception as e:
        return f'DNS error: {e}'


def lookup_dns_record(domain: str, record_type: str = 'TXT') -> list:
    """Look up any DNS record type for a domain."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 10
    resolver.lifetime = 10
    try:
        answers = resolver.resolve(domain, record_type)
        return [str(rdata) for rdata in answers]
    except dns.resolver.NXDOMAIN:
        return ['NXDOMAIN - domain does not exist']
    except dns.resolver.NoAnswer:
        return [f'No {record_type} records found']
    except dns.resolver.NoNameservers:
        return ['DNS query failed - no nameservers responded']
    except dns.resolver.LifetimeTimeout:
        return ['DNS query timed out']
    except Exception as e:
        return [f'DNS error: {e}']


def print_separator(char='=', length=70):
    print(char * length)


def diagnose_email(config: dict, inbox_cfg: dict, sender: str,
                   subject: str = None, message_id: str = None):
    """Find the target email and perform SPF diagnosis."""
    kp_cfg = config.get('keepassxc', {})
    timeout = config.get('spam', {}).get('processing_timeout_seconds', 30)

    # Get credentials
    credentials = get_keepassxc_credential(
        kp_cfg['database_path'],
        inbox_cfg['keepassxc_entry_name'],
        kp_cfg['password_file']
    )

    # Connect to IMAP
    imap = imaplib.IMAP4_SSL(credentials['host'], inbox_cfg['imap'].get('port', 993),
                              timeout=timeout)
    imap.login(credentials['username'], credentials['password'])

    # Search through all folders that might contain the email
    search_folders = ['Inbox', 'Spam', 'INBOX/Spam']
    found_email = None
    found_in_folder = None
    found_mail_id = None

    for folder in search_folders:
        try:
            status, _ = imap.select(folder)
            if status != 'OK':
                continue

            # Build search criteria
            criteria = f'(FROM "{sender}"'
            if subject:
                criteria += f' SUBJECT "{subject}"'
            if message_id:
                # Message-ID search
                criteria = f'(HEADER Message-ID "{message_id}")'
            criteria += ')'

            # IMAP SEARCH doesn't support combined AND with SUBJECT+FROM easily,
            # so fetch matching FROM first then filter by subject
            status, data = imap.search(None, f'(FROM "{sender}")')
            if status != 'OK' or not data[0]:
                continue

            mail_ids = data[0].decode('utf-8').split()
            # Check most recent 50 emails from this sender
            for mid in mail_ids[-50:]:
                status, msg_data = imap.fetch(mid, '(RFC822)')
                if status != 'OK':
                    continue
                msg = message_from_bytes(msg_data[0][1], policy=policy.default)

                # Check sender
                _, from_addr = parseaddr(msg.get('From', ''))
                from_addr = from_addr.strip().lower()
                if from_addr != sender.lower():
                    continue

                # Check subject
                if subject:
                    email_subject = decode_header_value(msg.get('Subject', ''))
                    if subject.lower() not in email_subject.lower():
                        continue

                # Check message-id
                if message_id:
                    email_msg_id = msg.get('Message-ID', '')
                    if message_id.strip('<>') not in email_msg_id.strip('<>'):
                        continue

                found_email = msg
                found_in_folder = folder
                found_mail_id = mid
                break

        except Exception as e:
            logger.warning(f"Error searching folder {folder}: {e}")
            continue

        if found_email:
            break

    imap.close()
    imap.logout()

    if not found_email:
        search_desc = f"From: {sender}"
        if subject:
            search_desc += f", Subject contains: {subject}"
        if message_id:
            search_desc += f", Message-ID: {message_id}"
        print(f"\n[NOT FOUND] Could not find email matching: {search_desc}")
        print(f"Searched folders: Inbox, Spam, INBOX/Spam")
        print(f"Make sure the sender address and subject (partial) are correct.\n")
        return

    # ========================================
    # EMAIL FOUND - DIAGNOSTIC OUTPUT
    # ========================================
    print_separator()
    print("EMAIL FOUND - SPF DIAGNOSTIC REPORT")
    print_separator()
    print(f"\nFound in folder: {found_in_folder} (message ID on server: {found_mail_id})")

    # Basic info
    from_raw = found_email.get('From', '')
    to_raw = found_email.get('To', '')
    subject_raw = decode_header_value(found_email.get('Subject', ''))
    date_raw = found_email.get('Date', '')
    msg_id = found_email.get('Message-ID', '')
    return_path = found_email.get('Return-Path', '')
    sender_header = found_email.get('Sender', '')
    envelope_from = found_email.get('Envelope-From', '')

    _, from_addr = parseaddr(from_raw)
    from_addr = from_addr.strip()
    from_domain = extract_domain(from_addr)

    print(f"\n--- Basic Information ---")
    print(f"  From:          {from_raw}")
    print(f"  From address:  {from_addr}")
    print(f"  From domain:   {from_domain}")
    print(f"  To:            {to_raw}")
    print(f"  Subject:       {subject_raw}")
    print(f"  Date:          {date_raw}")
    print(f"  Message-ID:    {msg_id}")
    print(f"  Return-Path:   {return_path}")
    if sender_header:
        print(f"  Sender header: {sender_header}")

    # All Received headers (they can appear multiple times)
    print(f"\n--- Received Headers (all instances) ---")
    received_headers = found_email.get_all('Received', [])
    if not received_headers:
        print("  (none)")
    for i, r in enumerate(received_headers):
        print(f"  Received[{i}]: {r}")

    # Authentication headers
    print(f"\n--- Authentication Headers ---")
    auth_results = found_email.get('Authentication-Results', '')
    received_spf = found_email.get('Received-SPF', '')
    dkim_signature = found_email.get('DKIM-Signature', '')
    dkim_headers = found_email.get_all('DKIM-Signature', [])
    arc_headers = found_email.get_all('ARC-Authentication-Results', [])
    domainkeys = found_email.get('DomainKey-Signature', '')
    spf_header = found_email.get('X-Spam', '')

    print(f"  Authentication-Results:")
    if auth_results:
        for line in auth_results.split('\n'):
            print(f"    {line.strip()}")
    else:
        print(f"    (none)")

    print(f"  Received-SPF:")
    if received_spf:
        print(f"    {received_spf}")
    else:
        print(f"    (none)")

    print(f"  DKIM-Signature:")
    if dkim_signature:
        for line in dkim_signature.split('\n'):
            print(f"    {line.strip()}")
    else:
        print(f"    (none)")

    if arc_headers:
        print(f"  ARC-Authentication-Results:")
        for arc in arc_headers:
            print(f"    {arc}")

    # ========================================
    # SPF ANALYSIS
    # ========================================
    print(f"\n--- SPF DNS RECORD ---")
    print(f"  Looking up TXT records for: {from_domain}")
    spf_record = lookup_spf_record(from_domain)
    print(f"\n  SPF record for '{from_domain}':")
    if isinstance(spf_record, list):
        if spf_record:
            for r in spf_record:
                print(f"    {r}")
        else:
            print(f"    (no TXT records found)")
    else:
        print(f"    {spf_record}")

    # Also check the exact domain (not just the registered domain)
    exact_domain = from_addr.split('@')[-1] if '@' in from_addr else from_domain
    if exact_domain != from_domain:
        print(f"\n  Also checking exact envelope domain: {exact_domain}")
        spf_record_exact = lookup_spf_record(exact_domain)
        print(f"  SPF record for '{exact_domain}':")
        if isinstance(spf_record_exact, list):
            for r in spf_record_exact:
                print(f"    {r}")
        else:
            print(f"    {spf_record_exact}")

    # ========================================
    # MANUAL SPF CHECK
    # ========================================
    print(f"\n--- MANUAL SPF CHECK ---")

    # Determine the sender IP from Received headers
    sender_ip = ''
    if received_headers:
        # The last Received header is typically the one from the sending server
        sender_ip = extract_ip_from_received(received_headers[-1])

    # Determine envelope sender from Return-Path
    envelope_sender = ''
    if return_path:
        _, envelope_sender = parseaddr(return_path)
        envelope_sender = envelope_sender.strip()
    elif from_addr:
        envelope_sender = from_addr

    print(f"  Envelope sender (Return-Path): {envelope_sender or '(none - using From)'}")
    print(f"  Sending IP (from last Received): {sender_ip or '(could not extract)'}")

    if sender_ip and envelope_sender:
        try:
            result = spf.check2(sender_ip, envelope_sender, from_domain)
            print(f"\n  pyspf.check2 results:")
            print(f"    SPF result:  {result[0]}")
            print(f"    Explanaton:  {result[1]}")
            print(f"    Helo:        {result[2]}")
            print(f"    SMTP From:   {result[3]}")
            print(f"    SMTP Helo:   {result[4]}")
            print(f"    Record:      {result[5] if len(result) > 5 else '(not available)'}")
        except Exception as e:
            print(f"\n  pyspf error: {e}")

    # Also check with the exact domain
    if sender_ip and envelope_sender and exact_domain != from_domain:
        try:
            result2 = spf.check2(sender_ip, envelope_sender, exact_domain)
            print(f"\n  pyspf.check2 with exact domain '{exact_domain}':")
            print(f"    SPF result:  {result2[0]}")
            print(f"    Explanaton:  {result2[1]}")
        except Exception as e:
            print(f"  pyspf error: {e}")

    # ========================================
    # AUTH RESULTS PARSING
    # ========================================
    print(f"\n--- AUTHENTICATION RESULTS ANALYSIS ---")
    if not auth_results:
        print("  No Authentication-Results header found on this email.")
        print("  Your receiving mail server may not perform auth checks,")
        print("  or the email arrived via a path that bypasses them.")
    else:
        # Parse SPF results from Authentication-Results
        spf_match = re.search(r'spf=([a-z]+)', auth_results)
        dkim_match = re.search(r'dkim=([a-z-]+)', auth_results)
        dmarc_match = re.search(r'dmarc=([a-z]+)', auth_results)

        if spf_match:
            spf_status = spf_match.group(1)
            # Find the domain checked
            spf_domain_match = re.search(r'spf=[a-z]+\s+([^;]+)', auth_results)
            spf_detail = spf_domain_match.group(1).strip() if spf_domain_match else ''
            print(f"  SPF status: {spf_status}")
            print(f"  SPF detail: {spf_detail}")

            status_meaning = {
                'pass': 'SPF passed - sending IP is authorized',
                'fail': 'SPF failed - sending IP is NOT authorized by the domain\'s SPF record',
                'softfail': 'SPF softfail - sending IP is likely not authorized (domain owner unsure)',
                'neutral': 'SPF neutral - domain has no clear opinion on this IP',
                'none': 'No SPF record exists for the sending domain',
                'temperror': 'SPF temporary error (DNS issue)',
                'permerror': 'SPF permanent error (malformed SPF record)',
            }
            print(f"  Meaning: {status_meaning.get(spf_status, 'Unknown SPF status')}")
        else:
            print("  SPF status: not found in Authentication-Results")

        if dkim_match:
            dkim_status = dkim_match.group(1)
            dkim_domain_match = re.search(r'dkim=([a-z-]+)\s+([^;]+)', auth_results)
            dkim_detail = dkim_domain_match.group(1).strip() if dkim_domain_match else ''
            print(f"  DKIM status: {dkim_status}")
            print(f"  DKIM detail: {dkim_detail}")

        if dmarc_match:
            dmarc_status = dmarc_match.group(1)
            dmarc_detail_match = re.search(r'dmarc=[a-z]+\s+([^;]+)', auth_results)
            dmarc_detail = dmarc_detail_match.group(1).strip() if dmarc_detail_match else ''
            print(f"  DMARC status: {dmarc_status}")
            print(f"  DMARC detail: {dmarc_detail}")

    # ========================================
    # WHY IS SPF FAILING?
    # ========================================
    print(f"\n--- WHY SPF IS FAILING ---")

    if isinstance(spf_record, list) or spf_record in ['No TXT records found', 'NXDOMAIN - domain does not exist']:
        print("  The sending domain has NO SPF record (no TXT record with v=spf1).")
        print("  This means the domain has not published any authorization for sending mail.")
        print("  Depending on your mail server's configuration, this may be treated as")
        print("  'spf=none' (no opinion) or 'spf=fail' (not authorized).")
    elif isinstance(spf_record, str) and not spf_record.startswith('v=spf1'):
        print(f"  DNS lookup issue: {spf_record}")
    elif isinstance(spf_record, str) and spf_record.startswith('v=spf1'):
        print(f"  The domain HAS an SPF record: {spf_record}")
        print(f"  But the sending IP ({sender_ip}) is NOT listed as authorized in that record.")
        print(f"  This is a genuine SPF failure - the sending server is not authorized by the domain owner.")
        print()
        print(f"  Common reasons:")
        print(f"    1. The domain owner hasn't added the sending server's IP to their SPF record")
        print(f"    2. The email is genuinely spoofed (someone pretending to be this domain)")
        print(f"    3. The domain uses a third-party mail service that isn't listed in SPF")
        print(f"    4. The Return-Path domain differs from the From domain (mailing list issue)")

        # Check for domain mismatch
        if return_path and envelope_sender:
            envelope_domain = extract_domain(envelope_sender)
            if envelope_domain != from_domain:
                print(f"\n  NOTE: Return-Path domain ({envelope_domain}) differs from From domain ({from_domain})")
                print(f"  SPF checks the Return-Path domain, not the From domain.")
                print(f"  The SPF record for '{envelope_domain}' does not authorize IP {sender_ip}.")

    # ========================================
    # SUMMARY
    # ========================================
    print(f"\n--- SUMMARY ---")
    spf_from_auth = re.search(r'spf=([a-z]+)', auth_results)
    if spf_from_auth:
        print(f"  Your mail server reports SPF as: {spf_from_auth.group(1)}")
    dkim_from_auth = re.search(r'dkim=([a-z-]+)', auth_results)
    if dkim_from_auth:
        dkim_val = dkim_from_auth.group(1)
        print(f"  Your mail server reports DKIM as: {dkim_val}")
        if dkim_val == 'pass':
            print(f"  DKIM is valid, so the email content hasn't been tampered with")
            print(f"  and the domain has cryptographically signed this email.")

    print()
    print_separator()


def main():
    parser = argparse.ArgumentParser(
        description='Find an email and diagnose its SPF status.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --sender user@example.com --subject "Invoice"
  %(prog)s --sender user@example.com --subject "Invoice" --inbox primary_email
  %(prog)s --sender user@example.com --message-id "<abc123@mail.example.com>"
  %(prog)s --sender user@example.com --subject "Order" --config ~/.emaillm.json
        """
    )
    parser.add_argument('--sender', required=True,
                        help='Sender email address to search for')
    parser.add_argument('--subject', default=None,
                        help='Partial subject line to match')
    parser.add_argument('--message-id', default=None,
                        help='Message-ID to search for exactly')
    parser.add_argument('--inbox', default=None,
                        help='Inbox name from config (defaults to first inbox)')
    parser.add_argument('--config', default=os.environ.get(
        'EMAILLM_CONFIG', os.path.expanduser('~/.emaillm.json')),
                        help='Path to emaillm config file')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose logging')

    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format='%(asctime)s - %(levelname)s - %(message)s')

    # Load config
    try:
        config = load_config(args.config)
    except Exception as e:
        print(f"Error loading config: {e}")
        sys.exit(1)

    # Find inbox config
    try:
        inbox_cfg = find_inbox_config(config, args.inbox)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

    print(f"Using inbox: {inbox_cfg['name']}")
    print(f"Searching for sender: {args.sender}")
    if args.subject:
        print(f"Subject contains: {args.subject}")
    if args.message_id:
        print(f"Message-ID: {args.message_id}")
    print()

    diagnose_email(config, inbox_cfg, args.sender, args.subject, args.message_id)


if __name__ == "__main__":
    main()
