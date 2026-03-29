#!/usr/bin/env python3
"""
EmailLM Setup Script

Interactive onboarding to configure EmailLM:
- Collects KeePassXC and vLLM settings
- Creates ~/.emaillm.json
- Creates KeePassXC password file
- Optionally sets up cron job
"""

import json
import os
import subprocess
import sys


# Default folder descriptions (from emaillm.py prompts)
DEFAULT_FOLDER_CONFIGS = {
    'spam': {
        'folder_name': 'Spam',
        'description': 'Unsolicited bulk emails, scams, fake offers, suspicious content'
    },
    'phishing': {
        'folder_name': 'Phishing_Attempts',
        'description': 'Attempts to steal credentials, fake login pages, urgent security alerts, requests for sensitive info'
    },
    'important': {
        'folder_name': 'Important',
        'description': 'Time-sensitive, critical business communications, priority messages from known contacts'
    },
    'promotion': {
        'folder_name': 'Promotions',
        'description': 'Marketing emails, newsletters, sales offers, product updates (legitimate)'
    },
    'transaction': {
        'folder_name': 'Transactions',
        'description': 'Orders, invoices, receipts, billing statements, purchase confirmations, shipping notifications, delivery updates, tracking information, payment confirmations'
    },
    'regular': {
        'folder_name': 'Regular',
        'description': 'Normal correspondence, non-urgent communications, general information'
    },
    'prompt_attack': {
        'folder_name': 'Prompt_Attacks',
        'file': 'prompts/prompt_injection.txt'
    }
}

# Default mailer domains (from emaillm.py)
DEFAULT_MAILER_DOMAINS = [
    'gmail.com',
    'google.com',
    'googlemail.com',
    'outlook.com',
    'hotmail.com',
    'live.com',
    'msn.com',
    'yahoo.com',
    'yahoo.co.uk',
    'yahoo.fr',
    'yahoo.de',
    'aol.com',
    'icloud.com',
    'me.com',
    'mac.com',
    'mailgun.org',
    'sendgrid.net',
    'amazonses.com',
    'ses.amazonaws.com',
    'mailchimp.com',
    'mandrillapp.com',
    'postmarkapp.com',
    'sparkpost.com',
    'sendinblue.com',
    'mailjet.com',
    'zendesk.com',
    'intercom.io',
    'salesforce.com',
    'stripe.com',
    'paypal.com',
    'squareup.com'
]


def print_header(text: str):
    """Print a formatted header."""
    print(f"\n{'='*60}")
    print(f"  {text}")
    print(f"{'='*60}\n")


def print_info(text: str):
    """Print an info message."""
    print(f"  ℹ️  {text}")


def print_success(text: str):
    """Print a success message."""
    print(f"  ✅ {text}")


def print_warning(text: str):
    """Print a warning message."""
    print(f"  ⚠️  {text}")


def get_input(prompt: str, default: str = None) -> str:
    """Get user input with optional default."""
    if default:
        response = input(f"{prompt} [{default}]: ").strip()
        return response if response else default
    return input(f"{prompt}: ").strip()


def get_bool_input(prompt: str, default: bool = True) -> bool:
    """Get yes/no input."""
    default_str = "Y/n" if default else "y/N"
    response = input(f"{prompt} [{default_str}]: ").strip().lower()
    if not response:
        return default
    return response in ('y', 'yes')


def get_int_input(prompt: str, default: int, min_val: int = None, max_val: int = None) -> int:
    """Get integer input with validation."""
    while True:
        response = input(f"{prompt} [{default}]: ").strip()
        if not response:
            return default
        try:
            value = int(response)
            if min_val is not None and value < min_val:
                print(f"  ⚠️  Please enter a value >= {min_val}")
                continue
            if max_val is not None and value > max_val:
                print(f"  ⚠️  Please enter a value <= {max_val}")
                continue
            return value
        except ValueError:
            print("  ⚠️  Please enter a valid number")


def get_selection(prompt: str, options: list, default_index: int = 0) -> tuple[int, str]:
    """Get user selection from a list of options."""
    print(f"\n{prompt}")
    for i, option in enumerate(options, 1):
        default_marker = " ← default" if i == default_index + 1 else ""
        print(f"  {i}. {option}{default_marker}")
    
    while True:
        response = input(f"\nSelect option [1-{len(options)}]: ").strip()
        try:
            index = int(response) - 1
            if 0 <= index < len(options):
                return index, options[index]
            print(f"  ⚠️  Please enter a number between 1 and {len(options)}")
        except ValueError:
            print("  ⚠️  Please enter a valid number")


def expand_path(path: str) -> str:
    """Expand ~ to home directory."""
    return os.path.expanduser(path)


def check_keepassxc_cli() -> bool:
    """Check if keepassxc-cli is installed and accessible.
    
    Returns:
        True if keepassxc-cli is found in PATH, False otherwise.
    """
    result = subprocess.run(['which', 'keepassxc-cli'], capture_output=True)
    if result.returncode != 0:
        print_warning("keepassxc-cli not found in PATH!")
        print_info("")
        print_info("KeePassXC CLI is required for EmailLM to retrieve email credentials.")
        print_info("")
        print_info("Installation instructions:")
        print_info("  https://github.com/keepassxreboot/keepassxc")
        print_info("")
        print_info("Quick install commands:")
        print_info("  Debian/Ubuntu: sudo apt install keepassxc-cli")
        print_info("  Fedora:        sudo dnf install keepassxc-cli")
        print_info("  Arch Linux:    sudo pacman -S keepassxc")
        print_info("  macOS (Homebrew): brew install keepassxc")
        print_info("")
        return False
    
    # Additional check: verify the CLI actually works
    try:
        result = subprocess.run(['keepassxc-cli', '--version'], capture_output=True, timeout=5)
        if result.returncode == 0:
            version = result.stdout.decode().strip()
            print_success(f"keepassxc-cli found: {version}")
            return True
        else:
            print_warning("keepassxc-cli found but returned an error")
            return False
    except subprocess.TimeoutExpired:
        print_warning("keepassxc-cli found but timed out")
        return False
    except Exception as e:
        print_warning(f"keepassxc-cli found but failed to run: {e}")
        return False


def check_vllm_running(base_url: str):
    """Check if vLLM is running and accessible."""
    import requests
    try:
        response = requests.get(f"{base_url}/models", timeout=5)
        if response.status_code == 200:
            return True
    except requests.RequestException:
        pass
    return False


def create_cron_entry(interval_minutes: int, script_path: str, log_path: str, python_path: str):
    """Create a cron entry for the specified interval."""
    if interval_minutes == 5:
        cron_line = f"*/5 * * * * cd {os.path.dirname(script_path)} && {python_path} emaillm.py >> {log_path} 2>&1"
    elif interval_minutes == 15:
        cron_line = f"*/15 * * * * cd {os.path.dirname(script_path)} && {python_path} emaillm.py >> {log_path} 2>&1"
    elif interval_minutes == 30:
        cron_line = f"*/30 * * * * cd {os.path.dirname(script_path)} && {python_path} emaillm.py >> {log_path} 2>&1"
    elif interval_minutes == 60:
        cron_line = f"0 * * * * cd {os.path.dirname(script_path)} && {python_path} emaillm.py >> {log_path} 2>&1"
    elif interval_minutes == 240:
        cron_line = f"0 */4 * * * cd {os.path.dirname(script_path)} && {python_path} emaillm.py >> {log_path} 2>&1"
    else:
        cron_line = f"*/{interval_minutes} * * * * cd {os.path.dirname(script_path)} && {python_path} emaillm.py >> {log_path} 2>&1"
    
    return cron_line


def add_to_crontab(cron_line: str):
    """Add cron entry to user's crontab."""
    # Get current crontab
    result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
    current_crontab = result.stdout if result.returncode == 0 else ""
    
    # Check if entry already exists
    if 'emaillm.py' in current_crontab:
        print_warning("An emaillm.py cron entry already exists!")
        if get_bool_input("Do you want to replace it?", default=False):
            # Remove existing entries
            lines = [line for line in current_crontab.split('\n') if 'emaillm.py' not in line]
            current_crontab = '\n'.join(lines)
        else:
            return False
    
    # Add new entry
    new_crontab = current_crontab.strip() + "\n" + cron_line + "\n"
    
    # Write to crontab
    result = subprocess.run(['crontab', '-'], input=new_crontab, capture_output=True, text=True)
    if result.returncode == 0:
        return True
    else:
        print_warning(f"Failed to update crontab: {result.stderr}")
        return False


def main():
    print_header("EmailLM Setup")
    print_info("This script will help you configure EmailLM.")
    print_info("You'll need your KeePassXC database path and password.")
    
    if not get_bool_input("\nContinue with setup?", default=True):
        print("\nSetup cancelled.")
        sys.exit(0)
    
    # Check prerequisites
    print_header("Checking Prerequisites")
    
    if not check_keepassxc_cli():
        if not get_bool_input("Do you want to exit and install keepassxc-cli first?", default=True):
            print_warning("Continuing without keepassxc-cli - this will likely fail!")
    
    # KeePassXC Configuration
    print_header("KeePassXC Configuration")
    
    database_path = get_input(
        "Path to your KeePassXC database file",
        default=os.path.expanduser("~/.local/share/KeePassXC/mydatabase.kdbx")
    )
    database_path = expand_path(database_path)
    
    if not os.path.exists(database_path):
        print_warning(f"Database file not found: {database_path}")
        if not get_bool_input("Continue anyway?", default=False):
            print("\nSetup cancelled.")
            sys.exit(1)
    
    password_file = get_input(
        "Path to store KeePassXC password file",
        default=os.path.expanduser("~/.keepassxc_password")
    )
    password_file = expand_path(password_file)
    
    # Get KeePassXC password
    print_info("Enter your KeePassXC database password (not stored in config)")
    import getpass
    kpx_password = getpass.getpass("KeePassXC password: ")
    kpx_password_confirm = getpass.getpass("Confirm password: ")
    
    if kpx_password != kpx_password_confirm:
        print_warning("Passwords do not match!")
        sys.exit(1)
    
    # Write password file securely (avoid race condition)
    try:
        # Use os.open with explicit flags to create file with restricted permissions from the start
        fd = os.open(password_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, 'w') as f:
                f.write(kpx_password.strip())
        except:
            # If we get here, file was created but write failed, clean up
            if os.path.exists(password_file):
                os.unlink(password_file)
            raise
        print_success(f"Password file created: {password_file}")
    except FileExistsError:
        print_warning(f"Password file already exists: {password_file}")
        if get_bool_input("Overwrite existing file?", default=False):
            os.unlink(password_file)
            # Retry with same logic
            fd = os.open(password_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(fd, 'w') as f:
                    f.write(kpx_password.strip())
                print_success(f"Password file created: {password_file}")
            except Exception as e2:
                print_warning(f"Failed to create password file: {e2}")
                sys.exit(1)
        else:
            print("\nSetup cancelled.")
            sys.exit(1)
    except Exception as e:
        print_warning(f"Failed to create password file: {e}")
        sys.exit(1)
    
    # Detect Python path
    print_header("Python Configuration")
    
    # Detect the Python executable being used to run this script
    detected_python = sys.executable
    
    # Ask user if they want to use the detected Python path
    python_path = get_input(
        "Python executable path for cron job",
        default=detected_python
    )
    
    # Verify the Python path exists
    if not os.path.exists(python_path):
        print_warning(f"Python path not found: {python_path}")
        if not get_bool_input("Continue anyway?", default=False):
            print("\nSetup cancelled.")
            sys.exit(1)
    else:
        print_success(f"Python path verified: {python_path}")
    
    # vLLM Configuration
    print_header("vLLM Configuration")
    
    vllm_url = get_input(
        "vLLM base URL",
        default="http://localhost:8000/v1"
    )
    
    if check_vllm_running(vllm_url):
        print_success("vLLM is running and accessible!")
    else:
        print_warning("Could not connect to vLLM at this URL")
        print_info("Make sure vLLM is running before using the spam filter")
        if not get_bool_input("Continue anyway?", default=True):
            print("\nSetup cancelled.")
            sys.exit(1)
    
    vllm_temp = get_input("vLLM temperature (higher = more creative, lower = more deterministic)", default="0.7")
    vllm_max_tokens = get_int_input("vLLM max tokens (higher = more context for large emails)", default=10000, min_val=100)
    vllm_enable_thinking = get_bool_input("Enable vLLM thinking mode (slower but may improve accuracy)?", default=False)
    
    # vLLM API Key (optional)
    print_info("If your vLLM endpoint requires authentication, provide the API key below")
    vllm_api_key = get_input("vLLM API key (leave empty if not required)", default="")
    if not vllm_api_key:
        vllm_api_key = None  # Will be stored as null in JSON
        print_info("API key not configured - vLLM calls will not include Authorization header")
    else:
        print_success("API key configured")
    
    # Folder configuration
    print_header("Folder Configuration")
    print_info("Configure folder names and descriptions for each category")
    print_info("Descriptions are used in the AI classification prompt\n")
    
    folder_configs = {}
    
    for category, default_config in DEFAULT_FOLDER_CONFIGS.items():
        print(f"--- {category.upper()} ---")
        
        folder_name = get_input(
            f"Folder name for {category}",
            default=default_config['folder_name']
        )
        
        # For prompt_attack, use file; for others, use description
        if category == 'prompt_attack':
            # Check if file exists
            file_path = default_config.get('file', 'prompts/prompt_injection.txt')
            if os.path.exists(file_path):
                print_info(f"Using existing prompt file: {file_path}")
                use_file = get_bool_input("Use this file?", default=True)
                if use_file:
                    folder_configs[category] = {
                        'folder_name': folder_name,
                        'file': file_path
                    }
                    continue
            # If not using file, ask for description (fallback)
            print_info("Note: prompt_attack typically uses a file for the long prompt")
            use_description = get_bool_input("Use inline description instead?", default=False)
            if use_description:
                description = get_input(
                    f"Description for {category}",
                    default="Detected prompt injection or AI manipulation attempts"
                )
                folder_configs[category] = {
                    'folder_name': folder_name,
                    'description': description
                }
            else:
                # Use the default file
                folder_configs[category] = {
                    'folder_name': folder_name,
                    'file': file_path
                }
        else:
            # Regular categories use description
            description = get_input(
                f"Description for {category} (used in AI prompt)",
                default=default_config['description']
            )
            folder_configs[category] = {
                'folder_name': folder_name,
                'description': description
            }
    
    print()
    
    processing_timeout = get_int_input("Processing timeout (seconds)", default=30, min_val=10)
    
    # Global allowlist
    print_header("Global Allowlist (Optional)")
    print_info("These senders will skip spam classification")
    
    allowlist_emails = []
    allowlist_domains = []
    
    if get_bool_input("Add allowlisted email addresses?", default=False):
        print_info("Enter email addresses one per line, empty line to finish")
        while True:
            email = input("  Email: ").strip()
            if not email:
                break
            allowlist_emails.append(email)
    
    if get_bool_input("Add allowlisted domains?", default=False):
        print_info("Enter domains one per line, empty line to finish")
        while True:
            domain = input("  Domain: ").strip()
            if not domain:
                break
            allowlist_domains.append(domain)
    
    # Inbox configuration
    print_header("Inbox Configuration")
    
    inboxes = []
    inbox_count = 0
    
    while True:
        inbox_count += 1
        print(f"\n--- Inbox #{inbox_count} ---")
        
        inbox_name = get_input("Inbox name (e.g., primary_email)", default=f"inbox_{inbox_count}")
        
        kpx_entry = get_input(
            "KeePassXC entry name for this inbox",
            default="Email Account"
        )
        
        imap_host = get_input("IMAP server hostname (e.g., imap.gmail.com)")
        imap_port = get_int_input("IMAP port", default=993, min_val=1, max_val=65535)
        
        # Per-inbox allowlist
        inbox_allowlist_emails = []
        inbox_allowlist_domains = []
        
        if get_bool_input("Add inbox-specific allowlisted emails?", default=False):
            print_info("Enter email addresses one per line, empty line to finish")
            while True:
                email = input("  Email: ").strip()
                if not email:
                    break
                inbox_allowlist_emails.append(email)
        
        if get_bool_input("Add inbox-specific allowlisted domains?", default=False):
            print_info("Enter domains one per line, empty line to finish")
            while True:
                domain = input("  Domain: ").strip()
                if not domain:
                    break
                inbox_allowlist_domains.append(domain)
        
        inboxes.append({
            "name": inbox_name,
            "keepassxc_entry_name": kpx_entry,
            "imap": {
                "host": imap_host,
                "port": imap_port
            },
            "allowlist": {
                "email_addresses": inbox_allowlist_emails,
                "domains": inbox_allowlist_domains
            }
        })
        
        if not get_bool_input("Add another inbox?", default=False):
            break
    
    # Cron configuration
    print_header("Cron Schedule Configuration")
    
    interval_options = [
        "Every 5 minutes",
        "Every 15 minutes",
        "Every 30 minutes",
        "Every 1 hour",
        "Every 4 hours"
    ]
    
    interval_index, interval_choice = get_selection(
        "How often should the spam filter run?",
        interval_options,
        default_index=2  # 30 minutes default
    )
    
    interval_map = {0: 5, 1: 15, 2: 30, 3: 60, 4: 240}
    interval_minutes = interval_map[interval_index]
    
    # Runtime configuration
    print_header("Runtime Configuration")
    
    pid_file = get_input(
        "PID file path",
        default=os.path.expanduser("~/.local/state/emaillm.pid")
    )
    
    log_file = get_input(
        "Log file path",
        default=os.path.expanduser("~/.local/share/emaillm/emaillm.log")
    )
    
    # Generate config
    print_header("Generating Configuration")
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.expanduser("~/.emaillm.json")
    
    config = {
        "keepassxc": {
            "database_path": database_path,
            "password_file": password_file
        },
        "vllm": {
            "base_url": vllm_url,
            "temperature": float(vllm_temp),
            "max_tokens": vllm_max_tokens,
            "enable_thinking": vllm_enable_thinking,
            "api_key": vllm_api_key
        },
        "spam": {
            "processing_timeout_seconds": processing_timeout
        },
        "folders": folder_configs,
        "global_allowlist": {
            "email_addresses": allowlist_emails,
            "domains": allowlist_domains
        },
        "mailers": {
            "domains": DEFAULT_MAILER_DOMAINS
        },
        "inboxes": inboxes,
        "runtime": {
            "pid_file": pid_file,
            "log_file": log_file
        }
    }
    
    try:
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=4)
        print_success(f"Config file created: {config_path}")
    except Exception as e:
        print_warning(f"Failed to create config file: {e}")
        sys.exit(1)
    
    # Setup cron
    print_header("Cron Setup")
    
    # For cron, use stdout redirection - file logging is handled by the script
    cron_line = create_cron_entry(interval_minutes, os.path.join(script_dir, "emaillm.py"), 
                                   "/dev/null", python_path)
    
    print_info("Cron entry that will be added:")
    print(f"  {cron_line}")
    
    if get_bool_input("\nAdd this to your crontab?", default=True):
        if add_to_crontab(cron_line):
            print_success("Cron job added successfully!")
            print_info(f"The spam filter will run {interval_choice}")
        else:
            print_warning("Cron job not added. You can add it manually:")
            print("  crontab -e")
            print("  # Add this line:")
            print(f"  {cron_line}")
    else:
        print_info("To add the cron job later:")
        print("  crontab -e")
        print("  # Add this line:")
        print(f"  {cron_line}")
    
    # Summary
    print_header("Setup Complete!")
    print_success("Configuration summary:")
    print(f"  • KeePassXC database: {database_path}")
    print(f"  • Password file: {password_file}")
    print(f"  • vLLM URL: {vllm_url}")
    print(f"  • vLLM thinking mode: {'enabled' if vllm_enable_thinking else 'disabled'}")
    print(f"  • vLLM API key: {'configured' if vllm_api_key else 'not configured'}")
    print(f"  • Folders configured: {len(folder_configs)}")
    print(f"  • Inboxes configured: {len(inboxes)}")
    print(f"  • Global allowlist: {len(allowlist_emails)} emails, {len(allowlist_domains)} domains")
    print(f"  • PID file: {pid_file}")
    print(f"  • Log file: {log_file}")
    print(f"  • Schedule: {interval_choice}")
    
    print_info("\nNext steps:")
    print(f"  1. Review your config file: {config_path}")
    print(f"  2. Test EmailLM manually: {python_path} emaillm.py")
    print(f"  3. Check logs after running: {log_file}")
    
    print_info("\nKeePassXC entry requirements for each inbox:")
    print_info("  • Username field: Your email address")
    print_info("  • Password field: Your email password/app password")
    print_info("  • Custom field 'host': Your IMAP server")
    
    print("\n")


if __name__ == "__main__":
    main()
