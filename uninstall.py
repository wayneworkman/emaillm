#!/usr/bin/env python3
"""
EmailLM Uninstaller

Safely removes all EmailLM components:
- Cron jobs
- Configuration files
- Log files
- PID files
- Password files (optional)
"""

import os
import subprocess
import sys
from pathlib import Path


def print_header(text: str):
    """Print a formatted header."""
    print(f"\n{'='*60}")
    print(f" {text}")
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


def print_error(text: str):
    """Print an error message."""
    print(f"  ❌ {text}")


def confirm_action(prompt: str, default: bool = False) -> bool:
    """Ask user for confirmation."""
    default_str = "y/N" if not default else "Y/n"
    response = input(f"{prompt} [{default_str}]: ").strip().lower()
    
    if not response:
        return default
    
    return response in ("y", "yes")


def get_cron_entries():
    """Get current crontab entries."""
    try:
        result = subprocess.run(
            ["crontab", "-l"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            return result.stdout.splitlines()
        elif result.returncode == 1:  # No crontab installed
            return []
        else:
            raise Exception(result.stderr)
    except Exception as e:
        print_error(f"Failed to read crontab: {e}")
        return []


def remove_cron_job():
    """Remove EmailLM cron job if it exists."""
    print_header("Checking for Cron Job")
    
    try:
        result = subprocess.run(
            ["crontab", "-l"],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 1:  # No crontab
            print_info("No crontab found")
            return True
        
        cron_entries = result.stdout.splitlines()
        emaillm_entries = [line for line in cron_entries if "emaillm" in line.lower()]
        
        if not emaillm_entries:
            print_info("No EmailLM cron job found")
            return True
        
        print_info("Found EmailLM cron job(s):")
        for entry in emaillm_entries:
            print(f"    {entry}")
        
        if not confirm_action("Remove EmailLM cron job(s)?", default=True):
            print_warning("Cron job removal skipped")
            return True
        
        # Remove EmailLM entries
        new_entries = [line for line in cron_entries if "emaillm" not in line.lower()]
        
        if new_entries:
            # Write remaining entries back
            result = subprocess.run(
                ["crontab"],
                input="\n".join(new_entries) + "\n",
                capture_output=True,
                text=True,
                timeout=10
            )
        else:
            # Remove crontab entirely
            result = subprocess.run(
                ["crontab", "-r"],
                capture_output=True,
                text=True,
                timeout=10
            )
        
        if result.returncode == 0:
            print_success("Cron job removed")
            return True
        else:
            print_error(f"Failed to remove cron job: {result.stderr}")
            return False
    
    except Exception as e:
        print_error(f"Error removing cron job: {e}")
        return False


def remove_config_file():
    """Remove configuration file."""
    print_header("Removing Configuration File")
    
    # Check EMAILLM_CONFIG env var first
    config_path = os.environ.get("EMAILLM_CONFIG")
    
    if not config_path:
        # Default location
        config_path = Path.home() / ".emaillm.json"
    
    config_path = Path(config_path).expanduser()
    
    if not config_path.exists():
        print_info(f"No config file found at {config_path}")
        return True
    
    print_info(f"Config file: {config_path}")
    
    if confirm_action("Remove config file?", default=True):
        try:
            config_path.unlink()
            print_success("Config file removed")
            return True
        except Exception as e:
            print_error(f"Failed to remove config file: {e}")
            return False
    else:
        print_warning("Config file removal skipped")
        return True


def remove_log_file():
    """Remove log file."""
    print_header("Removing Log File")
    
    # Default log location
    log_path = Path.home() / ".local/share/emaillm/emaillm.log"
    
    # Try to read config to get actual log path
    config_path = Path.home() / ".emaillm.json"
    if config_path.exists():
        try:
            import json
            with open(config_path) as f:
                config = json.load(f)
                if "runtime" in config and "log_file" in config["runtime"]:
                    log_path = Path(config["runtime"]["log_file"]).expanduser()
        except Exception:
            pass  # Use default path
    
    if not log_path.exists():
        print_info(f"No log file found at {log_path}")
        return True
    
    print_info(f"Log file: {log_path}")
    
    if confirm_action("Remove log file?", default=True):
        try:
            log_path.unlink()
            print_success("Log file removed")
            
            # Also remove parent directory if empty
            try:
                log_path.rmdir()  # Will fail if not empty
                print_success(f"Empty directory {log_path.parent} removed")
            except OSError:
                pass  # Directory not empty, that's fine
            
            return True
        except Exception as e:
            print_error(f"Failed to remove log file: {e}")
            return False
    else:
        print_warning("Log file removal skipped")
        return True


def remove_pid_file():
    """Remove PID file."""
    print_header("Removing PID File")
    
    # Default PID location
    pid_path = Path.home() / ".local/state/emaillm.pid"
    
    # Try to read config to get actual PID path
    config_path = Path.home() / ".emaillm.json"
    if config_path.exists():
        try:
            import json
            with open(config_path) as f:
                config = json.load(f)
                if "runtime" in config and "pid_file" in config["runtime"]:
                    pid_path = Path(config["runtime"]["pid_file"]).expanduser()
        except Exception:
            pass  # Use default path
    
    if not pid_path.exists():
        print_info(f"No PID file found at {pid_path}")
        return True
    
    print_info(f"PID file: {pid_path}")
    
    if confirm_action("Remove PID file?", default=True):
        try:
            pid_path.unlink()
            print_success("PID file removed")
            return True
        except Exception as e:
            print_error(f"Failed to remove PID file: {e}")
            return False
    else:
        print_warning("PID file removal skipped")
        return True


def remove_password_file():
    """Remove KeePassXC password file."""
    print_header("Removing KeePassXC Password File")
    
    # Default password file location
    password_path = Path.home() / ".keepassxc_password"
    
    # Try to read config to get actual password file path
    config_path = Path.home() / ".emaillm.json"
    if config_path.exists():
        try:
            import json
            with open(config_path) as f:
                config = json.load(f)
                if "keepassxc" in config and "password_file" in config["keepassxc"]:
                    password_path = Path(config["keepassxc"]["password_file"]).expanduser()
        except Exception:
            pass  # Use default path
    
    if not password_path.exists():
        print_info(f"No password file found at {password_path}")
        return True
    
    print_info(f"Password file: {password_path}")
    print_warning("⚠️  WARNING: This file contains your KeePassXC database password!")
    print_warning("⚠️  Only remove this if you created it specifically for EmailLM.")
    print_warning("⚠️  If this password is used by other KeePassXC automations, DO NOT remove it.")
    
    if not confirm_action("Remove password file?", default=False):
        print_warning("Password file removal skipped")
        return True
    
    try:
        password_path.unlink()
        print_success("Password file removed")
        return True
    except Exception as e:
        print_error(f"Failed to remove password file: {e}")
        return False


def remove_python_packages():
    """Optionally uninstall Python packages."""
    print_header("Python Package Cleanup")
    
    print_info("EmailLM uses these packages:")
    print_info("  - requests")
    print_info("  - pyspf")
    print_info("  - dnspython")
    print_info("  - tldextract")
    
    print_warning("Note: These packages may be used by other projects.")
    
    if not confirm_action("Uninstall EmailLM Python packages?", default=False):
        print_warning("Package uninstallation skipped")
        return True
    
    packages = ["requests", "pyspf", "dnspython", "tldextract"]
    success = True
    
    for package in packages:
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "uninstall", "-y", package],
                capture_output=True,
                text=True,
                timeout=30
            )
            if result.returncode == 0:
                print_success(f"Uninstalled {package}")
            else:
                print_warning(f"Failed to uninstall {package} (may not be installed)")
        except Exception as e:
            print_error(f"Error uninstalling {package}: {e}")
            success = False
    
    return success


def cleanup_imap_folders():
    """Optionally clean up IMAP folders created by EmailLM."""
    print_header("IMAP Folder Cleanup")
    
    print_warning("⚠️  WARNING: This would delete folders from your email account(s).")
    print_warning("⚠️  EmailLM creates folders like: Spam, Phishing_Attempts, Important,")
    print_warning("⚠️  Promotions, Transactions, Regular, Prompt_Attacks")
    print_warning("⚠️  These folders may contain emails you want to keep!")
    print_info("It's recommended to manually review and delete these folders in your email client.")
    
    if not confirm_action("Do you really want to attempt IMAP folder cleanup?", default=False):
        print_warning("IMAP folder cleanup skipped (recommended)")
        print_info("Please manually delete EmailLM folders from your email accounts.")
        return True
    
    print_error("IMAP folder cleanup is not implemented for safety reasons.")
    print_info("Please manually delete the following folders from your email accounts:")
    print_info("  - Spam")
    print_info("  - Phishing_Attempts")
    print_info("  - Important")
    print_info("  - Promotions")
    print_info("  - Transactions")
    print_info("  - Regular")
    print_info("  - Prompt_Attacks")
    
    return True


def main():
    """Main uninstaller entry point."""
    print_header("EmailLM Uninstaller")
    
    print_info("This script will remove all EmailLM components from your system.")
    print_info("Review each step carefully before confirming.\n")
    
    if not confirm_action("Continue with uninstallation?", default=True):
        print_info("Uninstallation cancelled")
        sys.exit(0)
    
    results = []
    
    # Remove components in safe order
    results.append(("Cron Job", remove_cron_job()))
    results.append(("Configuration File", remove_config_file()))
    results.append(("Log File", remove_log_file()))
    results.append(("PID File", remove_pid_file()))
    results.append(("Password File", remove_password_file()))
    results.append(("Python Packages", remove_python_packages()))
    results.append(("IMAP Folders", cleanup_imap_folders()))
    
    # Summary
    print_header("Uninstallation Summary")
    
    all_success = all(result for _, result in results)
    
    for component, success in results:
        status = "✅ Done" if success else "❌ Failed"
        print(f"  {status} - {component}")
    
    if all_success:
        print("\n🎉 EmailLM has been successfully uninstalled!")
    else:
        print("\n⚠️  Uninstallation completed with some issues.")
        print("   Please review the errors above and clean up manually if needed.")
    
    print("\nIf you want to reinstall EmailLM in the future:")
    print("  1. Clone the repository")
    print("  2. Run: pip install -r requirements.txt")
    print("  3. Run: python setup.py")
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nUninstallation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)
