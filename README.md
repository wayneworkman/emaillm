# EmailLM

Created by [Wayne Workman](https://github.com/wayneworkman)

[![Blog](https://img.shields.io/badge/Blog-wayne.theworkmans.us-blue)](https://wayne.theworkmans.us/)
[![GitHub](https://img.shields.io/badge/GitHub-wayneworkman-181717?logo=github)](https://github.com/wayneworkman)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Wayne_Workman-0077B5?logo=linkedin)](https://www.linkedin.com/in/wayne-workman-a8b37b353/)
[![SpinnyLights](https://img.shields.io/badge/SpinnyLights-wayneworkman-764ba2)](https://spinnylights.com/wayneworkman)

A Python script that retrieves emails via encrypted IMAP and classifies them using a vLLM endpoint. Features automatic spoof detection via DKIM/SPF validation and multi-category email organization.

## Features

- **Multiple Inbox Support**: Configure multiple email accounts with separate credentials
- **KeePassXC Integration**: Secure credential storage using `keepassxc-cli`
- **Prompt Injection Detection**: AI-powered detection of prompt injection attacks before classification
- **Authentication Validation**: Validates DKIM, SPF, and header consistency with lenient defaults
- **Dynamic Category Classification**: AI-powered categorization with fully configurable categories:
  - Each category has a customizable folder name and description
  - Descriptions are used in the AI prompt to guide classification
  - Supports both inline descriptions and external prompt files
  - Default categories: Spam, Phishing, Important, Promotions, Transactions, Regular
- **Automatic Folder Creation**: Creates all required folders if they don't exist
- **Hybrid Allow-list**: Global allow-list plus per-inbox additions with wildcard support (`*.domain.com`)
- **Processes All Inbox Emails**: Handles both read and unread emails
- **Newest First Processing**: Processes most recent emails first to avoid message ID shifting
- **Conversation Thread Detection**: Scans Sent folder to identify replies and ongoing conversations
- **Dynamic vLLM Model**: Automatically detects the current model served by vLLM
- **Configurable Email Limit**: Process only the latest N emails per run (default: 30)
- **Cron-Friendly**: Designed to run as a scheduled job with PID file protection
- **Flexible Configuration**: Config file location via environment variable (`EMAILLM_CONFIG`)
- **Dual Logging**: Console output (stdout) plus file logging with configurable paths

## Prerequisites

1. **Python 3.8+**
2. **KeePassXC** with `keepassxc-cli` installed
3. **vLLM** running (default: `http://localhost:8000`)
4. **IMAP access** to your email accounts (SSL/TLS on port 993)

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Ensure `keepassxc-cli` is in your PATH:
```bash
which keepassxc-cli
```

3. **Run the interactive setup script**:
```bash
python setup.py
```

   This will:
   - Check for `keepassxc-cli` installation
   - Collect your KeePassXC and vLLM settings
   - Create `~/.emaillm.json`
   - Create the KeePassXC password file with restricted permissions
   - Configure folder names and descriptions for each category
   - Set up global and per-inbox allowlists
   - Optionally set up the cron job

   **Manual setup**: See the sections below if you prefer to configure manually.

---

### Manual Setup (Alternative to setup.py)

3. Create your KeePassXC database entries for each email account. Each entry should have:
   - **Username field**: Your email address
   - **Password field**: Your email password/app password
   - **Custom field "host"**: Your IMAP server (e.g., `imap.gmail.com` or `mail.theworkmans.us`)
   - **Entry name**: Must match the `keepassxc_entry_name` in config (e.g., `personal`)

4. **Create a password file** for the KeePassXC database password:
```bash
echo 'your-database-password' > ~/.keepassxc_password
chmod 600 ~/.keepassxc_password  # Only readable by you
```

   The password file path is specified in `config.json` under `keepassxc.password_file`.

   **Important**: In KeePassXC, create a **custom field** named `host` (not `Hostname` or other variations) containing your IMAP server address.

## Configuration

### Configuration File Location

EmailLM looks for its configuration file in the following order:
1. Path specified by `EMAILLM_CONFIG` environment variable
2. Default location: `~/.emaillm.json`
3. Path specified via `--config` command line argument (overrides above)

**Example:**
```bash
# Set config location via environment variable
export EMAILLM_CONFIG=/etc/emaillm/config.json

# Or specify on command line
python emaillm.py --config /path/to/config.json
```

### Configuration File Structure

Copy `config.example.emaillm.json` to `~/.emaillm.json` and customize:

```json
{
    "keepassxc": {
        "database_path": "/home/user/.local/share/KeePassXC/mydatabase.kdbx",
        "password_file": "~/.keepassxc_password"
    },
    "vllm": {
        "base_url": "http://localhost:8000/v1",
        "temperature": 0.5,
        "max_tokens": 4096,
        "enable_thinking": false,
        "api_key": null
    },
    "spam": {
        "processing_timeout_seconds": 30,
        "max_emails_per_run": 30
    },
    "folders": {
        "spam": {
            "folder_name": "Spam",
            "description": "Unsolicited bulk emails, scams, fake offers, suspicious content"
        },
        "phishing": {
            "folder_name": "Phishing_Attempts",
            "description": "Attempts to steal credentials, fake login pages, urgent security alerts, requests for sensitive info"
        },
        "important": {
            "folder_name": "Important",
            "description": "Time-sensitive, critical business communications, priority messages from known contacts"
        },
        "promotion": {
            "folder_name": "Promotions",
            "description": "Marketing emails, newsletters, sales offers, product updates (legitimate)"
        },
        "transaction": {
            "folder_name": "Transactions",
            "description": "Orders, invoices, receipts, billing statements, purchase confirmations, shipping notifications, delivery updates, tracking information, payment confirmations"
        },
        "regular": {
            "folder_name": "Regular",
            "description": "Normal correspondence, non-urgent communications, general information"
        },
        "prompt_attack": {
            "folder_name": "Prompt_Attacks",
            "file": "prompts/prompt_injection.txt"
        }
    },
    "global_allowlist": {
        "email_addresses": [
            "trusted@example.com"
        ],
        "domains": [
            "mycompany.com",
            "*.trusted-partner.org"
        ]
    },
    "inboxes": [
        {
            "name": "primary_email",
            "keepassxc_entry_name": "Email - Primary Account",
            "imap": {
                "port": 993
            },
            "allowlist": {
                "email_addresses": ["boss@mycompany.com"],
                "domains": []
            }
        }
    ],
    "runtime": {
        "pid_file": "~/.local/state/emaillm.pid",
        "log_file": "~/.local/share/emaillm/emaillm.log"
    }
}
```

### Configuration Options

**vLLM Settings:**
- `base_url`: vLLM API endpoint (default: `http://localhost:8000/v1`)
- `temperature`: AI randomness (0.0-1.0, default: 0.1 - lower for more deterministic results)
- `max_tokens`: Maximum tokens for email content (default: 500, increase for longer emails)
- `enable_thinking`: Enable model thinking mode (default: false - disabled for faster responses)
- `api_key`: Optional Bearer token for vLLM authentication (default: null)

**EmailLM Settings:**
- `processing_timeout_seconds`: IMAP connection timeout (default: 30)
- `max_emails_per_run`: Maximum emails to process per run (default: 30)

**Runtime Settings:**
- `pid_file`: Path to PID file for preventing duplicate instances (default: `~/.local/state/emaillm.pid`)
- `log_file`: Path to log file (default: `~/.local/share/emaillm/emaillm.log`)

**Allowlist:**
- Supports exact email addresses: `user@example.com`
- Supports exact domains: `example.com` (matches `user@example.com` and `user@sub.example.com`)
- Supports wildcard subdomains: `*.example.com` (matches `user@sub.example.com` but not `user@example.com`)

## Usage

### Process all inboxes:
```bash
python emaillm.py
```

## Uninstallation

To remove EmailLM from your system, run the interactive uninstaller:

```bash
python uninstall.py
```

The uninstaller will:
- Remove the cron job (if configured)
- Delete the configuration file (`~/.emaillm.json`)
- Remove log files
- Clean up PID files
- Optionally remove the KeePassXC password file (with warning)
- Optionally uninstall Python packages (with warning)
- Provide instructions for manual IMAP folder cleanup

**Note**: The uninstaller will ask for confirmation before each destructive action. IMAP folders are not automatically deleted for safety - you should manually review and delete them from your email client.

### Process specific inbox:
```bash
python emaillm.py --inbox primary_email
```

### Use custom config:
```bash
python emaillm.py --config /path/to/config.json
```

### Verbose logging:
```bash
python emaillm.py -v
```

## Cron Setup

EmailLM handles its own file logging (configured in the `runtime.log_file` setting), so cron can simply redirect stdout to `/dev/null`:

```bash
*/15 * * * * cd /home/<username>/git/emaillm && python emaillm.py > /dev/null 2>&1
```

**Important**: 
- Ensure the password file path in config is accessible and has proper permissions (`chmod 600`)
- The script uses a PID file (configurable, default: `~/.local/state/emaillm.pid`) to prevent duplicate instances
- Logs are written to the file specified in `runtime.log_file` (default: `~/.local/share/emaillm/emaillm.log`)
- Console output (stdout) is also available for debugging

## How It Works

1. **Load Configuration**: Reads config from `~/.emaillm.json` (or `EMAILLM_CONFIG` env var)
2. **Configure Logging**: Sets up both console and file logging
3. **PID Check**: Creates PID file to prevent duplicate instances
4. **Credential Retrieval**: Fetches IMAP credentials from KeePassXC
5. **Email Retrieval**: Connects via IMAP SSL and fetches all emails in inbox (both read and unread)
6. **Folder Setup**: Creates all required folders if they don't exist
7. **Sent Folder Scan**: Extracts recipient email addresses and Message-IDs from Sent folder
8. **Email Processing** (newest first):
   - **Own Email Detection**: Moves emails from your own address to Important
   - **Authenticity Validation**:
     - DKIM signature verification
     - SPF record validation (lenient: softfail/neutral = pass)
     - Header consistency checks
     - **Failures = automatic spam** (unless allowlisted)
   - **Allow-list Check**: Trusted senders are moved to Regular folder
   - **Previously Contacted Check**: Emails from recipients in your Sent folder are marked as Important
   - **Conversation Thread Detection**: Checks In-Reply-To and References headers against Sent folder Message-IDs
   - **Prompt Injection Detection** (if configured):
     - Analyzes email content for prompt injection attacks
     - Detects attempts to manipulate AI instructions
     - **If unsafe = moved to Prompt_Attacks folder**
     - If safe = proceeds to classification
   - **AI Classification**: Sends email content (truncated to 10,000 chars) to vLLM for multi-category analysis
   - **Action**: Moves emails to appropriate folder based on classification
9. **Cleanup**: Expunges deleted messages and removes PID file

## vLLM Prompt Format

The script **dynamically builds the classification prompt** from your `folders` configuration. Each category's `description` field is used in the AI prompt to guide classification.

### For Email Classification:

The prompt includes all categories from your config (except `prompt_attack`):

```
Categories:
- spam: {your custom description}
- phishing: {your custom description}
- important: {your custom description}
- promotion: {your custom description}
- transaction: {your custom description}
- regular: {your custom description}

Format:
[Your detailed reasoning here]

##### {category_name}
```

The vLLM response should end with:
```
##### spam
```
or
```
##### phishing
```
etc.

### For Prompt Injection Detection:

The `prompt_attack` category can use either:
- `description`: Inline text (for short descriptions)
- `file`: Path to external file (recommended for long prompts, e.g., `prompts/prompt_injection.txt`)

The response should end with:
```
##### safe
```
or
```
##### unsafe
```

## Verbose Mode Output

When running with `-v` flag, the script outputs reasoning to stdout (not logged to file):

- **Prompt Injection Check**: Shows `[PROMPT ATTACK CHECK]` or `[PROMPT ATTACK DETECTION]` with reasoning
- **Email Classification**: Shows `[REASONING]` with classification and reasoning

This helps you understand why emails are classified or flagged without storing sensitive content in log files.

## Authentication Validation Details

The script uses **lenient defaults** to avoid false positives:

### DKIM Validation:
- Checks `Authentication-Results` header first (most reliable)
- If DKIM=pass: ✅ Valid
- If DKIM=fail: ❌ Invalid (spoofed unless allowlisted)
- If DKIM=none or unverifiable: ⚠️ Warns but passes (trusting server)

### SPF Validation:
- Checks `Authentication-Results` and `Received-SPF` headers
- If SPF=pass: ✅ Valid
- If SPF=fail: ❌ Invalid (spoofed unless allowlisted)
- If SPF=softfail or neutral: ✅ Passes (not treated as failure)
- If SPF=none: ✅ Passes (server didn't check, trusting server)
- Manual SPF check via `pyspf` as fallback (also lenient)

### Header Validation:
- Checks Return-Path and Sender headers against From address
- Allows known mailer domains (gmail.com, sendgrid.net, etc.)
- Logs warnings but doesn't mark as spoofed unless definitive mismatch

**Note**: Allowlisted senders still get validated but won't be marked as spam on failure.

## Security Considerations

- **Prompt Injection Detection**: All emails are scanned for prompt injection attempts before classification - failures are moved to `Prompt_Attacks` folder
- **Fail-Secure Design**: If prompt injection detection fails, emails are marked as unsafe by default
- **Authentication Validation**: DKIM/SPF failures automatically mark email as spam (unless allowlisted)
- **Allow-list Bypass**: Allowlisted senders still get validated but won't be marked as spam on failure
- **Encrypted Connections**: All IMAP connections use SSL/TLS
- **Credential Security**: KeePassXC password stored in a file with restricted permissions (600), email credentials in KeePassXC
- **PID File Protection**: Prevents duplicate instances from running simultaneously
- **Signal Handling**: Clean shutdown on SIGTERM/SIGINT removes PID file

## Logging

EmailLM uses dual logging:

- **Console output (stdout)**: Real-time progress and debug information (when using `-v`)
- **File logging**: Writes to the path specified in `runtime.log_file` (default: `~/.local/share/emaillm/emaillm.log`)
- **Sensitive data**: AI reasoning is logged to console only in verbose mode, not to files

**Note**: File logging requires write permissions to the log directory. If file logging fails, the script continues with console-only logging.

## Troubleshooting

### KeePassXC errors
- Verify `keepassxc-cli` is installed and in PATH
- Check database path is correct
- **Verify the custom field name is exactly `host`** (case-sensitive)
- Ensure entry names match exactly in config
- Verify password file exists and is readable (`ls -la ~/.keepassxc_password`)
- Test manually: `echo 'password' | keepassxc-cli show --all database entry`

### IMAP connection errors
- Check IMAP server hostname and port
- Verify credentials in KeePassXC
- For Gmail: Use app-specific passwords, not main password
- Ensure IMAP is enabled in email account settings
- Check `processing_timeout_seconds` is sufficient

### vLLM errors
- Verify vLLM is running: `curl http://localhost:8000/v1/models`
- Check model is loaded and responsive
- Adjust `max_tokens` if emails are too long (default: 500)
- Adjust `temperature` for classification consistency (default: 0.1 - lower for more deterministic results)
- Set `api_key` if your vLLM endpoint requires authentication
- vLLM requests have 600 second timeout for large emails

### Classification issues
- Enable verbose mode (`-v`) to see AI reasoning
- Adjust category descriptions in config for better accuracy
- Check that `prompt_attack` folder is configured if you want prompt injection detection
- Verify Sent folder is accessible for conversation thread detection

### Duplicate instance errors
- Script uses PID file (configurable in `runtime.pid_file`) to prevent duplicates
- If script crashes, manually remove PID file: `rm ~/.local/state/emaillm.pid (or your configured path)`
- Signal handlers clean up PID file on normal shutdown

### Logging errors
- Check that the log file directory exists and is writable
- Default location is `~/.local/share/emaillm/emaillm.log` - ensure `~/.local/share/emaillm/` directory exists
- Create directory if needed: `mkdir -p ~/.local/share/emaillm`
- Or use a custom location in config: `"log_file": "/custom/path/emaillm.log"`
- If file logging fails, console logging continues to work

## Testing

EmailLM includes a comprehensive test suite using pytest.

### Install Test Dependencies
```bash
pip install -r requirements.txt
```

### Run Tests
```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run with coverage report
pytest --cov=emaillm --cov-report=html
# Open htmlcov/index.html in browser to view coverage

# Run specific test file
pytest tests/test_config_validation.py

# Run tests matching a pattern
pytest -k "domain"  # Runs all tests with "domain" in name
```

### Test Coverage
The test suite aims for 80%+ code coverage. Coverage reports are generated in:
- `htmlcov/` - HTML report (browseable)
- `coverage.xml` - XML report (for CI/CD integration)

See `tests/README.md` for detailed testing documentation.

## License

MIT
