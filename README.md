# simple-dmarc-parser

A simple Python script to fetch, parse DMARC aggregate reports, monitor DNS records, and send email alerts.

## Features

* Fetch unread DMARC reports via IMAP (XML, `.xml.gz`, or `.zip` attachments)
* Parse DMARC records to check SPF and DKIM results
* Monitor DNS TXT records (DMARC, SPF, DKIM, BIMI)
* Send email notifications on failures or DNS changes
* Move processed emails to a designated folder

## Configuration

1. Copy and customize environment variables:

   ```bash
   cp env.example .env
   ```
2. Edit the `.env` file with your IMAP/SMTP credentials and settings.

3. Ensure the processed-folder called `Email-LOG-Processed` exists on your mail server (e.g., via a email client, webmail or the admin interface). The script moves processed messages to this IMAP folder.

### Key `.env` variables

| Variable           | Description                                                     |
| ------------------ | --------------------------------------------------------------- |
| `IMAP_HOST`        | IMAP server hostname                                            |
| `IMAP_PORT`        | IMAP SSL port (e.g., 993 for SSL/TLS)                                       |
| `IMAP_USER`        | IMAP username                                                   |
| `IMAP_PASS`        | IMAP password                                                   |
| `SOURCE_FOLDER`    | Folder to scan (e.g., `INBOX`)                                  |
| `PROCESSED_FOLDER` | Folder to move processed reports                                |
| `ALERT_EMAIL`      | Recipient address for alerts                                    |
| `SMTP_HOST`        | SMTP server hostname                                            |
| `SMTP_PORT`        | SMTP port (465 for SSL/TLS depending on the SMTP server)                                     |
| `SMTP_USER`        | SMTP username                                                   |
| `SMTP_PASS`        | SMTP password                                                   |
| `NOTIFY_ON_OK`     | `True` to notify on all-pass reports, `False` for failures only |

### `config.json`

Define expected DNS settings per domain:

```json
{
    "example.tdl": {
      "SPF": [
        "v=spf1 your spf record"
      ],
      "DKIM": {
        "default": [
          "v=DKIM1; very long public key"
        ]
      },
      "DMARC": [
        "v=DMARC1; your dmarc policy"
      ],
      "MTA-STS": {
        "version": "STSv1",
        "mode": "your",
        "mx": [
          "MTA-STS",
          "policy"
        ],
        "max_age": 604800
      },
      "TLS-RPT": [
        "v=TLSRPTv1; your tlsrpt rua record"
      ],
      "BIMI": [
        "v=BIMI1; your bimi record"
      ]
    }
  }
```

* `SPF`: list of allowed `v=spf1` records (empty accepts any pass)
* `DKIM`: list of selectors
* `DMARC`: expected policy (`null` to skip validation)

## Usage

Run the script:

```bash
python main.py
```

The script will:

1. Connect to IMAP and download unread reports.
2. Parse attachments and check SPF/DKIM results.
3. Send email alerts on failures or DNS mismatches.
4. Move processed emails to the configured folder.

## Troubleshooting

* **Missing folder**: Ensure the `Email-LOG-Processed` folder exists or create it on the email server.

## License

MIT License. See [LICENSE](LICENSE).
