"""
Secure Structured JSON Logging Module
======================================
Upgrade from Phase 1 plain-text logging to structured JSON.

Why structured JSON logging?
  1. Machine-parseable — SIEM tools (Splunk, ELK, Azure Monitor) can ingest
     and alert on specific fields without regex parsing.
  2. Every log line has a consistent schema: timestamp, level, module,
     message, plus optional structured fields.
  3. Sensitive field redaction is explicit and auditable.
  4. Log integrity: each anomaly entry carries a SHA-256 hash of its payload
     so post-hoc tampering is detectable.

python-json-logger is used for the main application log.
Anomaly and rotation logs use raw JSON lines for easy grep/jq analysis.
"""

import json
import logging
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

# Sensitive field names — values are redacted before writing to any log
_SENSITIVE = frozenset({
    'private_key', 'psk', 'preshared_key', 'api_key', 'password',
    'secret', 'token', 'auth', 'credential', 'key', 'priv',
})


# ---------------------------------------------------------------------------
# Structured JSON formatter
# ---------------------------------------------------------------------------
class SecureJsonFormatter(logging.Formatter):
    """
    Formats log records as single-line JSON objects.

    Output schema:
      {
        "timestamp": "2026-05-14T11:00:00.000000Z",
        "level":     "INFO",
        "logger":    "wg_manager",
        "message":   "...",
        "module":    "wg_manager",
        "lineno":    42
      }

    Sensitive substrings in the message are replaced with [REDACTED].
    """

    def format(self, record: logging.LogRecord) -> str:
        # Build the message first so we can inspect it
        msg = record.getMessage()

        # Redact any sensitive field values appearing verbatim in the message
        for field in _SENSITIVE:
            if field in msg.lower():
                msg = '[REDACTED — sensitive field detected in log message]'
                break

        entry = {
            'timestamp': datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(timespec='microseconds'),
            'level':   record.levelname,
            'logger':  record.name,
            'module':  record.module,
            'lineno':  record.lineno,
            'message': msg,
        }

        # Attach any extra structured fields the caller added
        for key, val in record.__dict__.items():
            if key not in logging.LogRecord.__dict__ and not key.startswith('_'):
                if key not in entry:
                    entry[key] = val

        if record.exc_info:
            entry['exception'] = self.formatException(record.exc_info)

        return json.dumps(entry, default=str)


# ---------------------------------------------------------------------------
# Logger factory
# ---------------------------------------------------------------------------
def setup_logger(name: str, log_file: Path, level: str = 'INFO') -> logging.Logger:
    """
    Create (or retrieve) a structured JSON logger.

    Handlers:
      - FileHandler  → log_file  (DEBUG and above, JSON format)
      - StreamHandler → stderr   (INFO and above, JSON format → journald)
    """
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger   # Already configured — avoid duplicate handlers

    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False

    log_file.parent.mkdir(parents=True, exist_ok=True)
    formatter = SecureJsonFormatter()

    # File handler — persists all levels
    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    # Stream handler — systemd/journald captures stdout/stderr from Gunicorn
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    return logger


# ---------------------------------------------------------------------------
# Anomaly log (security events — separate file, always JSON lines)
# ---------------------------------------------------------------------------
def log_anomaly(
    event_type: str,
    details: Dict[str, Any],
    severity: str = 'WARNING',
    log_file: Path = None,
) -> None:
    """
    Write a structured security anomaly record.

    Each record is a JSON line containing:
      - timestamp (UTC ISO-8601)
      - event type and severity
      - sanitised detail fields
      - SHA-256 integrity hash of the details (detects post-hoc tampering)
    """
    if log_file is None:
        from config import ANOMALY_LOG
        log_file = ANOMALY_LOG

    # Sanitise details — redact any key whose name looks sensitive
    safe_details: Dict[str, str] = {}
    for k, v in details.items():
        if any(s in k.lower() for s in _SENSITIVE):
            safe_details[k] = '[REDACTED]'
        else:
            safe_details[k] = str(v)

    payload_hash = hashlib.sha256(
        json.dumps(safe_details, sort_keys=True).encode()
    ).hexdigest()[:24]

    entry = {
        'timestamp':    datetime.now(tz=timezone.utc).isoformat(timespec='seconds'),
        'event':        event_type,
        'severity':     severity,
        'details':      safe_details,
        'payload_hash': payload_hash,   # tamper-evidence
    }

    log_file.parent.mkdir(parents=True, exist_ok=True)
    with open(log_file, 'a') as f:
        f.write(json.dumps(entry) + '\n')


# ---------------------------------------------------------------------------
# PSK rotation audit log
# ---------------------------------------------------------------------------
def log_psk_rotation(
    peer_name: str,
    old_psk: str,
    new_psk: str,
    log_file: Path = None,
) -> None:
    """
    Write a PSK rotation audit record.

    Only SHA-256 hashes of the PSK values are stored — never the raw PSK.
    This allows auditors to verify a rotation happened without exposing secrets.
    """
    if log_file is None:
        from config import ROTATION_LOG
        log_file = ROTATION_LOG

    def _hash(val: str) -> str:
        return hashlib.sha256(val.encode()).hexdigest()[:16]

    entry = {
        'timestamp':   datetime.now(tz=timezone.utc).isoformat(timespec='seconds'),
        'event':       'psk_rotation',
        'peer':        peer_name,
        'old_psk_sha': _hash(old_psk),   # hash only — raw PSK never logged
        'new_psk_sha': _hash(new_psk),
    }

    log_file.parent.mkdir(parents=True, exist_ok=True)
    with open(log_file, 'a') as f:
        f.write(json.dumps(entry) + '\n')
