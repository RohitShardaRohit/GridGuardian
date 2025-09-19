"""
setup_encrypt_config.py
Creates (or updates) an encrypted config.enc for guardian.py.

Requires:
  - env FILE_KEY set to a 32-byte url-safe base64 Fernet key
"""

import os, json, base64, sys
from cryptography.fernet import Fernet

def get_key_from_env() -> str:
    key = os.environ.get("FILE_KEY")
    if not key:
        sys.exit("ERROR: FILE_KEY env var is not set. Export it before running.")
    try:
        raw = base64.urlsafe_b64decode(key)
        if len(raw) != 32:
            raise ValueError
    except Exception:
        sys.exit("ERROR: FILE_KEY is invalid. It must be a 32-byte url-safe base64 string.")
    return key

def main():
    key = get_key_from_env()

    # --- Defaults ---
    cfg = {
        "ubuntu_ips": ["", ""], #add both ubuntu ips here
        "ubuntu_user": "", #add ubuntu username here

        "use_ssh_key": True,
        "ssh_key_path": os.path.expanduser(""), #add ssh key path here

        "ubuntu_pass": "", #add ubuntu password here

        "protected_path": "", #add protected path here
        "quarantine_path": "", #add quarantine path here
        "audit_key": "secure_files_watch",
        "syslog_tag": "file_guard",

        "kali_ip": "", #add kali ip here
    }
    # -------------------------------------

    cipher = Fernet(key.encode())
    payload = json.dumps(cfg, separators=(",", ":"), ensure_ascii=False).encode()

    with open("config.enc", "wb") as f:
        f.write(cipher.encrypt(payload))

    print("✓ Wrote config.enc (encrypted). Do NOT commit config.enc or your FILE_KEY.")

if __name__ == "__main__":
    main()
