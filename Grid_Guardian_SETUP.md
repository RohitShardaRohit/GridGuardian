# Grid Guardian — Setup Guide

This guide explains how to configure and run Grid Guardian against an Ubuntu VM.

> **Note:** This project is for educational and lab use only. Do not deploy in production.

---

## 1. Requirements

**Host (controller machine):**
- Python 3.8+
- Packages: `paramiko`, `cryptography`
- SSH keypair (recommended)

**Ubuntu VM (victim):**
- `auditd`
- `openssh-server`
- `logger`

---

## 2. Install dependencies

On host:
```bash
python3 -m pip install --user paramiko cryptography
```

On Ubuntu:
```bash
sudo apt update && sudo apt install -y auditd openssh-server logger
sudo systemctl enable --now ssh
```

---

## 3. Generate config key

On host, generate a Fernet key:
```bash
python3 - <<'PY'
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode())
PY
```

Export it:
```bash
export FILE_KEY="paste-key-here"
```

---

## 4. Create encrypted config

Run:
```bash
python3 setup_encrypt_config.py
```

This writes `config.enc`. Do **not** commit this file or the `FILE_KEY`.

Config includes:
- Ubuntu IPs (`192.168.xx.x`, `10.0.x.x`)
- Username
- SSH key path
- Protected path: `/home/<username>/Desktop/secure_files`
- Quarantine path: `/home/<username>/Desktop/quarantine`

---

## 5. Prepare Ubuntu folders

On Ubuntu VM:
```bash
mkdir -p ~/Desktop/secure_files ~/Desktop/quarantine
chmod 700 ~/Desktop/secure_files
```

---

## 6. Optional: sudoers for no password

To avoid repeated password prompts, add this line with `visudo` (replace `rohit` with your user):

```
<username> ALL=(ALL) NOPASSWD: /sbin/auditctl, /usr/bin/tail, /usr/bin/mv, /usr/bin/logger
```

---

## 7. Run Guardian

On host:
```bash
GUARDIAN_DEBUG=1 python3 guardian.py
```

Expected flow:
- Probes candidate IPs, finds Ubuntu VM
- Connects via SSH
- Ensures `auditctl` watch exists
- Streams audit log
- Quarantines any accessed files

---

## 8. Test it

On Ubuntu:
```bash
echo "secret" > ~/Desktop/secure_files/confidential.txt
```

From another machine:
```bash
scp <username>@<ubuntu-ip>:~/Desktop/secure_files/confidential.txt /tmp/
```

Guardian output:
```
[guardian] hit: ['/home/<username>/Desktop/secure_files/confidential.txt']
[guardian] quarantined: /home/<username>/Desktop/secure_files/confidential.txt -> /home/<username>/Desktop/quarantine/confidential.txt.<timestamp>
```

---

## 9. Restore quarantined file

On Ubuntu:
```bash
sudo mv ~/Desktop/quarantine/confidential.txt.<timestamp> ~/Desktop/secure_files/confidential.txt
sudo chown rohit:rohit ~/Desktop/secure_files/confidential.txt
```

---

## 10. Cleanup

Remove audit rules:
```bash
sudo auditctl -D
```

Stop sshd if not needed:
```bash
sudo systemctl stop ssh
```

---

## 11. Next Steps

- Forward syslog to Splunk for dashboarding
- Extend rules to multiple directories
- Add alerting (email, webhook)

---
