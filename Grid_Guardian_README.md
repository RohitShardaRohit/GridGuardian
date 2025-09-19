# Grid Guardian

**Grid Guardian** is a lightweight defensive automation project built in Python.  
It monitors a protected folder on an Ubuntu VM using `auditd`, and when files are accessed it **quarantines them within ~1 second**. All actions are logged to syslog so they can be forwarded to SIEMs like Splunk for correlation.

This project was built as part of hands-on security lab work to simulate **real-time file monitoring and response**.

---

## Features

- **Python + Paramiko**: automates SSH to the Ubuntu VM
- **auditd integration**: watches the target directory for read/write/exec/delete events
- **Encrypted config**: runtime config is stored in `config.enc` using Fernet (AES-128)
- **Quarantine system**: automatically moves accessed files into a quarantine folder
- **Splunk-ready**: logs actions to syslog, can be forwarded into Splunk/ELK
- **Fast response**: quarantines files in under 1 second during simulated attacks

---

## Architecture

1. **Guardian controller (host)**  
   Runs `guardian.py`, loads encrypted config, and connects to Ubuntu over SSH.

2. **Ubuntu victim VM**  
   Runs `auditd` and `sshd`. Audit rules log all access to the protected folder.

3. **Quarantine process**  
   Guardian tails `/var/log/audit/audit.log` via SSH, extracts suspicious file paths, and moves them into quarantine.

---

## Example Scenario

- An attacker on Kali tries to read `/home/rohit/Desktop/secure_files/confidential.pdf`
- Auditd logs the syscall with `key=secure_files_watch`
- Guardian detects it, moves the file into `~/Desktop/quarantine/`, and logs:
  ```
  [guardian] quarantined: /home/rohit/Desktop/secure_files/confidential.pdf -> /home/rohit/Desktop/quarantine/confidential.pdf.<timestamp>
  ```
- Splunk shows the correlated event in near-real-time

---

## Repo Contents

- `guardian.py` — main controller
- `setup_encrypt_config.py` — encrypts config into `config.enc`
- `README.md` — this overview
- `SETUP.md` — full installation and usage guide
