import os, json, time, re, socket, base64
import paramiko
from cryptography.fernet import Fernet

# ------------ config loading ------------
def load_cfg():
    key = os.environ.get("FILE_KEY")
    if not key:
        raise RuntimeError("FILE_KEY is not set. export FILE_KEY=... before running.")
    try:
        raw = base64.urlsafe_b64decode(key)
        if len(raw) != 32:
            raise ValueError
    except Exception:
        raise RuntimeError("FILE_KEY is invalid. It must be a 32-byte url-safe base64 key.")

    if not os.path.exists("config.enc"):
        raise RuntimeError("config.enc not found. Run setup_encrypt_config.py first.")

    cipher = Fernet(key.encode())
    with open("config.enc", "rb") as f:
        cfg = json.loads(cipher.decrypt(f.read()).decode())

    required = [
        "ubuntu_ips", "ubuntu_user",
        "use_ssh_key", "ssh_key_path", "ubuntu_pass",
        "protected_path", "quarantine_path",
        "audit_key", "syslog_tag"
    ]
    for k in required:
        if k not in cfg:
            raise RuntimeError(f"Missing config key: {k}")

    if cfg["use_ssh_key"]:
        if not os.path.exists(os.path.expanduser(cfg["ssh_key_path"])):
            raise RuntimeError("SSH key path does not exist. Check ssh_key_path in your config.")

    return cfg

# ------------ ip probe ------------
def port_open(ip, port=22, timeout=2.0):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        return True
    except Exception:
        return False
    finally:
        try: s.close()
        except: pass

def choose_reachable_ip(candidates):
    print(f"[guardian] Probing candidate IPs: {', '.join(candidates)}")
    for ip in candidates:
        ok = port_open(ip, 22, 2.0)
        print(f"[guardian] {ip} {'reachable' if ok else 'not reachable'} on 22")
        if ok:
            return ip
    raise RuntimeError(
        "No candidate IP reachable on port 22.\n"
        "- Ensure the VM is running\n"
        "- Adapter 2: Host-only (vboxnet0) → 192.168.56.x\n"
        "- Adapter 1: NAT Network → 10.0.2.x\n"
        "- openssh-server installed and UFW allows 22 on host-only"
    )

# ------------ ssh helpers ------------
def ssh_connect(ip, user, use_key, key_path, passwd):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    if use_key:
        pkey = paramiko.Ed25519Key.from_private_key_file(os.path.expanduser(key_path))
        client.connect(ip, username=user, pkey=pkey, timeout=10)
    else:
        client.connect(ip, username=user, password=passwd, timeout=10)
    return client

def run(client, cmd, sudo=False):
    if sudo:
        full = f"sudo -n bash -lc {json.dumps(cmd)}"
    else:
        full = f"bash -lc {json.dumps(cmd)}"
    stdin, stdout, stderr = client.exec_command(full)
    out = stdout.read().decode()
    err = stderr.read().decode()
    code = stdout.channel.recv_exit_status()
    return code, out, err

# ------------ bootstrap ------------
def shq(s: str) -> str:
    return json.dumps(s)

def bootstrap_remote(client, cfg):
    cmds = [
        f"mkdir -p {shq(cfg['protected_path'])}",
        f"mkdir -p {shq(cfg['quarantine_path'])}",
        f"sudo -n auditctl -l | grep -q -- {shq(cfg['audit_key'])} || "
        f"sudo -n auditctl -w {shq(cfg['protected_path'])} -p rwxa -k {shq(cfg['audit_key'])}",
        f'logger -t {shq(cfg["syslog_tag"])} "guardian bootstrap complete" || true'
    ]
    for c in cmds:
        code, out, err = run(client, c, sudo=False)
        if code != 0 and err.strip():
            print(f"[guardian] bootstrap warn: {c}\n  {err.strip()}")

# ------------ monitor & respond ------------
AUDIT_TAIL_CMD = r"""sudo -n /usr/bin/tail -F -n0 /var/log/audit/audit.log"""
PATH_RE = re.compile(r'name="([^"]+)"')

def extract_paths(line, protected_root):
    paths = []
    root = protected_root.rstrip("/") + "/"
    for m in PATH_RE.finditer(line):
        p = m.group(1)
        if p == protected_root or p.startswith(root):
            paths.append(p)
    return paths

def quarantine(client, cfg, paths):
    ts = int(time.time())
    moved = []
    for p in paths:
        base = os.path.basename(p)
        newp = f"{cfg['quarantine_path'].rstrip('/')}/{base}.{ts}"
        cmd = f"if [ -e {shq(p)} ]; then mv {shq(p)} {shq(newp)}; fi"
        code, out, err = run(client, cmd, sudo=False)
        if code == 0:
            moved.append((p, newp))
    if moved:
        msg = "quarantined: " + ", ".join([f"{a} -> {b}" for a, b in moved])
        run(client, f'logger -t {shq(cfg["syslog_tag"])} {shq(msg)}', sudo=False)
        print(f"[guardian] {msg}")

def stream_audit_and_act(client, cfg):
    transport = client.get_transport()
    ch = transport.open_session()
    ch.get_pty()  
    ch.exec_command(AUDIT_TAIL_CMD)

    print("[guardian] monitoring audit.log… Ctrl+C to stop.")
    protected = cfg["protected_path"]
    DEBUG = os.environ.get("GUARDIAN_DEBUG") == "1"

    
    window_active = False
    window_paths = set()
    window_deadline = 0.0

    def flush_window_if_due(force=False):
        nonlocal window_active, window_paths, window_deadline
        if window_active and (force or time.time() > window_deadline):
            if window_paths:
                paths = sorted(window_paths)
                print(f"[guardian] hit: {paths}")
                quarantine(client, cfg, paths)
            window_active = False
            window_paths.clear()

    buf = b""
    last_idle_check = time.time()

    while True:
        if ch.recv_stderr_ready():
            err = ch.recv_stderr(4096).decode(errors="ignore").strip()
            if err:
                print("[guardian] sudo/tail stderr:", err)

        if ch.recv_ready():
            chunk = ch.recv(8192)
            if not chunk:
                break
            buf += chunk

            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                s = line.decode(errors="ignore").rstrip("\r")
                if not s:
                    continue

                if DEBUG and (cfg["audit_key"] in s or "type=PATH" in s):
                    print("[debug]", s)

                if cfg["audit_key"] in s:
                    window_active = True
                    window_deadline = time.time() + 1.0  
                    window_paths.clear()
                    continue

                
                if window_active and "type=PATH" in s:
                    for p in extract_paths(s, protected):
                        window_paths.add(p)

                
                if window_active and s == "----":
                    flush_window_if_due(force=True)

            last_idle_check = time.time()

        else:
            
            now = time.time()
            if window_active and now - last_idle_check > 0.2:
                flush_window_if_due(force=False)
                last_idle_check = now

            if ch.exit_status_ready():
                
                flush_window_if_due(force=True)
                break

            time.sleep(0.1)

# ------------ main ------------
def main():
    cfg = load_cfg()

    ip = choose_reachable_ip(cfg["ubuntu_ips"])
    cfg["ubuntu_ip"] = ip
    print(f"[guardian] using ubuntu_ip={ip}")

    print("[guardian] SSH connect…")
    client = ssh_connect(
        ip,
        cfg["ubuntu_user"],
        cfg["use_ssh_key"],
        cfg["ssh_key_path"],
        cfg["ubuntu_pass"],
    )

    try:
        bootstrap_remote(client, cfg)
        stream_audit_and_act(client, cfg)
    finally:
        client.close()

if __name__ == "__main__":
    main()



