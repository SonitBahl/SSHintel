import paramiko
import time
import socket
from pathlib import Path

from .server import Server
from .logger import funnel_logger

host_key_path = Path(__file__).parent.parent / 'static' / 'server.key'
host_key = paramiko.RSAKey(filename=host_key_path)

fake_fs = {
    "home": {
        "user1": {
            "notes.txt": "This is a test file.",
            "script.sh": "#!/bin/bash\necho Hello World",
            "Documents": {},
            "Downloads": {},
        }
    }
}

def resolve_path(cwd, target):
    if target.startswith("/"):
        return target
    return cwd.rstrip("/") + "/" + target

def get_dir(path):
    parts = [p for p in path.strip("/").split("/") if p]
    cur = fake_fs
    for p in parts:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return None
    return cur

def emulated_shell(channel, client_ip):
    prompt_template = "user1@ubuntu:{}$ "
    cwd = "/home/user1"
    cwd_display = "~"
    prompt = prompt_template.format(cwd_display).encode()
    command = b""
    channel.send(prompt)

    while True:
        char = channel.recv(1)
        if not char:
            break

        if char == b"\r":
            channel.send(b"\r\n")
            cmd = command.strip().decode()
            response = b""

            if cmd == "exit":
                channel.send(b"logout\r\n")
                break

            elif cmd == "pwd":
                response += cwd.encode()

            elif cmd == "whoami":
                response += b"user1"

            elif cmd == "hostname":
                response += b"ubuntu"

            elif cmd == "uname -a":
                response += b"Linux ubuntu 5.15.0-50-generic #56~20.04 SMP x86_64 GNU/Linux"

            elif cmd == "id":
                response += b"uid=1001(user1) gid=1001(user1) groups=1001(user1)"

            elif cmd == "clear":
                response += b"\033[2J\033[H"

            elif cmd.startswith("cd "):
                target = cmd[3:].strip()
                new_path = "/".join(cwd.strip("/").split("/")[:-1]) if target == ".." else resolve_path(cwd, target)
                if get_dir(new_path):
                    cwd = new_path
                else:
                    response += f"bash: cd: {target}: No such file or directory".encode()

            elif cmd == "ls":
                dir_obj = get_dir(cwd)
                if isinstance(dir_obj, dict):
                    response += "  ".join(dir_obj.keys()).encode()
                else:
                    response += f"ls: cannot access '{cwd}': Not a directory".encode()

            elif cmd.startswith("mkdir "):
                dirname = cmd[6:].strip()
                dir_obj = get_dir(cwd)
                if isinstance(dir_obj, dict):
                    if dirname not in dir_obj:
                        dir_obj[dirname] = {}
                    else:
                        response += f"mkdir: cannot create directory '{dirname}': File exists".encode()

            elif cmd.startswith("touch "):
                filename = cmd[6:].strip()
                dir_obj = get_dir(cwd)
                if isinstance(dir_obj, dict):
                    dir_obj[filename] = ""

            elif cmd.startswith("rm "):
                filename = cmd[3:].strip()
                dir_obj = get_dir(cwd)
                if isinstance(dir_obj, dict):
                    if filename in dir_obj:
                        del dir_obj[filename]
                    else:
                        response += f"rm: cannot remove '{filename}': No such file".encode()

            elif cmd.startswith("cat "):
                filename = cmd[4:].strip()
                dir_obj = get_dir(cwd)
                if isinstance(dir_obj, dict) and filename in dir_obj:
                    content = dir_obj[filename]
                    if isinstance(content, str):
                        response += content.encode()
                    else:
                        response += f"cat: {filename}: Is a directory".encode()
                else:
                    response += f"cat: {filename}: No such file or directory".encode()

            elif ">" in cmd and cmd.startswith("echo "):
                try:
                    parts = cmd[5:].split(">")
                    msg = parts[0].strip()
                    fname = parts[1].strip()
                    dir_obj = get_dir(cwd)
                    if isinstance(dir_obj, dict):
                        dir_obj[fname] = msg
                except Exception:
                    response += b"bash: syntax error near unexpected token `>'"

            elif cmd.startswith("echo "):
                msg = cmd[5:].strip()
                response += msg.encode()

            elif cmd == "":
                pass 

            else:
                response += f"bash: {cmd}: command not found".encode()

            funnel_logger.info(f'Command "{cmd}" executed by {client_ip}')

            if response:
                channel.send(response + b"\r\n")

            cwd_display = cwd.replace("/home/user1", "~") if cwd.startswith("/home/user1") else cwd
            prompt = prompt_template.format(cwd_display).encode()
            channel.send(prompt)

            command = b""
        else:
            channel.send(char)
            command += char

    channel.close()

def client_handle(client, addr, username, password, tarpit=False):
    client_ip = addr[0]
    print(f"{client_ip} connected to server.")
    try:
        transport = paramiko.Transport(client)
        transport.local_version = "SSH-2.0-MySSHServer_1.0"
        transport.add_server_key(host_key)

        server = Server(client_ip, username, password)
        transport.start_server(server=server)
        channel = transport.accept(100)

        if channel is None:
            print("No channel was opened.")
            return

        banner = "Welcome to Ubuntu 22.04 LTS!\r\n\r\n"

        if tarpit:
            for char in banner * 100:
                channel.send(char)
                time.sleep(8)
        else:
            channel.send(banner)

        emulated_shell(channel, client_ip)

    except Exception as e:
        print("!!! Exception in client handler !!!")
        print(e)
    finally:
        try:
            transport.close()
        except Exception:
            pass
        client.close()