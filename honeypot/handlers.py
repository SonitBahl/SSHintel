import paramiko
import time
import threading
import socket
from pathlib import Path

from .server import Server
from .logger import funnel_logger

host_key_path = Path(__file__).parent.parent / 'static' / 'server.key'
host_key = paramiko.RSAKey(filename=host_key_path)

def emulated_shell(channel, client_ip):
    prompt = b"user1@ubuntu:~$ "
    channel.send(prompt)
    command = b""
    cwd = "/home/user1"

    while True:
        char = channel.recv(1)
        if not char:
            break
        channel.send(char)
        command += char

        if char == b"\r":
            cmd = command.strip().decode()

            if cmd == "exit":
                channel.send(b"\nlogout\n")
                break

            response = b"\n"
            if cmd == "pwd":
                response += cwd.encode() + b"\n"
            elif cmd == "whoami":
                response += b"user1\n"
            elif cmd == "ls":
                response += b"Documents  Downloads  script.sh  notes.txt\n"
            elif cmd.startswith("cat "):
                filename = cmd[4:].strip()
                if filename == "notes.txt":
                    response += b"This is a test file.\n"
                elif filename == "script.sh":
                    response += b"#!/bin/bash\necho Hello World\n"
                else:
                    response += f"cat: {filename}: No such file or directory\n".encode()
            elif cmd.startswith("echo "):
                response += cmd[5:].encode() + b"\n"
            elif cmd == "uname -a":
                response += b"Linux ubuntu 5.15.0-50-generic #56~20.04 SMP x86_64 GNU/Linux\n"
            elif cmd == "hostname":
                response += b"ubuntu\n"
            elif cmd == "clear":
                response = b"\033[2J\033[H"
            elif cmd == "id":
                response += b"uid=1001(user1) gid=1001(user1) groups=1001(user1)\n"
            elif cmd.startswith("cd "):
                target = cmd[3:].strip()
                if target.startswith("/"):
                    cwd = target
                else:
                    cwd = f"{cwd}/{target}"
            elif cmd == "mkdir test":
                response += b""
            elif cmd == "rm test":
                response += b""
            else:
                response += f"{cmd}: command not found\n".encode()

            funnel_logger.info(f'Command "{cmd}" executed by {client_ip}')
            channel.send(response)
            channel.send(prompt)
            command = b""
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