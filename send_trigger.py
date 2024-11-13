import socket

dest_ip = "192.168.51.142"
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
        data, addr = sock.recvmsg(1024)
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
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(message.encode(), (dest_ip, dest_port3))
        print(f"Sending last trigger packet to {dest_ip} on port {dest_port3}")
    finally:
        sock.close()


def main():
    print("Beginning trigger sequence...\n")
    send_trigger1()
    send_trigger2()
    message = listen()
    send_trigger3(message)


if __name__ == "__main__":
    main()