# Simple Firewall Script
# Author: Ryan Feneley
# August 2024

import logging
import socket
import threading

# Set up logging
logging.basicConfig(filename='firewall.log', level=logging.INFO, format='%(asctime)s - %(message)s')

class Firewall:
    def __init__(self):
        self.allowed_ips = set()
        self.blocked_ips = set()
        self.allowed_ports = set()
        self.blocked_ports = set()

    def allow_ip(self, ip):
        self.allowed_ips.add(ip)
        logging.info(f"Allowed IP: {ip}")

    def block_ip(self, ip):
        self.blocked_ips.add(ip)
        logging.info(f"Blocked IP: {ip}")

    def allow_port(self, port):
        self.allowed_ports.add(port)
        logging.info(f"Allowed Port: {port}")

    def block_port(self, port):
        self.blocked_ports.add(port)
        logging.info(f"Blocked Port: {port}")

    def is_allowed(self, ip, port):
        if ip in self.blocked_ips:
            logging.warning(f"Blocked access from: {ip} on port: {port}")
            return False
        if port in self.blocked_ports:
            logging.warning(f"Blocked access on port: {port} from IP: {ip}")
            return False
        if ip in self.allowed_ips or port in self.allowed_ports:
            logging.info(f"Allowed access from: {ip} on port: {port}")
            return True
        logging.info(f"No specific rules for: {ip} on port: {port}. Allowing by default.")
        return True

class TrafficHandler(threading.Thread):
    def __init__(self, conn, addr, firewall):
        super().__init__()
        self.conn = conn
        self.addr = addr
        self.firewall = firewall

    def run(self):
        ip, port = self.addr
        if self.firewall.is_allowed(ip, port):
            self.handle_connection()
        else:
            logging.info(f"Connection refused from {self.addr}")
            self.conn.close()

    def handle_connection(self):
        logging.info(f"Connection established with {self.addr}")
        try:
            # Simulate receiving data
            data = self.conn.recv(1024)
            if not data:
                return
            logging.info(f"Data received from {self.addr}: {data.decode()}")
            # Send a response back
            self.conn.sendall(b'HTTP/1.1 200 OK\r\n\r\n')
        finally:
            self.conn.close()

class SimpleFirewallServer:
    def __init__(self, host='0.0.0.0', port=8080):
        self.firewall = Firewall()
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((host, port))
        self.server_socket.listen(5)
        logging.info(f"Server started on {host}:{port}")

    def run(self):
        try:
            while True:
                conn, addr = self.server_socket.accept()
                TrafficHandler(conn, addr, self.firewall).start()
        except KeyboardInterrupt:
            logging.info("Server shutting down.")
        finally:
            self.server_socket.close()

#example use
if __name__ == "__main__":
    # Initialize firewall rules
    firewall = Firewall()
    firewall.allow_ip('192.168.1.10')
    firewall.block_ip('192.168.1.20')
    firewall.allow_port(8080)
    firewall.block_port(22)  # Block SSH
    server = SimpleFirewallServer()
    server.run()
