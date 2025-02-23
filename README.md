# Simple Firewall Script
## Overview
This project is a Python-based firewall script designed to block or allow network traffic based on specified IP addresses and port numbers. The script monitors incoming traffic, matches it against defined rules, and either allows or blocks the traffic accordingly.

## Features
- Define a list of allowed and blocked IP addresses.
- Define a list of allowed and blocked ports.
- Logs every connection attempt and its status (allowed/blocked).
- Multithreaded to handle multiple connections simultaneously.
- Easy to customize for adding new firewall rules.

## Requirements
- Python 3.x
- socket module (part of Python's standard library)
- logging module (part of Python's standard library)

## Usage
1. Clone the repository or download the code.
2. Modify the irewall.py file to add your own rules for allowed/blocked IP addresses and ports in the main section.
3. Run the script:
   \\\ash
   python simple_firewall.py
   \\\
4. The firewall will start listening on the specified port (default is 8080) and log any incoming connection attempts.

## How it Works
- The firewall script opens a socket on a specified port and listens for incoming connections.
- For each connection attempt, it checks the source IP address and port number against the defined rules.
- If the IP address or port is blocked, the connection is rejected and logged.
- If the IP address or port is allowed, the connection is accepted and processed, with any traffic logged.
- Traffic is handled using separate threads, allowing the firewall to manage multiple connections simultaneously.

