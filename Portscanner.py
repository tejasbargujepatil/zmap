import socket
from datetime import datetime
import threading
from concurrent.futures import ThreadPoolExecutor
import asyncio
import sys
import logging

# Setup logging
logging.basicConfig(filename='port_scanner.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Display ASCII Banner
print("Tejas Barguje Patil")

# Validate and Define Target
if len(sys.argv) == 2:
    target = sys.argv[1]
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("\nHostname Could Not Be Resolved..! Check the hostname and try again.")
        sys.exit()
else:
    print("Invalid number of arguments.")
    print("Usage: python3 Portscanner.py <hostname>")
    sys.exit()

# Add Banner
print("_" * 50)
print(f"Scanning Target: {target} ({target_ip})")
print("Scanning Started At: " + str(datetime.now()))
print("_" * 50)

# Port Scanning Functions
def scan_port(port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)  # Set timeout for connection attempts
            result = s.connect_ex((target_ip, port))
            if result == 0:
                print(f"TCP Port {port} is open")
                logging.info(f"TCP Port {port} is open")
                detect_service(s, port)
            else:
                logging.debug(f"TCP Port {port} is closed or filtered")
    except socket.timeout:
        print(f"TCP Port {port} connection timed out.")
        logging.warning(f"TCP Port {port} connection timed out.")
    except Exception as e:
        print(f"Error scanning TCP port {port}: {e}")
        logging.error(f"Error scanning TCP port {port}: {e}")

def scan_udp_port(port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2)  # Set timeout for UDP attempts
            s.sendto(b'', (target_ip, port))
            try:
                s.recvfrom(1024)
                print(f"UDP Port {port} is open")
                logging.info(f"UDP Port {port} is open")
            except socket.timeout:
                print(f"UDP Port {port} is open but not responding")
                logging.info(f"UDP Port {port} is open but not responding")
    except Exception as e:
        print(f"Error scanning UDP port {port}: {e}")
        logging.error(f"Error scanning UDP port {port}: {e}")

def detect_service(s, port):
    try:
        if port in [80, 443]:  # Common HTTP/S ports
            s.send(b'HEAD / HTTP/1.1\r\nHost: {}\r\n\r\n'.format(target).encode())
            banner = s.recv(1024).decode().strip()
            print(f"Service detected on TCP Port {port}: {banner}")
            logging.info(f"Service detected on TCP Port {port}: {banner}")
        elif port == 21:
            print(f"FTP service detected on TCP Port {port}")
            logging.info(f"FTP service detected on TCP Port {port}")
        elif port == 22:
            print(f"SSH service detected on TCP Port {port}")
            logging.info(f"SSH service detected on TCP Port {port}")
        elif port == 23:
            print(f"Telnet service detected on TCP Port {port}")
            logging.info(f"Telnet service detected on TCP Port {port}")
        elif port == 25:
            print(f"SMTP service detected on TCP Port {port}")
            logging.info(f"SMTP service detected on TCP Port {port}")
        # Add more services as needed
    except Exception as e:
        print(f"Service detection failed on port {port}: {e}")
        logging.error(f"Service detection failed on port {port}: {e}")

# Asynchronous Port Scanning
async def scan_port_async(port):
    try:
        reader, writer = await asyncio.open_connection(target_ip, port)
        print(f"TCP Port {port} is open")
        logging.info(f"TCP Port {port} is open")
        writer.close()
        await writer.wait_closed()
    except Exception as e:
        pass  # Ignoring exceptions for closed ports

async def scan_ports_async(start_port, end_port):
    tasks = [scan_port_async(port) for port in range(start_port, end_port + 1)]
    await asyncio.gather(*tasks)

# Threaded Port Scanning
def scan_ports_threaded(start_port, end_port):
    with ThreadPoolExecutor(max_workers=100) as executor:
        for port in range(start_port, end_port + 1):
            executor.submit(scan_port, port)

# Main Execution Flow (CLI)
if __name__ == "__main__":
    try:
        start_port = int(input("Enter start port: "))
        end_port = int(input("Enter end port: "))

        if start_port <= 0 or end_port > 65535 or start_port > end_port:
            print("Invalid port range. Please enter a valid range between 1 and 65535.")
            sys.exit()

        print("Choose scan type:")
        print("1. Threaded TCP Scan")
        print("2. Async TCP Scan")
        print("3. UDP Scan")

        choice = input("Enter choice: ")

        if choice == '1':
            scan_ports_threaded(start_port, end_port)
        elif choice == '2':
            asyncio.run(scan_ports_async(start_port, end_port))
        elif choice == '3':
            for port in range(start_port, end_port + 1):
                scan_udp_port(port)
        else:
            print("Invalid choice. Please select a valid option.")
    except KeyboardInterrupt:
        print("\nExiting Program..! ")
        sys.exit()
    except ValueError:
        print("\nInvalid input. Please enter integers for ports.")
        sys.exit()
    except socket.gaierror:
        print("\nHostname Could Not Be Resolved..! Check the hostname and try again.")
        sys.exit()
    except socket.error:
        print("\nError occurred while connecting to the server. Please check the target and try again.")
        sys.exit()

    print(f"Scanning Completed at: {str(datetime.now())}")
    logging.info("Scanning completed at: " + str(datetime.now()))
