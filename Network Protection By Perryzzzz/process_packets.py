
from scapy.all import sniff, IP, TCP, ICMP, Raw, UDP, ARP, Packet, send  # "Packet" is for type hinting
import psutil
from collections import defaultdict, deque
import socket
import time
import os
import asyncio

# ---- Constants And Dictionaries ---- #
TIME_WINDOW = 10  # time in seconds
SYN_THRESHOLD = 100  # Number of packets
PING_THRESHOLD = 1000  # Number of packets
HTTP_THRESHOLD = 100  # Number of packets
UDP_THRESHOLD = 1000  # Number of packets
SYNACK_THRESHOLD = 100  # Number of packets
PING_SIZE_THRESHOLD = 1500  # Size in bytes


# Creates a dictionaries for each kind of packets, to track timestamps of packets. For each source IP address
# the deque will store up to TIME_WINDOW recent timestamps, automatically removing older ones.
synack_packets = defaultdict(lambda: deque(maxlen=TIME_WINDOW))
udp_packets = defaultdict(lambda: deque(maxlen=TIME_WINDOW))
syn_packets = defaultdict(lambda: deque(maxlen=TIME_WINDOW))
ping_packets = defaultdict(lambda: deque(maxlen=TIME_WINDOW))
http_packets = defaultdict(lambda: deque(maxlen=TIME_WINDOW))


# Configure Current Machine's IP #
def conf_current_ip() -> str:
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    return ip_address


# Main Checking Function, A "hub" For All The Checks #
async def checking_packets(packet: Packet) -> None:
    if IP in packet:
        ip_dst = packet[IP].dst
        my_ip = conf_current_ip()

        # Filter only the packets that are destined to my computer
        if ip_dst != my_ip:
            return

        await asyncio.gather(
            check_syn(packet),
            check_synack(packet),
            check_pod(packet),
            check_ping(packet),
            check_http(packet),
            check_udp(packet),
            detect_arp_poison(packet)
        )
    else:
        return


# ---- Packet Checks Below ---- #

# Check SYN Flood #
async def check_syn(packet: Packet) -> None:
    ip_src = packet[IP].src
    current_time = time.time()
    if TCP in packet and packet[TCP].flags & 0x02:
        """
        If the current packet contains TCP protocol and a SYN flag,
        then we append the time we got the packet (now) to the deque of the associated 
        source IP key in the dictionary
        """
        syn_packets[ip_src].append(current_time)
        while syn_packets[ip_src] and syn_packets[ip_src][0] < current_time - TIME_WINDOW:
            """
                Keeps updating the deque to store the most recent packets by checking if the
                deque isn't empty, and if the current time minus the time stamp we set
                is bigger than the oldest packet, if yes, than remove, the most old one
                and continue checking the next one, when we perform this check we're basically 
                removing all the unrelevant packets that are not in the time stamp,
                "current_time - TIME_WINDOW" represent the time of the oldest packet that should be kept
            """
            syn_packets[ip_src].popleft()
        print(f"SYN Packet Detected From {ip_src}")
        # If the length of the deque is longer that the threshold, it means that we passed the number
        # of packets allowed in the 10 seconds timestamp
        if len(syn_packets[ip_src]) > SYN_THRESHOLD:
            choice = input(f"Potential SYN Flood From {ip_src}, Would U Like To Block This IP? (Y/N) ").lower()
            await free_system_resources()
            while True:
                if choice == 'y':
                    await block_ip(ip_src)
                    break
                elif choice != 'n' and choice != 'y':
                    choice = input("Invalid Input, Only Y/N").lower()

    else:
        return


# Check SYN-ACK Flood #
async def check_synack(packet: Packet) -> None:
    ip_src = packet[IP].src
    current_time = time.time()
    if TCP in packet and (packet[TCP].flags & (0x02 | 0x10)) == (0x02 | 0x10):
        # If the current packet is a SYN-ACK, we append the time
        # we got the packet (now) to the deque of the associated source IP key in the dictionary
        synack_packets[ip_src].append(current_time)
        while synack_packets[ip_src] and synack_packets[ip_src][0] < current_time - TIME_WINDOW:
            """
                Keeps updating the deque to store the most recent packets by checking if the
                deque isn't empty, and if the current time minus the time stamp we set
                is bigger than the oldest packet, if yes, than remove, the most old one
                and continue checking the next one, when we perform this check we're basically 
                removing all the unrelevant packets that are not in the time stamp,
                "current_time - TIME_WINDOW" represent the time of the oldest packet that should be kept
            """
            synack_packets[ip_src].popleft()
        print(f"SYN-ACK Packet Detected From {ip_src}")
        if len(synack_packets[ip_src]) > SYNACK_THRESHOLD:
            # If the length of the deque is longer that the threshold, it means that we passed the number
            # of packets allowed in the 10 seconds timestamp
            choice = input(f"Potential SYN-ACK Flood From {ip_src}, Would U Like To Block This IP? (Y/N) ").lower()
            await free_system_resources()
            while True:
                if choice == 'y':
                    await block_ip(ip_src)
                    break
                elif choice != 'n' and choice != 'y':
                    choice = input("Invalid Input, Only Y/N").lower()
    else:
        return


# Check Ping Of Death Attack #
async def check_pod(packet: Packet) -> None:
    ip_src = packet[IP].src
    if ICMP in packet and packet[ICMP].type == 8:
        # Checks if the packet is a ping packet (with ICMP protocol), and checks the packet's type is a request
        if len(packet) > PING_SIZE_THRESHOLD:
            # If the length of the packets (in bytes), is bigger than the threshold we set,
            # so it's a ping of death packet
            choice = input(f"Potential Ping of Death From {ip_src}, Would U Like To Block This IP? (Y/N) ").lower()
            await free_system_resources()
            while True:
                if choice == 'y':
                    await block_ip(ip_src)
                    break
                elif choice != 'n' and choice != 'y':
                    choice = input("Invalid Input, Only Y/N").lower()
    else:
        return


# Check Ping Flood - Classic DoS (and DDoS) #
async def check_ping(packet: Packet) -> None:
    ip_src = packet[IP].src
    current_time = time.time()
    if ICMP in packet and packet[ICMP].type == 8:
        """
        If the current packet contains ICMP protocol (ping packet), and its type is "request"
        then we append the time we got the packet (now) to the deque of the associated 
        source IP key in the dictionary
        """
        ping_packets[ip_src].append(current_time)
        while ping_packets[ip_src] and ping_packets[ip_src][0] < current_time - TIME_WINDOW:
            """
                Keeps updating the deque to store the most recent packets by checking if the
                deque isn't empty, and if the current time minus the time stamp we set
                is bigger than the oldest packet, if yes, than remove, the most old one
                and continue checking the next one, when we perform this check we're basically 
                removing all the unrelevant packets that are not in the time stamp,
                "current_time - TIME_WINDOW" represent the time of the oldest packet that should be kept
            """
            ping_packets[ip_src].popleft()
        print(f"Ping Packet Detected From {ip_src}")
        if len(ping_packets[ip_src]) > PING_THRESHOLD:
            # If the length of the deque is longer that the threshold, it means that we passed the number
            # of packets allowed in the 10 seconds timestamp
            choice = input(f"Potential DoS Attack From {ip_src}, Would U Like To Block This IP (Y/N) ").lower()
            await free_system_resources()
            while True:
                if choice == 'y':
                    await block_ip(ip_src)
                    break
                elif choice != 'n' and choice != 'y':
                    choice = input("Invalid Input, Only Y/N").lower()
    else:
        return


# Check HTTP Flood #
async def check_http(packet: Packet) -> None:
    ip_src = packet[IP].src
    current_time = time.time()
    if TCP in packet and packet[TCP].dport == 80:
        # If the current packet uses TCP protocol, and the port is 80 (HTTP protocol), continue to the
        # next checking
        if packet.haslayer(Raw) and b"GET" in packet[Raw].load:
            """
            If the packet has the application layer (for scapy is "Raw"), and if the packet
            contains "GET Request" in that layer, then we append the time we got the packet (now)
            to the deque of the associated source IP key in the dictionary
            """
            http_packets[ip_src].append(current_time)
            while http_packets[ip_src] and http_packets[ip_src][0] < current_time - TIME_WINDOW:
                """
                    Keeps updating the deque to store the most recent packets by checking if the
                    deque isn't empty, and if the current time minus the time stamp we set
                    is bigger than the oldest packet, if yes, than remove, the most old one
                    and continue checking the next one, when we perform this check we're basically 
                    removing all the unrelevant packets that are not in the time stamp,
                    "current_time - TIME_WINDOW" represent the time of the oldest packet that should be kept
                """
                http_packets[ip_src].popleft()
            print(f"HTTP Packet Detected From {ip_src}")
            if len(http_packets[ip_src]) > HTTP_THRESHOLD:
                # If the length of the deque is longer that the threshold, it means that we passed the number
                # of packets allowed in the 10 seconds timestamp
                choice = input(f"Potential HTTP Flood From {ip_src}, Would U Like To Block This IP? (Y/N) ").lower()
                await free_system_resources()
                while True:
                    if choice == 'y':
                        await block_ip(ip_src)
                        break
                    elif choice != 'n' and choice != 'y':
                        choice = input("Invalid Input, Only Y/N").lower()
    else:
        return


# Check UDP Flood #
async def check_udp(packet: Packet) -> None:
    ip_src = packet[IP].src
    current_time = time.time()
    if UDP in packet:
        """
        Just checks if the packet uses the UDP Protocol, if yes
        then we append that current time of the packet to the deque of the
        associated source IP key in the dictionary
        """
        udp_packets[ip_src].append(current_time)
        while udp_packets[ip_src] and udp_packets[ip_src][0] < current_time - TIME_WINDOW:
            """
                Keeps updating the deque to store the most recent packets by checking if the
                deque isn't empty, and if the current time minus the time stamp we set
                is bigger than the oldest packet, if yes, than remove, the most old one
                and continue checking the next one, when we perform this check we're basically 
                removing all the unrelevant packets that are not in the time stamp,
                "current_time - TIME_WINDOW" represent the time of the oldest packet that should be kept
            """
            udp_packets[ip_src].popleft()
        print(f"UDP Packet Detected From {ip_src}")
        if len(udp_packets[ip_src]) > UDP_THRESHOLD:
            # If the length of the deque is longer that the threshold, it means that we passed the number
            # of packets allowed in the 10 seconds timestamp
            choice = input(f"Potential UDP Flood From {ip_src}, Would U Like To Block This IP? (Y/N) ").lower()
            await free_system_resources()
            while True:
                if choice == 'y':
                    await block_ip(ip_src)
                    break
                elif choice != 'n' and choice != 'y':
                    choice = input("Invalid Input, Only Y/N").lower()
    else:
        return


# Detect ARP Poisoning #
async def detect_arp_poison(packet):
    ip_src = packet[IP].src

    if packet.haslayer(ARP):
        print(f"ARP Packet Detected From {ip_src}")
        if packet[ARP].op == 2:  # ARP reply
            ip = packet[ARP].psrc
            mac = packet[ARP].hwsrc

            # If the IP exists in ip_mac_table, check for a mismatch
            if ip in ip_mac_table:
                if ip_mac_table[ip] != mac:
                    print(f"ARP Poisoning Detected! IP: {ip} Old MAC: {ip_mac_table[ip]} New MAC: {mac}")
                    block_attacker_mac(mac)

                    # Fix the ARP table on other devices by sending a legitimate ARP response
                    correct_mac = ip_mac_table[ip]
                    await arp_fix(ip, correct_mac, packet[ARP].pdst)
            else:
                # If the IP is not in the table, assume it's a new entry and add it
                ip_mac_table[ip] = mac
                print(f"New IP-MAC Mapping Added: {ip} -> {mac}")


# ---- Recovering And Handling Section ---- #

# Get the current ARP table from the OS
def get_arp_table():
    arp_table = {}
    output = ""
    if os.name == "posix":  # Linux/MacOS
        output = os.popen("arp -n").readlines()
    elif os.name == "nt":  # Windows
        output = os.popen("arp -a").readlines()

    for line in output[1:]:  # Skip the header
        parts = line.split()
        if len(parts) >= 4:  # Format varies slightly on different OS
            ip = parts[0]
            mac = parts[1] if os.name == "nt" else parts[2]
            arp_table[ip] = mac

    return arp_table


# Block the attacker's MAC address
def block_attacker_mac(mac_address):
    print(f"Blocking MAC address on Windows: {mac_address}")
    os.system(f"netsh advfirewall firewall add rule name=\"BlockARP\""
              f"dir=in interface=any action=block enable=yes remoteip=any localmac={mac_address}")


# Send Correct ARP Reply To Fix Poisoned ARP Tables #
async def arp_fix(ip, correct_mac, target_ip):
    # Sen
    packet = ARP(op=2, psrc=ip, hwsrc=correct_mac, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff")
    send(packet, verbose=False)
    print(f"Sent ARP Fix For IP {ip} To {target_ip} With MAC {correct_mac}")


# Blocks An IP From Sending Packets To Our Machine #
async def block_ip(ip_address: str) -> None:
    # A command that drops the IP from the IPs table of the computer
    command = (f"netsh advfirewall firewall add rule name=\"Block {ip_address}\""
               f" dir=in action=block remoteip={ip_address}")
    # Perform the command above
    os.system(command)
    print(f"The Following IP Have Been Blocked: {ip_address}")


async def reset_bandwidth_limit_windows() -> None:
    """
    Reset network bandwidth throttling (QoS) settings on Windows using PowerShell commands.
    """
    # Example: Remove all QoS policies using PowerShell
    command = 'powershell "Remove-NetQosPolicy -Confirm:$false"'
    exit_code = os.system(command)
    if exit_code == 0:
        print("Network Bandwidth (QoS) Policies Removed.")
    else:
        print(f"Failed To Remove QoS Policies")


async def reset_bandwidth_limit_linux(interface: str) -> None:
    """
    Remove any bandwidth throttling (traffic shaping) on a specific network interface (Linux).
    """
    # Delete the traffic control rule applied to the specified interface
    command = f"tc qdisc del dev {interface} root"
    exit_code = os.system(command)
    if exit_code == 0:
        print(f"Bandwidth throttling removed for interface: {interface}")
    else:
        print(f"Failed to remove bandwidth throttling on interface: {interface}. Command exit code: {exit_code}")


async def kill_cpu_hogging_processes(threshold_percent: float) -> None:
    """
    Terminates processes using more than the specified percentage of CPU.
    """
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
        try:
            if proc.info['cpu_percent'] > threshold_percent:
                choice = input(f"Terminating Process? {proc.info['name']} (PID: {proc.info['pid']}) Using {proc.info['cpu_percent']}% CPU (Y/N) ")
                while True:
                    if choice.lower() == 'y':
                        proc.terminate()
                        break
                    elif choice.lower() == 'n':
                        print("Moving To Next Process")
                        break
                    elif choice.lower() != 'y' and choice.lower() != 'n':
                        choice = input("Invalid Choice, Y/N Or Only ")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue


# Function to terminate memory-hogging processes
async def kill_memory_hogging_processes(threshold_mb: int) -> None:
    """
    Terminates processes using more than the specified threshold of memory (in MB).
    """
    for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
        try:
            # Get memory usage in MB
            memory_usage_mb = proc.info['memory_info'].rss / (1024 * 1024)
            if memory_usage_mb > threshold_mb:
                choice = input(f"Terminating Process? {proc.info['name']} (PID: {proc.info['pid']}) Using {memory_usage_mb:.2f} MB(Y/N): ").lower()
                while True:
                    if choice == 'y':
                        proc.terminate()
                        break
                    elif choice == 'n':
                        print("Moving To Next Process")
                        break
                    elif choice != 'y' and choice != 'n':
                        choice = input("Invalid Choice, Y/N Or Only ")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue


async def free_system_resources() -> None:
    """
    Frees system resources by killing heavy processes and resetting network limits.
    """
    print("Recovering System Resources After Attack...")

    # Kill memory of useless processes and cpu
    await asyncio.gather(
        kill_memory_hogging_processes(500),
        kill_cpu_hogging_processes(80.0),
    )

    # Reset network bandwidth limitations (Linux or Windows)
    if os.name == 'posix':  # Linux/Unix
        asyncio.run(reset_bandwidth_limit_linux("eth0"))
    elif os.name == 'nt':  # Windows
        asyncio.run(reset_bandwidth_limit_windows())

    print("System Resources Have Been Freed.")

ip_mac_table = get_arp_table()


def main():
    print("Start Checking", end="")
    time.sleep(0.5)
    print(".", end="")
    time.sleep(0.5)
    print(".", end="")
    time.sleep(0.5)
    print(".")
    # Creates a lambda function, and passes the current packet to the main function inside the "asyncio.run" command
    sniff(filter="ip", prn=lambda pkt: asyncio.run(checking_packets(pkt)), store=0)
    print("Finished Checking For Potential Attacks")


if __name__ == "__main__":
    main()

"""
I used asyncio and async functions because I want the packet checks to run concurrently, with this I can perform
multiple checks at the same time, and not one by one
the asyncio library helps handle these async functions efficiently
"""
