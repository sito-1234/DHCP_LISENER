DHCP Listener Script

This Python script listens for DHCP packets on the network and logs information about the DHCP requests, including the MAC address of the requester, the requested IP address, hostname, and vendor ID.
Requirements

    Python 3.x
    Scapy library for network packet manipulation

Dependencies

The script uses the Scapy library to capture and analyze DHCP packets. You can install it using pip:

pip install scapy

Purpose

This script is used to monitor DHCP packets (UDP port 67 and 68) on the network. It extracts and prints details such as:

    MAC address of the requester
    Requested IP address from the DHCP client
    Hostname of the requesting device (if provided)
    Vendor ID (if available)

How It Works

    Capture DHCP Packets: The script uses Scapy's sniff() function to capture packets on the network.
    Filter Packets: It specifically looks for UDP packets on port 67 (DHCP server) and port 68 (DHCP client).
    Extract Information: If the packet is a DHCP packet, it extracts information from the DHCP options like the requested IP and hostname.
    Print Information: The script prints the following details:
        Time when the packet was captured
        MAC address of the device making the DHCP request
        Requested IP address
        Hostname of the device (if available)
        Vendor ID (if available)

Usage

    Run the Script: To run the script, use the following command:

sudo python3 dhcplistener.py

Running with sudo is required because the script listens for raw network packets, which requires elevated privileges.

Example Output: Once the script is running, it will output something like:

    [2024-12-02 - 16:30:15] : 00:1a:2b:3c:4d:5e - MyDevice / VendorX requested 192.168.1.100

    This shows the MAC address, the hostname, the vendor ID, and the requested IP address for the DHCP client.

Troubleshooting

    Permission Error: If you get a PermissionError: [Errno 1] Operation not permitted, ensure you are running the script with sudo as it requires administrative privileges to capture network packets.

    Scapy Installation Issues: If Scapy is not installed, run pip install scapy to install it. If you face any issues, check the official Scapy installation guide here.

Customization

    You can modify the script to filter for specific DHCP options or log the information to a file instead of printing it to the console.

    If you want to capture different types of packets, modify the filter parameter in the sniff() function accordingly.

Notes

    This script is intended for educational and testing purposes. Always ensure you have permission to monitor network traffic on any network you run this on.

    You should have a basic understanding of how DHCP works to fully appreciate the data being captured.
