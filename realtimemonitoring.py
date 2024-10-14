import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading
import time

# Global variable to control packet capture
capture_running = False

# Rate limiting configuration
RATE_LIMIT = 200  # Maximum packets per timeframe
TIMEFRAME = 5    # Timeframe in seconds

# Dictionary to track packet counts and timestamps
request_counts = {}

# Function to process each packet
def process_packet(packet):
    global request_counts
    current_time = time.time()

    try:
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            source_ip = ip_layer.src
            protocol_number = ip_layer.proto  # Get protocol number

            # Clean up old entries
            if source_ip in request_counts:
                request_counts[source_ip] = [
                    timestamp for timestamp in request_counts[source_ip]
                    if current_time - timestamp < TIMEFRAME
                ]

            # Check the packet count for this source IP
            if len(request_counts.get(source_ip, [])) >= RATE_LIMIT:
                return  # Drop packet processing if rate limit exceeded

            # Log the packet
            if source_ip not in request_counts:
                request_counts[source_ip] = []
            request_counts[source_ip].append(current_time)

            # Gather packet information
            dest_ip = ip_layer.dst
            source_port = None
            dest_port = None
            length = len(packet)

            # Determine transport layer protocol
            if packet.haslayer(TCP):
                source_port = packet[TCP].sport
                dest_port = packet[TCP].dport
            elif packet.haslayer(UDP):
                source_port = packet[UDP].sport
                dest_port = packet[UDP].dport
            elif packet.haslayer(ICMP):
                # For ICMP, no ports
                source_port = None
                dest_port = None
            
            # Prepare the info tuple
            info = (source_ip, dest_ip, source_port if source_port else 'N/A',
                    dest_port if dest_port else 'N/A', protocol_number, length, 
                    len(packet[TCP].payload) if packet.haslayer(TCP) else 0)

            # Insert the packet information into the Treeview
            packet_tree.insert("", tk.END, values=info)
            # Auto-scroll to the last row
            packet_tree.yview_moveto(1.0)
    except Exception as e:
        messagebox.showerror("Error", f"Error processing packet: {e}")

# Function to start packet capture in a separate thread
def start_capture():
    global capture_running
    interface = interface_combobox.get()
    if not interface:
        messagebox.showerror("Input Error", "Please select a network interface.")
        return

    # Capture all TCP, UDP, and ICMP traffic
    capture_filter = "tcp or udp or icmp"

    capture_running = True

    def capture_traffic():
        global capture_running
        try:
            # Use Scapy's sniff function with a filter and custom callback
            sniff(iface=interface, filter=capture_filter, prn=process_packet, stop_filter=lambda x: not capture_running)
        except Exception as e:
            messagebox.showerror("Capture Error", f"Error capturing packets: {e}")
            capture_running = False

    # Start capture in a separate thread
    capture_thread = threading.Thread(target=capture_traffic)
    capture_thread.start()

# Function to stop packet capture
def stop_capture():
    global capture_running
    capture_running = False

# Set up the Tkinter GUI
root = tk.Tk()
root.title("Network Traffic Analyzer")

# Create and place widgets
tk.Label(root, text="Network Interface:").grid(row=0, column=0, padx=10, pady=10)

# Static list for demonstration
interface_options = ["Wi-Fi", "Ethernet"]
interface_combobox = ttk.Combobox(root, values=interface_options, width=50, state="readonly")
interface_combobox.grid(row=0, column=1, padx=10, pady=10)
interface_combobox.set("Select an interface")  # Placeholder text

start_button = tk.Button(root, text="Start Capture", command=start_capture)
start_button.grid(row=1, column=0, padx=10, pady=10)

stop_button = tk.Button(root, text="Stop Capture", command=stop_capture)
stop_button.grid(row=1, column=1, padx=10, pady=10)

# Create Treeview for displaying packet data
columns = ("Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol Number", "Length", "Payload Length")
packet_tree = ttk.Treeview(root, columns=columns, show='headings', height=15)
packet_tree.grid(row=2, column=0, columnspan=2, padx=10, pady=10)

# Define column headings
for col in columns:
    packet_tree.heading(col, text=col)
    packet_tree.column(col, width=120)  # Adjust width as needed

# Run the Tkinter event loop
root.mainloop()
