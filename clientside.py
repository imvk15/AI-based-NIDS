import tkinter as tk
from tkinter import messagebox
from tkinter import ttk, filedialog
import csv
from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading
import time
from collections import deque
import requests  # For HTTP requests to server
import json

# Server details
SERVER_URL = "http://127.0.0.1:5000/detect"  # Update with server IP if needed

# Global variables for packet capture and data
capture_running = False
packet_data = deque(maxlen=1000)  # Buffer for captured packets
display_data = deque(maxlen=1000)  # Buffer for displaying packets
all_captured_packets = []  # List to hold all captured packets for saving

# Function to send packet data to server for prediction
def send_to_server(packet_info):
    try:
        # Format data as dictionary matching server expectations
        data = [{
            "IPV4_SRC_ADDR": packet_info[0],
            "IPV4_DST_ADDR": packet_info[1],
            "SRC_PORT": packet_info[2],
            "DST_PORT": packet_info[3],
            "PROTOCOL": packet_info[4],
            "LENGTH": packet_info[5],
            "PAYLOAD_LEN": packet_info[6]
        }]
        
        # Send data to server
        response = requests.post(SERVER_URL, json=data)
        response_data = response.json()

        # Get the attack type from server response
        attack_type = response_data[0].get("attack", "Unknown")
        return attack_type

    except Exception as e:
        print(f"Server error: {e}")
        return "Error"

# Function to process each packet
def process_packet(packet):
    global packet_data, all_captured_packets

    try:
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            source_ip = ip_layer.src
            protocol_number = ip_layer.proto  # Get protocol number

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
                source_port = None
                dest_port = None
            
            # Prepare the info tuple
            info = (source_ip, dest_ip, source_port if source_port else 'N/A',
                    dest_port if dest_port else 'N/A', protocol_number, length, 
                    len(packet[TCP].payload) if packet.haslayer(TCP) else 0)

            # Get attack type prediction from the server
            attack_type = send_to_server(info)

            # Add attack type to info tuple for display
            display_info = info + (attack_type,)

            # Store captured packet information
            packet_data.append(display_info)
            all_captured_packets.append(display_info)  # Store in all captured packets

    except Exception as e:
        messagebox.showerror("Error", f"Error processing packet: {e}")

# Function to update the display
def update_display():
    while capture_running:
        if packet_data:
            # Move packets from the capture buffer to the display buffer
            display_data.extend(packet_data)
            packet_data.clear()  # Clear the capture buffer

            # Update the Treeview with new data and apply color tags based on protocol
            for packet in display_data:
                # Assign a tag based on the protocol
                protocol_number = packet[4]
                tag = None
                if protocol_number == 6:    # TCP
                    tag = "tcp"
                elif protocol_number == 17:  # UDP
                    tag = "udp"
                elif protocol_number == 1:   # ICMP
                    tag = "icmp"

                # Insert data with attack type in the last column
                packet_tree.insert("", tk.END, values=packet, tags=(tag,))
            display_data.clear()  # Clear the display buffer

            packet_tree.yview_moveto(1.0)  # Auto-scroll to the last row
        time.sleep(0.1)  # Reduced sleep time for faster updates

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
            # Use store=0 to not store packets in memory
            sniff(iface=interface, filter=capture_filter, prn=process_packet, 
                  stop_filter=lambda x: not capture_running, store=0)
        except Exception as e:
            messagebox.showerror("Capture Error", f"Error capturing packets: {e}")
            capture_running = False

    # Start capture and display in separate threads
    capture_thread = threading.Thread(target=capture_traffic)
    capture_thread.start()

    display_thread = threading.Thread(target=update_display)
    display_thread.start()

# Function to stop packet capture
def stop_capture():
    global capture_running
    capture_running = False

# Function to save packet data to CSV in a separate thread
def save_to_csv():
    global all_captured_packets  # Access the captured packet data
    if not all_captured_packets:
        messagebox.showinfo("Info", "No data to save.")
        return

    # Open file dialog to select location and filename
    file_path = filedialog.asksaveasfilename(defaultextension=".csv",
                                               filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
                                               title="Save As")
    
    if not file_path:
        return  # User canceled the dialog

    def save():
        try:
            with open(file_path, "w", newline="") as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol Number", "Length", "Payload Length", "Attack Type"])
                writer.writerows(all_captured_packets)  # Save all captured packets

            messagebox.showinfo("Success", "Data saved successfully!")
            all_captured_packets.clear()  # Clear the captured data after saving
        except Exception as e:
            messagebox.showerror("Error", f"Error saving data: {e}")

    # Start saving in a separate thread
    save_thread = threading.Thread(target=save)
    save_thread.start()

# GUI Setup with Tkinter
root = tk.Tk()
root.title("Network Traffic Analyzer")

# Create and place widgets
tk.Label(root, text="Network Interface:").grid(row=0, column=0, padx=10, pady=10)

# Static list for demonstration
interface_options = ["Wi-Fi", "Ethernet"]  # Update with actual network interfaces on your system
interface_combobox = ttk.Combobox(root, values=interface_options, width=50, state="readonly")
interface_combobox.grid(row=0, column=1, padx=10, pady=10)
interface_combobox.set("Select an interface")  # Placeholder text

start_button = tk.Button(root, text="Start Capture", command=start_capture)
start_button.grid(row=1, column=0, padx=10, pady=10)

save_button = tk.Button(root, text="Save Data As", command=save_to_csv)
save_button.grid(row=1, column=1, padx=10, pady=10)

stop_button = tk.Button(root, text="Stop Capture", command=stop_capture)
stop_button.grid(row=1, column=2, padx=10, pady=10)

# Create a frame for the Treeview and scrollbar
frame = ttk.Frame(root)
frame.grid(row=2, column=0, columnspan=3, padx=10, pady=10)

# Create Treeview for displaying packet data
columns = ("Source IP", "Destination IP", "Source Port", "Destination Port", 
           "Protocol Number", "Length", "Payload Length", "Attack Type")
packet_tree = ttk.Treeview(frame, columns=columns, show='headings', height=25)
packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

# Create a scrollbar and attach it to the Treeview
scrollbar = ttk.Scrollbar(frame, orient="vertical", command=packet_tree.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

# Configure the Treeview to use the scrollbar
packet_tree.configure(yscroll=scrollbar.set)

# Define column headings
for col in columns:
    packet_tree.heading(col, text=col)
    packet_tree.column(col, width=150)  # Adjust width as needed

# Set up color coding for different protocols
packet_tree.tag_configure("tcp", background="lightgreen")  # TCP: Green
packet_tree.tag_configure("udp", background="lightblue")   # UDP: Blue
packet_tree.tag_configure("icmp", background="yellow")     # ICMP: Yellow

# Run the Tkinter event loop
root.mainloop()
