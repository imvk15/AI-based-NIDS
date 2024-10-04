import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from scapy.all import sniff, IP, TCP
import threading

# Global variable to control packet capture
capture_running = False

# Function to process each packet
def process_packet(packet):
    try:
        if packet.haslayer(IP) and packet.haslayer(TCP):
            ip_layer = packet[IP]
            tcp_layer = packet[TCP]
            source_ip = ip_layer.src
            dest_ip = ip_layer.dst
            source_port = tcp_layer.sport
            dest_port = tcp_layer.dport
            protocol = ip_layer.proto
            length = len(packet)
            payload_length = len(packet[TCP].payload) if packet.haslayer(TCP) else 0
            info = (source_ip, dest_ip, source_port, dest_port, protocol, length, payload_length)
            # Insert the packet information into the Treeview
            packet_tree.insert("", tk.END, values=info)
            # Auto-scroll to the last row
            packet_tree.yview_moveto(1.0)
    except Exception as e:
        messagebox.showerror("Error", f"Error processing packet: {e}")

# Function to start packet capture in a separate thread
def start_capture():
    global capture_running
    interface = interface_entry.get()
    if not interface:
        messagebox.showerror("Input Error", "Please enter a network interface.")
        return

    # Capture filters to limit the traffic captured (e.g., HTTP traffic)
    capture_filter = "tcp port 80"

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
interface_entry = tk.Entry(root)
interface_entry.grid(row=0, column=1, padx=10, pady=10)

start_button = tk.Button(root, text="Start Capture", command=start_capture)
start_button.grid(row=1, column=0, padx=10, pady=10)

stop_button = tk.Button(root, text="Stop Capture", command=stop_capture)
stop_button.grid(row=1, column=1, padx=10, pady=10)

# Create Treeview for displaying packet data
columns = ("Source IP", "Destination IP", "Source Port", "Destination Port", "Protocol", "Length", "Payload Length")
packet_tree = ttk.Treeview(root, columns=columns, show='headings', height=15)
packet_tree.grid(row=2, column=0, columnspan=2, padx=10, pady=10)

# Define column headings
for col in columns:
    packet_tree.heading(col, text=col)
    packet_tree.column(col, width=120)  # Adjust width as needed

# Run the Tkinter event loop
root.mainloop()
