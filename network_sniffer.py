#!/usr/bin/env python3

import os
import sys
import threading
import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext
from datetime import datetime
from scapy.all import sniff
from scapy.all import IP
from scapy.all import TCP
from scapy.all import UDP
from scapy.all import ICMP
from scapy.all import Raw
from scapy.utils import wrpcap


class NetworkSniffer:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Sniffer - CodeAlpha")
        self.root.geometry("1200x750")
        self.root.configure(bg='#1e1e1e')
        
        # tracking variables
        self.sniffing = False
        self.packet_count = 0
        self.packets = []
        # had to cap this at 100 or the table gets laggy
        self.MAX_PACKETS = 100
        
        self.build_ui()
        self.update_status("Ready - Click Start to capture packets")
    
    def build_ui(self):
        # ---------- Control Panel ----------
        control_frame = tk.Frame(self.root, bg='#2d2d2d')
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # start button
        self.start_btn = tk.Button(
            control_frame,
            text="Start",
            command=self.start_sniffing,
            bg='#007acc',
            fg='white',
            font=('Arial', 10, 'bold'),
            padx=10
        )
        self.start_btn.pack(side=tk.LEFT, padx=2)
        
        # stop button
        self.stop_btn = tk.Button(
            control_frame,
            text="Stop",
            command=self.stop_sniffing,
            bg='#cc3333',
            fg='white',
            font=('Arial', 10, 'bold'),
            state=tk.DISABLED,
            padx=10
        )
        self.stop_btn.pack(side=tk.LEFT, padx=2)
        
        # clear button
        self.clear_btn = tk.Button(
            control_frame,
            text="Clear",
            command=self.clear_table,
            bg='#e68a00',
            fg='white',
            font=('Arial', 10, 'bold'),
            padx=10
        )
        self.clear_btn.pack(side=tk.LEFT, padx=2)
        
        # save button
        self.save_btn = tk.Button(
            control_frame,
            text="Save",
            command=self.save_packets,
            bg='#0066cc',
            fg='white',
            font=('Arial', 10, 'bold'),
            padx=10
        )
        self.save_btn.pack(side=tk.LEFT, padx=2)
        
        # packet counter
        self.counter_label = tk.Label(
            control_frame,
            text="Packets: 0/100",
            bg='#2d2d2d',
            fg='#4fc3f7',
            font=('Arial', 11, 'bold')
        )
        self.counter_label.pack(side=tk.RIGHT, padx=10)
        
        # ---------- Packet Table ----------
        table_frame = tk.Frame(self.root, bg='#1e1e1e')
        table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # style the table
        style = ttk.Style()
        style.theme_use('clam')
        style.configure(
            "Treeview",
            background="#2d2d2d",
            foreground="#e0e0e0",
            fieldbackground="#2d2d2d",
            font=('Consolas', 9)
        )
        style.configure(
            "Treeview.Heading",
            background="#3c3c3c",
            foreground="#4fc3f7",
            font=('Arial', 9, 'bold')
        )
        style.map('Treeview', background=[('selected', '#007acc')])
        
        # define columns - all required fields from Task 1
        columns = (
            '#',
            'Time',
            'Protocol',
            'Src IP',
            'Src Port',
            'Dst IP',
            'Dst Port',
            'Length',
            'Payload Preview'
        )
        self.tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show='headings',
            height=15
        )
        
        # set column widths
        column_widths = [45, 110, 80, 140, 70, 140, 70, 60, 250]
        for col, width in zip(columns, column_widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, anchor='center' if col != 'Payload Preview' else 'w')
        
        # scrollbars
        vertical_scroll = ttk.Scrollbar(
            table_frame,
            orient=tk.VERTICAL,
            command=self.tree.yview
        )
        horizontal_scroll = ttk.Scrollbar(
            table_frame,
            orient=tk.HORIZONTAL,
            command=self.tree.xview
        )
        self.tree.configure(
            yscrollcommand=vertical_scroll.set,
            xscrollcommand=horizontal_scroll.set
        )
        
        # layout with grid
        self.tree.grid(row=0, column=0, sticky='nsew')
        vertical_scroll.grid(row=0, column=1, sticky='ns')
        horizontal_scroll.grid(row=1, column=0, sticky='ew')
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)
        
        # double-click to see details
        self.tree.bind('<Double-Button-1>', self.show_details)
        
        # ---------- Status Bar ----------
        self.status_variable = tk.StringVar()
        status_bar = tk.Label(
            self.root,
            textvariable=self.status_variable,
            bg='#2d2d2d',
            fg='#e0e0e0',
            anchor=tk.W,
            padx=10,
            relief=tk.SUNKEN
        )
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def update_status(self, message):
        """update the status bar text"""
        self.status_variable.set(message)
    
    # this is where packets get processed
    def packet_callback(self, packet):
        if not self.sniffing or self.packet_count >= self.MAX_PACKETS:
            return
        
        self.packet_count += 1
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        # default values
        src_ip = '-'
        dst_ip = '-'
        src_port = '-'
        dst_port = '-'
        protocol = 'Unknown'
        payload_preview = '-'
        
        # check for IP layer
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            
            # check transport protocols
            if packet.haslayer(TCP):
                src_port = str(packet[TCP].sport)
                dst_port = str(packet[TCP].dport)
                protocol = 'TCP'
                flags = packet[TCP].flags
                payload_preview = f"Flags: {flags}"
            elif packet.haslayer(UDP):
                src_port = str(packet[UDP].sport)
                dst_port = str(packet[UDP].dport)
                protocol = 'UDP'
                payload_preview = 'UDP Packet'
            elif packet.haslayer(ICMP):
                protocol = 'ICMP'
                payload_preview = f"Type: {packet[ICMP].type}"
        
        # try to get payload preview
        if packet.haslayer(Raw):
            raw_data = packet[Raw].load
            try:
                # first 30 bytes as text for preview
                text_preview = raw_data[:30].decode('ascii', errors='ignore')
                clean_preview = ''.join(c if c.isprintable() else '.' for c in text_preview)
                if payload_preview == '-':
                    payload_preview = clean_preview
                else:
                    payload_preview += f" | Payload: {clean_preview}"
            except Exception:
                # not every packet has a readable payload, skip if it fails
                if payload_preview == '-':
                    payload_preview = '(binary data)'
        
        # store for saving later
        self.packets.append(packet)
        
        # update the GUI (thread-safe)
        self.root.after(
            0,
            self.update_table,
            self.packet_count,
            timestamp,
            protocol,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            len(packet),
            payload_preview[:50]
        )
        self.root.after(0, self.update_counter)
    
    def update_table(self, count, timestamp, protocol, src_ip, src_port,
                     dst_ip, dst_port, length, payload_preview):
        # remove oldest if we hit the limit
        if len(self.tree.get_children()) >= 100:
            self.tree.delete(self.tree.get_children()[0])
        
        values = (
            count,
            timestamp,
            protocol,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            length,
            payload_preview
        )
        self.tree.insert('', tk.END, values=values)
        self.tree.yview_moveto(1.0)
    
    def update_counter(self):
        self.counter_label.config(text=f"Packets: {self.packet_count}/{self.MAX_PACKETS}")
        self.update_status(f"Captured {self.packet_count} of {self.MAX_PACKETS} packets")
        
        if self.packet_count >= self.MAX_PACKETS:
            self.stop_sniffing()
    
    def start_sniffing(self):
        print("[DEBUG] Starting packet capture...")  # will remove later
        
        if self.packet_count >= self.MAX_PACKETS:
            self.update_status("Already captured 100 packets. Click Clear.")
            return
        
        self.sniffing = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.update_status("Capturing packets...")
        
        # run sniffing in a background thread so the GUI doesn't freeze
        self.sniffer_thread = threading.Thread(
            target=self.run_sniffer,
            daemon=True
        )
        self.sniffer_thread.start()
    
    def run_sniffer(self):
        try:
            sniff(
                prn=self.packet_callback,
                stop_filter=lambda pkt: not self.sniffing or self.packet_count >= self.MAX_PACKETS,
                store=0
            )
        except Exception as error:
            self.root.after(0, lambda: self.update_status(f"Error: {error}"))
    
    def stop_sniffing(self):
        self.sniffing = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        
        if self.packet_count >= self.MAX_PACKETS:
            self.update_status(f"Captured {self.MAX_PACKETS} packets - Complete")
        else:
            self.update_status(f"Stopped after {self.packet_count} packets")
    
    def clear_table(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        self.packet_count = 0
        self.packets = []
        self.counter_label.config(text=f"Packets: 0/{self.MAX_PACKETS}")
        self.update_status("Cleared - Ready")
        self.start_btn.config(state=tk.NORMAL)
    
    def save_packets(self):
        if not self.packets:
            self.update_status("No packets to save")
            return
        
        filename = f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        try:
            wrpcap(filename, self.packets)
            self.update_status(f"Saved {len(self.packets)} packets to {filename}")
        except Exception as error:
            self.update_status(f"Save error: {error}")
    
    def show_details(self, event):
        """double-click to open full packet details in a new window"""
        selected = self.tree.selection()
        if not selected:
            return
        
        values = self.tree.item(selected[0])['values']
        if not values:
            return
        
        packet_index = values[0] - 1
        if packet_index < 0 or packet_index >= len(self.packets):
            return
        
        packet = self.packets[packet_index]
        
        # create a new window
        detail_window = tk.Toplevel(self.root)
        detail_window.title(f"Packet #{values[0]} Details")
        detail_window.geometry("800x600")
        detail_window.configure(bg='#1e1e1e')
        
        # text area for details
        detail_text = scrolledtext.ScrolledText(
            detail_window,
            bg='#2d2d2d',
            fg='#e0e0e0',
            font=('Consolas', 10),
            wrap=tk.WORD
        )
        detail_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        detail_text.insert(tk.END, f"PACKET #{values[0]} DETAILS\n")
        detail_text.insert(tk.END, "-" * 50 + "\n\n")
        
        # Source and destination
        if packet.haslayer(IP):
            detail_text.insert(tk.END, f"Source IP: {packet[IP].src}\n")
            detail_text.insert(tk.END, f"Destination IP: {packet[IP].dst}\n\n")
        else:
            detail_text.insert(tk.END, "No IP layer found\n\n")
        
        # Protocol and port info
        if packet.haslayer(TCP):
            detail_text.insert(tk.END, f"Protocol: TCP\n")
            detail_text.insert(tk.END, f"Source Port: {packet[TCP].sport}\n")
            detail_text.insert(tk.END, f"Destination Port: {packet[TCP].dport}\n")
            detail_text.insert(tk.END, f"Flags: {packet[TCP].flags}\n\n")
        elif packet.haslayer(UDP):
            detail_text.insert(tk.END, f"Protocol: UDP\n")
            detail_text.insert(tk.END, f"Source Port: {packet[UDP].sport}\n")
            detail_text.insert(tk.END, f"Destination Port: {packet[UDP].dport}\n\n")
        elif packet.haslayer(ICMP):
            detail_text.insert(tk.END, f"Protocol: ICMP\n")
            detail_text.insert(tk.END, f"Type: {packet[ICMP].type}\n")
            if hasattr(packet[ICMP], 'code'):
                detail_text.insert(tk.END, f"Code: {packet[ICMP].code}\n")
            detail_text.insert(tk.END, "\n")
        else:
            detail_text.insert(tk.END, "Protocol: Unknown/Other\n\n")
        
        detail_text.insert(tk.END, f"Packet Length: {len(packet)} bytes\n")
        detail_text.insert(tk.END, f"Time: {datetime.now().strftime('%H:%M:%S')}\n\n")
        
        detail_text.insert(tk.END, "-" * 50 + "\n")
        detail_text.insert(tk.END, "PAYLOAD DATA:\n")
        detail_text.insert(tk.END, "-" * 30 + "\n")
        
        # Show payload with hex dump - keeping the useful code
        if packet.haslayer(Raw):
            raw_data = packet[Raw].load
            detail_text.insert(tk.END, f"Payload Size: {len(raw_data)} bytes\n\n")
            
            # Hex dump
            detail_text.insert(tk.END, "Hex Dump:\n")
            hex_str = raw_data.hex()
            for i in range(0, len(hex_str), 32):
                detail_text.insert(tk.END, f"  {hex_str[i:i+32]}\n")
            
            detail_text.insert(tk.END, "\n")
            
            # ASCII preview
            try:
                ascii_str = raw_data.decode('ascii', errors='ignore')
                clean_str = ''.join(c if c.isprintable() or c in '\n\r\t' else '.' for c in ascii_str)
                detail_text.insert(tk.END, "ASCII Preview:\n")
                detail_text.insert(tk.END, f"  {clean_str[:200]}\n")
                if len(clean_str) > 200:
                    detail_text.insert(tk.END, "  ... (truncated)\n")
            except:
                detail_text.insert(tk.END, "ASCII Preview: (not valid ASCII)\n")
        else:
            detail_text.insert(tk.END, "No raw payload data available\n")
        
        detail_text.config(state=tk.DISABLED)


# had to add this after writing the class - realized we need admin/root
def check_privileges():
    """check if we have the permissions we need"""
    try:
        if os.name == 'nt':  # Windows
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:  # Linux/Mac
            return os.getuid() == 0
    except:
        return False


# need root/admin to open raw sockets, scapy will fail without this
if not check_privileges():
    if os.name == 'nt':
        print("[-] Error: Run as Administrator (Right-click -> Run as administrator)")
    else:
        print("[-] Error: Run with sudo (sudo python3 sniffer.py)")
    sys.exit(1)


# main entry point
if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkSniffer(root)
    root.mainloop()
