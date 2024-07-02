import dpkt
import socket
import os
import json

def parse_smb_packet(packet):
    try:
        eth = dpkt.ethernet.Ethernet(packet)
        ip = eth.data
        tcp = ip.data
        smb = dpkt.smb.SMB(tcp.data)

        if smb.cmd == dpkt.smb.SMB_COM_WRITE:
            # Extract attachment metadata
            file_name = f"file{len(smb.payload)}.doc"
            file_size = len(smb.payload)
            src_ip = socket.inet_ntoa(ip.src)
            src_port = tcp.sport
            dst_ip = socket.inet_ntoa(ip.dst)
            dst_port = tcp.dport

            # Create a folder for extracted files if it doesn't exist
            if not os.path.exists("extracted_files"):
                os.makedirs("extracted_files")

            # Save the attachment to a file
            with open(f"extracted_files/{file_name}", "wb") as f:
                f.write(smb.payload)

            # Save the metadata to a JSON file
            metadata = {
                "file_name": file_name,
                "file_size": file_size,
                "source_ip": src_ip,
                "source_port": src_port,
                "destination_ip": dst_ip,
                "destination_port": dst_port
            }
            with open("metadata.json", "a") as f:
                json.dump(metadata, f)
                f.write("\n")

            print(f"Found attachment: {file_name} ({file_size} bytes)")
            print(f"Extracted metadata: {file_name} ({file_size} bytes)")
            print(f"Source IP: {src_ip}")
            print(f"Source Port: {src_port}")
            print(f"Destination IP: {dst_ip}")
            print(f"Destination Port: {dst_port}")
            print()

    except (IndexError, UnicodeDecodeError, dpkt.dpkt.UnpackError):
        pass

# Read the PCAP file
with open('smb.pcap', 'rb') as f:
    pcap = dpkt.pcap.Reader(f)
    for timestamp, buf in pcap:
        parse_smb_packet(buf)