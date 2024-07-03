import dpkt
import socket
import os
import json

def parse_smb_packet(packet):
     try:
        eth = dpkt.ethernet.Ethernet(packet)
        ip = eth.data
        tcp = ip.data

        # Check if the packet contains SMB data
        if len(tcp.data) < 4 or tcp.data[:4] != b'\xff\x53\x4d\x42':
            # This packet does not contain valid SMB data, skip it
            return

        # Parse the SMB command
        smb_cmd = tcp.data[4]

        if smb_cmd == 0x0B:  # SMB_COM_WRITE
            # Extract attachment metadata
            file_name = f"file{len(tcp.data) - 36}.doc"
            file_size = len(tcp.data) - 36
            src_ip = socket.inet_ntoa(ip.src)
            src_port = tcp.sport
            dst_ip = socket.inet_ntoa(ip.dst)
            dst_port = tcp.dport

                # Create a folder for extracted files if it doesn't exist
        if not os.path.exists("extracted_files"):
                    os.makedirs("extracted_files")

                # Save the attachment to a file
        with open(f"extracted_files/{file_name}", "wb") as f:
                    f.write(tcp.data[36:])

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

def main():
    try:
        pcap_file = input("smb.pcap", "rb")
        with open(pcap_file, "rb") as f:
            pcap = dpkt.pcap.Reader(f)
            for timestamp, packet in pcap:
                parse_smb_packet(packet)
    except FileNotFoundError:
        print(f"Error: {pcap_file} file not found.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
