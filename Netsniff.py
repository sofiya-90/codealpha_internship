import threading
import time
from scapy.all import sniff, IP, TCP, AsyncSniffer

def packet_callback(packet):
    """This function prints a summary of each captured packet."""
    print(packet.summary())

def detailed_packet_callback(packet):
    """This function displays all details of each captured packet."""
    print(packet.show())

def process_packet(packet):
    """This function processes each captured packet to extract IP and TCP information."""
    if packet.haslayer(IP):  # Check if the packet has an IP layer
        ip_layer = packet.getlayer(IP)
        src_ip = ip_layer.src  # Source IP address
        dst_ip = ip_layer.dst  # Destination IP address
        print(f"IP Packet: {src_ip} -> {dst_ip}")

        if packet.haslayer(TCP):  # Check if the packet has a TCP layer
            tcp_layer = packet.getlayer(TCP)
            src_port = tcp_layer.sport  # Source port number
            dst_port = tcp_layer.dport  # Destination port number
            print(f"TCP Segment: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

def start_sniffing(stop_event):
    """This function starts the packet sniffing process."""
    try:
        # Create an AsyncSniffer instance
        sniffer = AsyncSniffer(prn=packet_callback, count=10)
        sniffer.start()
        stop_event.wait()  # Wait until the stop event is set
        sniffer.stop()

        # Sniffing packets with an IP filter, call detailed_packet_callback function
        sniffer = AsyncSniffer(prn=detailed_packet_callback, filter="ip", store=0)
        sniffer.start()
        stop_event.wait()  # Wait until the stop event is set
        sniffer.stop()

        # Sniffing packets with an IP filter, call process_packet function
        sniffer = AsyncSniffer(prn=process_packet, filter="ip", store=0)
        sniffer.start()
        stop_event.wait()  # Wait until the stop event is set
        sniffer.stop()
    except KeyboardInterrupt:
        # Handle user interrupt (Ctrl+C)
        print("Sniffing stopped by user.")
    except Exception as e:
        # Handle any other exceptions
        print(f"An error occurred: {e}")

def sniffing_thread(stop_event):
    """Thread to run the sniffing process and terminate after timeout."""
    start_sniffing(stop_event)

if __name__ == "__main__":
    # Set the timeout duration (in seconds)
    timeout_duration = 30  # Change this value to set a different timeout duration

    # Create an Event object to stop the sniffing process
    stop_event = threading.Event()

    # Create a thread to run the sniffing process
    thread = threading.Thread(target=sniffing_thread, args=(stop_event,))
    thread.start()

    # Wait for the specified timeout duration
    time.sleep(timeout_duration)

    # Set the stop event to terminate the sniffing process
    stop_event.set()

    # Wait for the thread to finish
    thread.join()
    print("Sniffing completed.")
