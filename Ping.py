import os
import sys
import socket
import struct
import select
import time
import signal
import csv
import datetime
from icmp_messages import ICMP_CONTROL_MESSAGE, ICMPv6_CONTROL_MESSAGE
from PingStats import PingStats

# ICMP parameters

ICMP_ECHOREPLY = 0          # Echo reply (per RFC792)
ICMP_ECHO = 8               # Echo request (per RFC792)
ICMP_ECHO_IPV6 = 128        # Echo request (per RFC4443)
ICMP_ECHO_IPV6_REPLY = 129  # Echo request (per RFC4443)
ICMP_PORT = 1
ICMP_PORT_IPV6 = 58
ICMP_MAX_RECV = 2048        # Max size of incoming buffer
MAX_SLEEP = 1000

# Check OS. Windows and Unix-based OS's vary in time implementation
if sys.platform == "win32":
    # On Windows, the best timer is time.clock()
    default_timer = time.clock
else:
    # On most other platforms the best timer is time.time()
    default_timer = time.time


def calculate_checksum(source_string):
    """
    A port of the functionality of in_cksum() from ping.c
    Ideally this would act on the string as a series of 16-bit ints (host
    packed), but this works.
    Network data is big-endian, hosts are typically little-endian
    """
    countTo = (int(len(source_string) / 2)) * 2
    my_sum = 0
    count = 0

    # Handle bytes in pairs (decoding as short ints)
    loByte = 0
    hiByte = 0
    while count < countTo:
        if (sys.byteorder == "little"):
            loByte = source_string[count]
            hiByte = source_string[count + 1]
        else:
            loByte = source_string[count + 1]
            hiByte = source_string[count]
        try:     # For Python3
            my_sum = my_sum + (hiByte * 256 + loByte)
        except:  # For Python2
            my_sum = my_sum + (ord(hiByte) * 256 + ord(loByte))
        count += 2

    # Handle last byte if applicable (odd-number of bytes)
    # Endianness should be irrelevant in this case
    if countTo < len(source_string):  # Check for odd length
        loByte = source_string[len(source_string) - 1]
        try:      # For Python3
            my_sum += loByte
        except:   # For Python2
            my_sum += ord(loByte)

    my_sum &= 0xffffffff  # Truncate sum to 32 bits (a variance from ping.c,
    # which uses signed ints, but overflow is unlikely
    # in ping)

    my_sum = (my_sum >> 16) + (my_sum & 0xffff)  # Add high 16 and low 16 bits
    my_sum += (my_sum >> 16)                     # Add carry from above, if any
    answer = ~my_sum & 0xffff                    # Invert & truncate to 16 bits
    answer = socket.htons(answer)

    return answer


class Ping(object):
    def __init__(self, destination, timeout=3000, packet_size=64, own_id=None,
                 quiet=False, silent=False, ipv6=False):
        self.stats = PingStats
        # Statistics
        self.stats.destination_ip = "0.0.0.0"
        self.stats.destination_host = destination
        self.stats.destination_port = ICMP_PORT
        self.stats.packets_sent = 0
        self.stats.packets_received = 0
        self.stats.lost_rate = 100.0
        self.stats.min_time = 999999999
        self.stats.max_time = 0
        self.stats.total_time = 0
        self.stats.average_time = 0.0

        # Parameters
        self.ipv6 = ipv6
        self.timeout = timeout
        self.packet_size = packet_size - 8
        self.sequence_number = 0
        self.unknown_host = False

        self.silent = silent

        if own_id is None:
            self.own_id = os.getpid() & 0xFFFF
        else:
            self.own_id = own_id

        # Output Streams
        if quiet:
            devnull = open(os.devnull, 'w')
            self._stdout = devnull
            self._stderr = devnull
        else:
            self._stdout = sys.stdout
            self._stderr = sys.stderr

        # Get IP from hostname
        try:
            if self.ipv6:
                self.stats.destination_port = ICMP_PORT_IPV6
                info = socket.getaddrinfo(self.stats.destination_host, None)[0]
                self.stats.destination_ip = info[4][0]
            else:
                self.stats.destination_ip = \
                    socket.gethostbyname(self.stats.destination_host)
        except socket.error:
            etype, evalue, etb = sys.exc_info()
            self._stderr.write("\nERROR: Unknown host: %s (%s)\n" %
                               (self.stats.destination_host, evalue.args[1]))
            #sys.exit(2)
            self.unknown_host = True
            return

        # Print opening line on CSV and command line
        if not self.silent:
            sys.stdout.write("\nTARGET: %s (%s):  PACKET SIZE: %d bytes" %
                             (self.stats.destination_host,
                              self.stats.destination_ip,
                              self.packet_size))
            sys.stdout.write("\n=======================================\n")

    def do_one(self):
        """
        Returns either the delay (in ms) or None on timeout.
        """
        delay = None

        # One could use UDP here, but it's obscure
        if self.ipv6:
            sock_af = socket.AF_INET6
            sock_type = socket.SOCK_RAW
            sock_protocol = socket.getprotobyname("ipv6-icmp")
        else:
            sock_af = socket.AF_INET
            sock_type = socket.SOCK_RAW
            sock_protocol = socket.getprotobyname("icmp")
        try:
            current_socket = socket.socket(sock_af, sock_type, sock_protocol)
        except socket.error:
            etype, evalue, etb = sys.exc_info()
            self._stderr.write("socket.error: %s\n" % evalue)
            self._stderr.write("Note that ICMP messages can only be send "
                               "from processes running as root.\n")
            sys.exit(3)

        send_time = self.send_one_ping(current_socket)

        if send_time is None:
            current_socket.close()
            return delay
        self.stats.packets_sent += 1

        receive_time, packet_size, ip_header, icmp_header = \
            self.receive_one_ping(current_socket)
        current_socket.close()

        icmp_seq_number = icmp_header["seq_number"]
        icmp_type = icmp_header["type"]
        icmp_code = icmp_header["code"]

        if self.ipv6:
            host_addr = self.stats.destination_host
        else:
            host_addr = self.stats.destination_ip

        if host_addr == self.stats.destination_host:
            from_info = host_addr
        else:
            if self.ipv6:
                from_info = self.stats.destination_host
            else:
                from_info = "%s (%s)" % (self.stats.destination_host,
                                         host_addr)

        if receive_time:
            ip_header_ttl = ip_header["ttl"]
            delay = (receive_time - send_time) * 1000.0

            # Write out the packet information when it comes back
            self._stdout.write(
                "Packet number: %d | TTL: %d | Time: %0.3fms\n" % (icmp_seq_number, ip_header_ttl, delay))

            self.stats.packets_received += 1
            self.stats.total_time += delay
            if self.stats.min_time > delay:
                self.stats.min_time = delay
            if self.stats.max_time < delay:
                self.stats.max_time = delay
        else:
            # Timed out - Print out returned ICMP message
            if self.ipv6:
                imcp_message = ICMPv6_CONTROL_MESSAGE[icmp_type][icmp_code]
            else:
                imcp_message = ICMP_CONTROL_MESSAGE[icmp_type][icmp_code]
            delay = None
            self._stdout.write("From %s: icmp_seq=%d %s\n" %
                               (self.stats.destination_ip, icmp_seq_number, imcp_message))

        return delay

    def send_one_ping(self, current_socket):
        """
        Send one ping to the given >destIP<.
        """

        # Header is type (8), code (8), checksum (16), id (16), sequence (16)
        # (numDataBytes - 8) - Remove header size from packet size
        checksum = 0

        # Make a dummy header with a 0 checksum.
        if self.ipv6:
            header = struct.pack(
                "!BbHHh", ICMP_ECHO_IPV6, 0, checksum,
                self.own_id, self.sequence_number
            )
        else:
            header = struct.pack(
                "!BBHHH", ICMP_ECHO, 0, checksum,
                self.own_id, self.sequence_number
            )

        pad_bytes = []
        start_val = 0x42

        # We need to build the data differently for different
        # versions of python, else it will make packets of
        # unexpected sizes
        if sys.version[:1] == '2':
            # Version 2.*
            byte = struct.calcsize("d")
            data = (self.packet_size - byte) * "Q"
            data = struct.pack("d", default_timer()) + data
        else:
            # Version 3+
            for i in range(start_val, start_val + self.packet_size):
                pad_bytes += [(i & 0xff)]  # Keep chars in the 0-255 range
            data = bytearray(pad_bytes)

        # Calculate the checksum on the data and the dummy header.
        # Checksum is in network order
        checksum = calculate_checksum(header + data)

        # Now that we have the right checksum, we put that in. It's just easier
        # to make up a new header than to stuff it into the dummy
        if self.ipv6:
            header = struct.pack("!BbHHh", ICMP_ECHO_IPV6, 0, checksum,
                                 self.own_id, self.sequence_number)
        else:
            header = struct.pack("!BBHHH", ICMP_ECHO, 0, checksum,
                                 self.own_id, self.sequence_number)

        # Build packet and calculate time it was sent
        packet = header + data
        send_time = default_timer()

        try:
            if self.ipv6:
                current_socket.sendto(packet, (self.stats.destination_ip,
                                               self.stats.destination_port,
                                               0, 0))
            else:
                current_socket.sendto(packet, (self.stats.destination_ip,
                                               self.stats.destination_port))
        except socket.error:
            etype, evalue, etb = sys.exc_info()
            self._stderr.write("General failure (%s)\n" % (evalue.args[1]))
            send_time = None

        return send_time

    def receive_one_ping(self, current_socket):
        """
        Receive the ping from the socket. Timeout = in ms
        """

        time_left = self.timeout / 1000.0

        # Loop while waiting for packet or timeout
        while True:
            select_start = default_timer()
            what_ready = select.select([current_socket], [], [], time_left)
            select_duration = (default_timer() - select_start)
            time_received = default_timer()
            packet_data, addr = current_socket.recvfrom(ICMP_MAX_RECV)

            if self.ipv6:
                icmp_header_raw = packet_data[0:8]
            else:
                icmp_header_raw = packet_data[20:28]

            icmp_header = self.convert_header_dictionary(
                names = [
                    "type",
                    "code",
                    "checksum",
                    "packet_id",
                    "seq_number"
                ],
                struct_format = "!BBHHH",
                data = icmp_header_raw)

            ip_header = None

            # TODO: Still need to work on IPv6 Headers
            if icmp_header["packet_id"] == self.own_id:  # Our packet
                if self.ipv6:
                    ip_header = self.convert_header_dictionary (
                        names = [
                            "version",
                            "type",
                            "flow_label",
                            "payload_length",
                            "protocol",
                            "ttl",
                            "src_ip",
                            "dest_ip"
                        ],
                        struct_format="!BBHHBBdd",
                        data=packet_data[:24]
                        # "src_ip_a", "src_ip_b", "dest_ip_a", "dest_ip_b"
                        # ],
                        # struct_format="!BBHHBBQQQQ",
                        # data=packet_data[:40]
                    )
                # ip_header['src_ip'] = ip_header['src_ip_a'] + ip_header['src_ip_b']
                # ip_header['dest_ip'] = ip_header['dest_ip_a'] + ip_header['dest_ip_b']
                else:
                    ip_header = self.convert_header_dictionary (
                        names = [
                            "version",
                            "type",
                            "length",
                            "id",
                            "flags",
                            "ttl",
                            "protocol",
                            "checksum",
                            "src_ip",
                            "dest_ip"
                        ],
                        struct_format="!BBHHHBBHII",
                        data = packet_data[:20]
                    )

            if what_ready[0] == []:  # Timeout
                return None, 0, ip_header, icmp_header

            if icmp_header["packet_id"] == self.own_id:  # Our packet
                data_size = len(packet_data) - 28
                return time_received, (data_size + 8), ip_header, icmp_header

            time_left = time_left - select_duration

            if time_left <= 0:
                return None, 0, ip_header, icmp_header

    def calculate_packet_loss(self):
        if self.stats.packets_sent:
            lost_count = self.stats.packets_sent - self.stats.packets_received
            self.stats.lost_rate = \
                float(lost_count) / self.stats.packets_sent * 100.0
        else:
            self.stats.lost_rate = 100.0

    def calculate_packet_average(self):
        if self.stats.packets_received:
            self.stats.average_time = \
                self.stats.total_time / self.stats.packets_received
        else:
            self.stats.average_time = 0.0

    def print_stats(self):

        # If running in silent mode, don't print out to the console
        if self.silent:
            return

        # Header for the network analysis
        sys.stdout.write("\nCompleted analysis on: %s" % self.stats.destination_host)
        sys.stdout.write("\n=======================================")

        # Calculate packet loss
        self.calculate_packet_loss()
        sys.stdout.write(
            "\nPackets sent: %d"
            "\nPackets received: %d"
            "\nPacket loss: %0.1f%%"
            "\nTotal Time: %dms\n" % (
                self.stats.packets_sent,
                self.stats.packets_received,
                self.stats.lost_rate,
                self.stats.total_time
            ))

        if self.stats.packets_received > 0:
            # Calculate the average packet time
            self.calculate_packet_average()
            sys.stdout.write(
                "\nMinimum RTT: %0.3fms"
                "\nAverage RTT: %0.3fms"
                "\nMaximum RTT: %0.3fms\n\n" % (
                    self.stats.min_time,
                    self.stats.average_time,
                    self.stats.max_time))

        # Write results to the CSV data file
        timestamp = datetime.datetime.now()
        timestamp.isoformat()
        csv_data_storage = open('data.csv','a')
        csv_data_storage.write(("\n" +
                                str(timestamp) + "," +
                                str(self.stats.lost_rate) + "," +
                                str(self.stats.min_time)  + "," +
                                str(self.stats.average_time) + "," +
                                str(self.stats.max_time)))
        csv_data_storage.close()

    def convert_header_dictionary(self, names, struct_format, data):
        """
        Unpack the raw received IP and ICMP header info into to a dictionary
        """
        unpacked_data = struct.unpack(struct_format, data)
        return dict(list(zip(names, unpacked_data)))

    def signal_handler(self, signum, frame):
        """
        Handle print_exit via signals
        """
        self.calculate_packet_loss()
        self.print_stats()
        #self._stdout.write("\n(Terminated with signal %d)\n" % (signum))
        sys.exit(not self.stats.packets_received)

    def setup_signal_handler(self):
        signal.signal(signal.SIGINT, self.signal_handler)   # Handle Ctrl-C
        if hasattr(signal, "SIGBREAK"):
            # Handle Ctrl-Break e.g. under Windows
            signal.signal(signal.SIGBREAK, self.signal_handler)

    def run(self, count=None, deadline=None):
        """
        send and receive pings in a loop. Stop if count or until deadline.
        """
        self.setup_signal_handler()

        while True:
            if self.unknown_host:
                return self.stats

            delay = self.do_one()

            self.sequence_number += 1
            if count and self.sequence_number >= count:
                break
            if deadline and self.stats.total_time >= deadline:
                break

            #if delay == None:
            if delay is None:
                delay = 0

            # Pause for the remainder of the MAX_SLEEP period (if applicable)
            if (MAX_SLEEP > delay):
                time.sleep((MAX_SLEEP - delay) / 1000.0)

        self.calculate_packet_loss()
        self.print_stats()
        return self.stats
