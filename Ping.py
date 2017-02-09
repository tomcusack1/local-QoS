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
ICMP_ECHOREPLY = 0          # Echo reply   (per RFC792)
ICMP_ECHO = 8               # Echo request (per RFC792)
ICMP_ECHO_IPV6 = 128        # Echo request (per RFC4443)
ICMP_ECHO_IPV6_REPLY = 129  # Echo request (per RFC4443)
ICMP_PORT = 1
ICMP_PORT_IPV6 = 58
ICMP_MAX_RECV = 2048        # Max size of incoming buffer
MAX_SLEEP = 1000
default_timer = time.time


def calculate_checksum(header: str) -> int:
    """
    A port of the functionality of in_cksum() from ping.c
    Ideally this would act on the string as a series of 16-bit ints (host
    packed), but this works.
    Network data is big-endian, hosts are typically little-endian
    """

    # Handle bytes in pairs (decoding as short ints)
    low_byte = 0
    high_byte = 0

    count_to = (int(len(header) / 2)) * 2
    total = 0
    count = 0

    while count < count_to:
        if sys.byteorder == "little":
            low_byte = int(header[count])
            high_byte = int(header[count + 1])
        else:
            low_byte = int(header[count + 1])
            high_byte = int(header[count])

        total += high_byte * 256 + low_byte

        count += 2

    if count_to < len(header):
        # Handle last byte if applicable (odd-number of bytes)
        low_byte = header[len(header) - 1]
        total += low_byte

    # Truncate sum to 32 bits (a variance from ping.c, which uses signed ints, but overflow is unlikely in ping)
    total &= 0xffffffff
    total = (total >> 16) + (total & 0xffff)  # Add high 16 and low 16 bits
    total += (total >> 16)                     # Add carry from above, if any
    answer = ~total & 0xffff                    # Invert & truncate to 16 bits
    answer = socket.htons(answer)

    return answer


class Ping(object):
    def __init__(self, destination, timeout=3000, packet_size=64, own_id=None, quiet=False, silent=False, ipv6=False):
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
        self.packet_sent_time = []
        self.packet_received_time = []

        # Parameters
        self.ipv6 = ipv6
        self.timeout = timeout
        self.packet_size = packet_size - 8
        self.sequence_number = 0
        self.unknown_host = False

        self.connected_devices = []

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
                self.stats.destination_ip = socket.gethostbyname(self.stats.destination_host)
        except socket.error:
            error_type, error_value, etb = sys.exc_info()
            self._stderr.write("\nERROR: Unknown host: %s (%s)\n" % (self.stats.destination_host, error_value.args[1]))
            self.unknown_host = True
            return

    def calculate_ping_delay(self):
        """Example function with PEP 484 type annotations.

        Args:
            param1: The first parameter.
            param2: The second parameter.

        Returns:
            The return value. True for success, False otherwise.

        """
        delay = None
        sock_af = socket.AF_INET
        sock_type = socket.SOCK_RAW
        sock_protocol = socket.getprotobyname("icmp")

        try:
            current_socket = socket.socket(sock_af, sock_type, sock_protocol)
        except socket.error:
            error_type, error_value, etb = sys.exc_info()
            self._stderr.write("socket.error: %s\n" % error_value)
            self._stderr.write("Note that ICMP messages can only be send "
                               "from processes running as root.\n")
            sys.exit(3)

        send_time = self.send_ping(current_socket)
        # print("Sent ping at: %2f" % send_time)

        if send_time is None:
            current_socket.close()
            return delay

        self.stats.packets_sent += 1

        receive_time, packet_size, ip_header, icmp_header = self.receive_ping(current_socket)
        # print("Received ping at: %2f" % receive_time)

        self.packet_sent_time.append(send_time)
        self.packet_received_time.append(receive_time)

        current_socket.close()

        icmp_sequence_number = icmp_header["seq_number"]
        icmp_type = icmp_header["type"]
        icmp_code = icmp_header["code"]
        host_address = self.stats.destination_ip

        if host_address == self.stats.destination_host:
            from_info = host_address
        else:
            from_info = "%s (%s)" % (self.stats.destination_host, host_address)

        if receive_time:
            ip_header_ttl = ip_header["ttl"]
            delay = (receive_time - send_time) * 1000.0
            self.stats.packets_received += 1
            self.stats.total_time += delay

            if self.stats.min_time > delay:
                self.stats.min_time = delay
            if self.stats.max_time < delay:
                self.stats.max_time = delay
        else:
            # Timed out - Print out returned ICMP message
            delay = None
            self._stdout.write("Timeout.")

        return delay

    def send_ping(self, current_socket: socket.socket) -> float:
        """Example function with PEP 484 type annotations.

        Args:
            param1: The first parameter.
            param2: The second parameter.

        Returns:
            The return value. True for success, False otherwise.

        """
        checksum = 0

        # Make a dummy header with a 0 checksum.
        header = struct.pack("!BBHHH", ICMP_ECHO, 0, checksum, self.own_id, self.sequence_number)
        pad_bytes = []
        start_val = 0x42

        for i in range(start_val, start_val + self.packet_size):
            pad_bytes += [(i & 0xff)]  # Keep chars in the 0-255 range

        data = bytearray(pad_bytes)

        # Calculate the checksum on the data and the dummy header. Checksum is in network order
        checksum = calculate_checksum(header + data)

        # Now that we have the right checksum, we put that in. It's just easier
        # to make up a new header than to stuff it into the dummy
        header = struct.pack("!BBHHH", ICMP_ECHO, 0, checksum, self.own_id, self.sequence_number)

        # Build packet and record time it was sent
        packet = header + data
        send_time = default_timer()
        print(send_time)

        try:
            current_socket.sendto(packet, (self.stats.destination_ip, self.stats.destination_port))
        except socket.error:
            error_type, error_value, etb = sys.exc_info()
            self._stderr.write("General failure (%s)\n" % (error_value.args[1]))
            send_time = None

        return send_time

    def receive_ping(self, current_socket: socket.socket):
        """A ping listener. Opens the current socket, and waits for a sent ping to come back.

        Args:
            current_socket: The connection being used to send pings to

        Returns:
            The time in ms the amount of time the ping took to be received
            None: The connection timed out, or the host was not valid

        """

        time_left = self.timeout / 1000.0

        while True:

            start_time = default_timer()
            open_connection = select.select([current_socket], [], [], time_left)
            wait_time = default_timer() - start_time
            time_received = default_timer()

            packet_data, address = current_socket.recvfrom(ICMP_MAX_RECV)
            icmp_header_raw = packet_data[20:28]
            icmp_header = self.convert_header_dictionary(names=["type", "code", "checksum", "packet_id", "seq_number"],
                                                         struct_format="!BBHHH", data=icmp_header_raw)
            ip_header = self.convert_header_dictionary(names=["version", "type", "length", "id", "flags", "ttl",
                                                              "protocol", "checksum", "src_ip", "dest_ip"],
                                                       struct_format="!BBHHHBBHII", data = packet_data[:20])

            if open_connection[0] is None:
                return None, 0, ip_header, icmp_header

            if icmp_header["packet_id"] == self.own_id:
                data_size = len(packet_data) - 28
                return time_received, (data_size + 8), ip_header, icmp_header

            time_left -= wait_time

            if time_left <= 0:
                return None, 0, ip_header, icmp_header

    def calculate_packet_loss(self) -> float:
        """Example function with PEP 484 type annotations.

        Args:
            param1: The first parameter.
            param2: The second parameter.
        Returns:
            The return value. True for success, False otherwise.

        """
        if self.stats.packets_sent:
            lost_count = self.stats.packets_sent - self.stats.packets_received
            self.stats.lost_rate = float(lost_count) / self.stats.packets_sent * 100.0
        else:
            self.stats.lost_rate = 100.0

    def calculate_packet_average(self) -> float:
        """Example function with PEP 484 type annotations.

        Args:
            param1: The first parameter.
            param2: The second parameter.
        Returns:
            The return value. True for success, False otherwise.

        """
        if self.stats.packets_received:
            self.stats.average_time = self.stats.total_time / self.stats.packets_received
        else:
            self.stats.average_time = 0.0

    def calculate_bandwidth(self) -> float:
        """
            Calculates bandwidth using formula: Packet Size (0.064kb) / Average RTT (14.1599ms) = Bandwidth (4.23 Mb/s)
            e.g. 1 packet = 56 bytes (+ 8b header) = 0.064kb bytes sent
        """
        # TODO: Test and verify bandwidth readings
        packet_size_in_kb = (self.packet_size + 8) / 1000.00
        return packet_size_in_kb / self.stats.average_time

    def calculate_jitter(self) -> float:
        """
        Example function with PEP 484 type annotations.

        Args:
            param1: The first parameter.
            param2: The second parameter.
        Returns:
            The return value. True for success, False otherwise.


            Gets the difference in time from 2 packets and calculates the jitter
            i.e. 1485176622.90079 - 1485176621.897069 = 1.00372099876 - 1
            Returns a float representation of the jitter (IPDV)
        """
        i = 0
        jitter = []

        while i < len(self.packet_received_time):
            try:
                # Get the difference between the two packets and subtract it from the transmission rate
                window = self.packet_received_time[i + 1] - self.packet_received_time[i]
                jitter.append(window - 1)
                i += 2
            except IndexError:
                sum(jitter) / float(len(jitter))

        return sum(jitter) / float(len(jitter))

    def export_data(self):
        """Example function with PEP 484 type annotations.

        Args:
            param1: The first parameter.
            param2: The second parameter.
        Returns:
            The return value. True for success, False otherwise.

        """
        self.calculate_packet_loss()
        jitter = 0.00
        bandwidth = 0.00

        if self.stats.packets_received > 0:
            self.calculate_packet_average()
            bandwidth = self.calculate_bandwidth()
            jitter = self.calculate_jitter()

        # Export results to CSV
        timestamp = datetime.datetime.now()
        timestamp.isoformat()
        csv_data_storage = open('data/' + str(datetime.date.today()) + '.csv', 'a')
        csv_data_storage.write(("\n" +
                                str(self.stats.destination_ip) + "," +
                                str(timestamp) + "," +
                                str(self.stats.lost_rate) + "," +
                                str(self.stats.min_time) + "," +
                                str(self.stats.average_time) + "," +
                                str(self.stats.max_time) + "," +
                                str(bandwidth) + "," +
                                str(jitter)))
        csv_data_storage.close()

        # sys.stdout.write("Exported data to CSV.\n")

    def convert_header_dictionary(self, names, struct_format, data) -> dict:
        """Example function with PEP 484 type annotations.

        Args:
            param1: The first parameter.
            param2: The second parameter.
        Returns:
            The return value. True for success, False otherwise.

        """
        unpacked_data = struct.unpack(struct_format, data)
        return dict(list(zip(names, unpacked_data)))

    def signal_handler(self, signum, frame):
        """Example function with PEP 484 type annotations.

        Args:
            param1: The first parameter.
            param2: The second parameter.
        Returns:
            The return value. True for success, False otherwise.

        Handle print_exit via signals
        """
        self.calculate_packet_loss()
        self.export_data()
        sys.exit(not self.stats.packets_received)

    def setup_signal_handler(self):
        """Example function with PEP 484 type annotations.

        Args:
            param1: The first parameter.
            param2: The second parameter.
        Returns:
            The return value. True for success, False otherwise.

        """
        # Handle Ctrl-C
        signal.signal(signal.SIGINT, self.signal_handler)

        if hasattr(signal, "SIGBREAK"):
            # Handle Windows conditions
            signal.signal(signal.SIGBREAK, self.signal_handler)

    def run(self, count=None, deadline=None):
        """Example function with PEP 484 type annotations.

        Args:
            param1: The first parameter.
            param2: The second parameter.
        Returns:
            The return value. True for success, False otherwise.

        """
        #self.setup_signal_handler()

        while True:
            if self.unknown_host:
                return self.stats

            delay = self.calculate_ping_delay()

            self.sequence_number += 1

            if count and self.sequence_number >= count:
                break

            if deadline and self.stats.total_time >= deadline:
                break

            if delay is None:
                delay = 0

            # Pause for the remainder of the MAX_SLEEP period (if applicable)
            if (MAX_SLEEP > delay):
                time.sleep((MAX_SLEEP - delay) / 1000.0)

        self.calculate_packet_loss()
        self.export_data()
        return self.stats
