#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
ICMP Control Messages
http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages
ICMP Types 0, 3, 4, 5, 8, 11, 12, 13, 14 from RFC792
ICMP Types 9, 11 from RFC1256
"""
ICMP_CONTROL_MESSAGE = \
    {0: {0: 'Echo Reply',
        },
     3: {0: 'Net Unreachable',
         1: 'Host Unreachable',
         2: 'Destination protocol unreachable',
         3: 'Destination port unreachable',
         4: 'Fragmentation required, and DF flag set',
         5: 'Source route failed',
         6: 'Destination network unknown',
         7: 'Destination host unknown',
         8: 'Source host isolated',
         9: 'Network administratively prohibited',
         10: 'Host administratively prohibited',
         11: 'Network unreachable for TOS',
         12: 'Host unreachable for TOS',
         13: 'Communication administratively prohibited',
         14: 'Host Precedence Violation',
         15: 'Precedence cutoff in effect',
        },
     4: {0: 'Source quench',
        },
     5: {0: 'Redirect Datagram for the Network',
         1: 'Redirect Datagram for the Host',
         2: 'Redirect Datagram for the TOS & network',
         3: 'Redirect Datagram for the TOS & host',
        },
     8: {0: 'Echo request',
        },
     9: {0: 'Router Advertisement',
        },
     10: {0: 'Router discovery/selection/solicitation',
         },
     11: {0: 'TTL expired in transit',
          1: 'Fragment reassembly time exceeded',
         },
     12: {0: 'Pointer indicates the error',
          1: 'Missing a required option',
          2: 'Bad length',
         },
     13: {0: 'Timestamp',
         },
     14: {0: 'Timestamp reply',
         },
    }


"""
ICMPv6 Control Messages
http://en.wikipedia.org/wiki/ICMPv6#Types_of_ICMPv6_messages
ICMPv6 Types 0-127 are Error Messages
ICMPv6 Types 128-255 are Informational Messages
"""
ICMPv6_CONTROL_MESSAGE = \
    {1: {0: 'no route to destination',
         1: 'communication with destination administratively prohibited',
         2: 'beyond scope of source address',
         3: 'address unreachable',
         4: 'port unreachable',
         5: 'source address failed ingress/egress policy',
         6: 'reject route to destination',
         7: 'Error in Source Routing Header',
        },
     2: {0: 'packet too big',
        },
     3: {0: 'hop limit exceeded in transit',
         1: 'fragment reassembly time exceeded',
        },
     4: {0: 'erroneous header field encountered',
         1: 'unrecognized Next Header type encountered',
         2: 'unrecognized IPv6 option encountered',
        },
    }

if __name__ == '__main__':
    # Print all defined ICMP Control Messages
    print("ICMP Control Messages")
    print("Type\tCode:\tMessage")
    for (type, codes) in list(ICMP_CONTROL_MESSAGE.items()):
        print("")
        for (code, message) in list(codes.items()):
            print(("[%d]\t[%d]:\t%s" % (type, code, message)))
    print("")

    # Print all defined ICMPv6 Control Messages
    print("ICMPv6 Control Messages")
    print("Type\tCode:\tMessage")
    for (type, codes) in list(ICMPv6_CONTROL_MESSAGE.items()):
        print("")
        for (code, message) in list(codes.items()):
            print(("[%d]\t[%d]:\t%s" % (type, code, message)))
