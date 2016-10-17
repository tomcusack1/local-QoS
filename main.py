#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
from Ping import Ping


def ping(hostname,
         count=3,
         timeout=3000,
         packet_size=64,
         own_id=None,
         quiet=False,
         silent=False,
         ipv6=False):

    p = Ping(hostname, timeout, packet_size, own_id, quiet, silent, ipv6)
    stats = p.run(count)

    return not stats.packets_received


def usage():
    usage_message = "Usage: %s hostname" % (sys.argv[0])
    sys.stderr.write(usage_message)


def main(arguments):
    # There is some duplication in trying to not break for older versions.
    # OptionParser is still present in current versions, but it is deprecated
    try:

        import argparse
        parser = argparse.ArgumentParser(description='Perform network analysis on LAN')

        parser.add_argument('destination', type=str, nargs='?', help='destination')
        parser.add_argument('--test', action="store_true", help='Run a basic test suite')
        parser.add_argument('-q', '--quiet',
                            action="store_true",
                            help='Quiet output.  Nothing is displayed except the summary '
                                 'lines at startup time and when finished.')
        parser.add_argument('--ipv6',
                            action="store_true",
                            help='Run using IPv6, instead of the default (IPv4)')
        parser.add_argument('-c',
                            dest='count',
                            metavar='count',
                            type=int,
                            default=50,
                            help='Stop after sending count ECHO_REQUEST packets.')
        parser.add_argument('-s',
                            dest='packetsize',
                            metavar='packetsize',
                            type=int,
                            default=64,
                            help='Specifies the number of data bytes to be sent.  The default '
                                 'is 56, which translates into 64 ICMP data bytes when '
                                 'combined with the 8 bytes of ICMP header data.')
        parser.add_argument('-W',
                            dest='timeout',
                            metavar='timeout',
                            type=int,
                            default=3,
                            help='Time to wait for a response, in seconds.')

        args = parser.parse_args()

    except ImportError:

        from optparse import OptionParser
        import argparse

        parser = OptionParser(description='Send ICMP ECHO_REQUEST to network hosts')

        parser.add_option('--test', action="store_true", help='Run a basic test suite')
        parser.add_option('-q', '--quiet',
                          action="store_true",
                          help='Quiet output.  Nothing is displayed except the summary '
                               'lines at startup time and when finished.')
        parser.add_option('--ipv6',
                          action="store_true",
                          help='Run using IPv6, instead of the default (IPv4)')
        parser.add_option('-c',
                          dest='count',
                          metavar='count',
                          type=int,
                          default=3,
                          help='Stop after sending count ECHO_REQUEST packets.')
        parser.add_option('-s',
                          dest='packetsize',
                          metavar='packetsize',
                          type=int,
                          default=64,
                          help='Specifies the number of data bytes to be sent.  The default '
                               'is 56, which translates into 64 ICMP data bytes when '
                               'combined with the 8 bytes of ICMP header data.')
        parser.add_option('-W',
                          dest='timeout',
                          metavar='timeout',
                          type=int,
                          default=3,
                          help='Time to wait for a response, in seconds.')

        (args, positional_args) = parser.parse_args()

        # Add destination to this object to match argparse.parse_args() output
        if positional_args:
            args.destination = positional_args[0]
        else:
            args.destination = False

    if not args.destination:
        parser.print_help()
        sys.exit(1)

    # Convert timeout from sec to ms
    args.timeout *= 1000

    retval = ping(hostname=args.destination,
                  count=args.count,
                  timeout=args.timeout,
                  packet_size=args.packetsize,
                  own_id=None,
                  quiet=args.quiet,
                  ipv6=args.ipv6)

    sys.exit(retval)

main(sys.argv)
