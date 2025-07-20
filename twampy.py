#!/usr/bin/env python3

##############################################################################
#                                                                            #
#  twampy.py                                                                 #
#                                                                            #
#  History Change Log:                                                       #
#                                                                            #
#    1.0  [SW]  2017/08/18    first version                                  #
#    1.1  [SW]  2024/12/02    updates for python3.12                         #
#                                                                            #
#  Objective:                                                                #
#    Python implementation of the Two-Way Active Measurement Protocol        #
#    (TWAMP and TWAMP light) as defined in RFC5357. This tool was            #
#    developed to validate the Nokia SR OS TWAMP implementation.             #
#                                                                            #
#  Features supported:                                                       #
#    - unauthenticated mode                                                  #
#    - IPv4 and IPv6                                                         #
#    - Support for DSCP, Padding, JumboFrames, IMIX                          #
#    - Support to set DF flag (don't fragment)                               #
#    - Basic Delay, Jitter, Loss statistics (jitter according to RFC1889)    #
#                                                                            #
#  Modes of operation:                                                       #
#    - TWAMP Controller                                                      #
#        combined Control Client, Session Sender                             #
#    - TWAMP Control Client                                                  #
#        to run TWAMP light test session sender against TWAMP server         #
#    - TWAMP Test Session Sender                                             #
#        same as TWAMP light                                                 #
#    - TWAMP light Reflector                                                 #
#        same as TWAMP light                                                 #
#                                                                            #
#  Limitations:                                                              #
#    As there is no hardware based timestamping, latency and jitter values   #
#    measured by twampy are not very precise. DF flag implementation is      #
#    currently not supported on OS X (darwin) and FreeBSD.                   #
#                                                                            #
#  Not yet supported:                                                        #
#    - authenticated and encrypted mode                                      #
#    - sending intervals variation                                           #
#    - enhanced statistics                                                   #
#       => bining and interim statistics                                     #
#       => late arrived packets                                              #
#       => smokeping like graphics                                           #
#       => median on latency                                                 #
#       => improved jitter (rfc3393, statistical variance formula):          #
#          jitter:=sqrt(SumOf((D[i]-average(D))^2)/ReceivedProbesCount)      #
#    - daemon mode: NETCONF/YANG controlled, ...                             #
#    - enhanced failure handling (catch exceptions)                          #
#    - per probe time-out for statistics (late arrival)                      #
#    - Validation with other operating systems (such as FreeBSD)             #
#    - Support for RFC 5938 Individual Session Control                       #
#    - Support for RFC 6038 Reflect Octets Symmetrical Size                  #
#    - Support for RFC 8762 Simple 2-Way Active Measurement Protocol (STAMP) #
#                                                                            #
#  License:                                                                  #
#    Licensed under the BSD license                                          #
#    See LICENSE.md delivered with this project for more information.        #
#                                                                            #
#  Author:                                                                   #
#                                                                            #
#    Sven Wisotzky                                                           #
#    mail:  sven.wisotzky(at)nokia.com                                       #
##############################################################################

"""
TWAMP validation tool for Python Version 1.0
Copyright (C) 2013-2017 Nokia. All Rights Reserved.
"""

__title__ = "twampy"
__version__ = "1.0"
__status__ = "released"
__author__ = "Sven Wisotzky"
__date__ = "2017 August 18th"

#############################################################################

import os
import struct
import sys
import time
import datetime
import socket
import logging
import binascii
import threading
import random
import argparse
import signal
import select

#############################################################################

if (sys.platform == "win32"):
    time0 = time.time() - time.clock()

# Constants to convert between python timestamps and NTP 8B binary format [RFC1305]
TIMEOFFSET = 2208988800     # Time Difference: 1-JAN-1900 to 1-JAN-1970
ALLBITS = 0xFFFFFFFF        # To calculate 32bit fraction of the second


def now():
    if (sys.platform == "win32"):
        return time.clock() + time0
    return time.time()


def time_ntp2py(data):
    """
    Convert NTP 8 byte binary format [RFC1305] to python timestamp
    """

    ta, tb = struct.unpack('!2I', data)
    t = ta - TIMEOFFSET + float(tb) / float(ALLBITS)
    return t


def zeros(nbr):
    return struct.pack('!%sB' % nbr, *[0 for x in range(nbr)])


def dp(ms):
    if abs(ms) > 60000:
        return "%7.1fmin" % float(ms / 60000)
    if abs(ms) > 10000:
        return "%7.1fsec" % float(ms / 1000)
    if abs(ms) > 1000:
        return "%7.2fsec" % float(ms / 1000)
    if abs(ms) > 1:
        return "%8.2fms" % ms
    return "%8dus" % int(ms * 1000)


def parse_addr(addr, default_port=20000):
    if addr == '':
        # no address given (default: localhost IPv4 or IPv6)
        return "", default_port, 0
    elif ']:' in addr:
        # IPv6 address with port
        ip, port = addr.rsplit(':', 1)
        return ip.strip('[]'), int(port), 6
    elif ']' in addr:
        # IPv6 address without port
        return addr.strip('[]'), default_port, 6
    elif addr.count(':') > 1:
        # IPv6 address without port
        return addr, default_port, 6
    elif ':' in addr:
        # IPv4 address with port
        ip, port = addr.split(':')
        return ip, int(port), 4
    else:
        # IPv4 address without port
        return addr, default_port, 4

#############################################################################


class udpSession(threading.Thread):

    def __init__(self, addr="", port=20000, tos=0, ttl=64, do_not_fragment=False, ipversion=4):
        threading.Thread.__init__(self)
        if ipversion == 6:
            self.bind6(addr, port, tos, ttl)
        else:
            self.bind(addr, port, tos, ttl, do_not_fragment)
        self.running = True

    def bind(self, addr, port, tos, ttl, df):
        log.debug(
            "bind(addr=%s, port=%d, tos=%d, ttl=%d)", addr, port, tos, ttl)
        self.socket = socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, tos)
        self.socket.setsockopt(socket.SOL_IP,     socket.IP_TTL, ttl)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((addr, port))
        if df:
            if (sys.platform == "linux"):
                self.socket.setsockopt(socket.SOL_IP, 10, 2)
            elif (sys.platform == "win32"):
                self.socket.setsockopt(socket.SOL_IP, 14, 1)
            elif (sys.platform == "darwin"):
                log.error("do-not-fragment can not be set on darwin")
            else:
                log.error("unsupported OS, ignore do-not-fragment option")
        else:
            if (sys.platform == "linux"):
                self.socket.setsockopt(socket.SOL_IP, 10, 0)

    def bind6(self, addr, port, tos, ttl):
        log.debug(
            "bind6(addr=%s, port=%d, tos=%d, ttl=%d)", addr, port, tos, ttl)
        self.socket = socket.socket(
            socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_TCLASS, tos)
        self.socket.setsockopt(
            socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, ttl)
        self.socket.setsockopt(socket.SOL_SOCKET,   socket.SO_REUSEADDR, 1)
        self.socket.bind((addr, port))
        log.info("Wait to receive test packets on [%s]:%d", addr, port)

    def sendto(self, data, address):
        log.debug("transmit: %s", binascii.hexlify(data))
        self.socket.sendto(data, address)

    def recvfrom(self):
        data, address = self.socket.recvfrom(9216)
        log.debug("received: %s", binascii.hexlify(data))
        return data, address

    def stop(self, signum, frame):
        log.info("SIGINT received: Stop TWL session reflector")
        self.running = False
        
        # Print testing statistics immediately if this is a reflector with test mode
        if hasattr(self, 'test_mode') and self.test_mode:
            # Send any pending responses before showing statistics
            if hasattr(self, 'pending_responses') and len(self.pending_responses) > 0:
                log.info("Sending %d pending responses before exit", len(self.pending_responses))
                for response in self.pending_responses:
                    try:
                        self.sendto(response['data'], response['address'])
                        log.info("TEST: Sent pending %s packet [sseq=%d]", response['type'], response['sseq'])
                    except Exception as e:
                        log.debug("Failed to send pending response: %s", str(e))
                self.pending_responses = []
            
            total_packets = sum(self.test_stats.values())
            print("Testing Statistics Summary:")
            print("  Total packets processed: %d" % total_packets)
            print("  Normal responses: %d (%.1f%%)" % (self.test_stats['normal'], 
                     100 * self.test_stats['normal'] / total_packets if total_packets > 0 else 0))
            print("  Dropped packets: %d (%.1f%%)" % (self.test_stats['dropped'],
                     100 * self.test_stats['dropped'] / total_packets if total_packets > 0 else 0))
            print("  Delayed packets: %d (%.1f%%)" % (self.test_stats['delayed'],
                     100 * self.test_stats['delayed'] / total_packets if total_packets > 0 else 0))
            print("  Reordered packets: %d (%.1f%%)" % (self.test_stats['reordered'],
                     100 * self.test_stats['reordered'] / total_packets if total_packets > 0 else 0))
            print("  Duplicated packets: %d (%.1f%%)" % (self.test_stats['duplicated'],
                     100 * self.test_stats['duplicated'] / total_packets if total_packets > 0 else 0))
            print("  Pending responses: %d" % len(self.pending_responses))
        
        try:
            self.socket.shutdown(socket.SHUT_RDWR)
        except Exception as e:
            log.debug("Socket shutdown failed: %s", str(e))
        try:
            self.socket.close()
        except Exception as e:
            log.debug("Socket close failed: %s", str(e))


class twampStatistics():

    def __init__(self):
        self.count = 0
        self.out_of_order_count = 0
        self.late_arrivals = 0
        self.duplicates = 0

    def add(self, delayRT, delayOB, delayIB, rseq, sseq, order_status='in_order'):
        if self.count == 0:
            self.minOB = delayOB
            self.minIB = delayIB
            self.minRT = delayRT

            self.maxOB = delayOB
            self.maxIB = delayIB
            self.maxRT = delayRT

            self.sumOB = delayOB
            self.sumIB = delayIB
            self.sumRT = delayRT

            self.lossIB = rseq
            self.lossOB = sseq - rseq

            self.jitterOB = 0
            self.jitterIB = 0
            self.jitterRT = 0

            self.lastOB = delayOB
            self.lastIB = delayIB
            self.lastRT = delayRT
        else:
            self.minOB = min(self.minOB, delayOB)
            self.minIB = min(self.minIB, delayIB)
            self.minRT = min(self.minRT, delayRT)

            self.maxOB = max(self.maxOB, delayOB)
            self.maxIB = max(self.maxIB, delayIB)
            self.maxRT = max(self.maxRT, delayRT)

            self.sumOB += delayOB
            self.sumIB += delayIB
            self.sumRT += delayRT

            self.lossIB = rseq - self.count
            self.lossOB = sseq - rseq

            if self.count == 1:
                self.jitterOB = abs(self.lastOB - delayOB)
                self.jitterIB = abs(self.lastIB - delayIB)
                self.jitterRT = abs(self.lastRT - delayRT)
            else:
                self.jitterOB = self.jitterOB + \
                    (abs(self.lastOB - delayOB) - self.jitterOB) / 16
                self.jitterIB = self.jitterIB + \
                    (abs(self.lastIB - delayIB) - self.jitterIB) / 16
                self.jitterRT = self.jitterRT + \
                    (abs(self.lastRT - delayRT) - self.jitterRT) / 16

            self.lastOB = delayOB
            self.lastIB = delayIB
            self.lastRT = delayRT

        # Track ordering statistics
        if order_status == 'out_of_order':
            self.out_of_order_count += 1
        elif order_status == 'late_arrival':
            self.late_arrivals += 1
        elif order_status == 'duplicate':
            self.duplicates += 1

        self.count += 1

    def print_current(self, total_sent):
        timestamp = datetime.datetime.now().strftime('%y/%m/%d %H:%M:%S')
        if self.count > 0:
            loss_rt = total_sent - self.count
            print("--- Current Statistics at %s (received: %d, sent: %d) ---" % (timestamp, self.count, total_sent))
            print("  Outbound:  Min=%s Max=%s Avg=%s Jitter=%s Loss=%.1f%%" % 
                  (dp(self.minOB), dp(self.maxOB), dp(self.sumOB / self.count), dp(self.jitterOB), 
                   100 * float(self.lossOB) / total_sent if total_sent > 0 else 0))
            print("  Inbound:   Min=%s Max=%s Avg=%s Jitter=%s Loss=%.1f%%" % 
                  (dp(self.minIB), dp(self.maxIB), dp(self.sumIB / self.count), dp(self.jitterIB), 
                   100 * float(self.lossIB) / total_sent if total_sent > 0 else 0))
            print("  Roundtrip: Min=%s Max=%s Avg=%s Jitter=%s Loss=%.1f%%" % 
                  (dp(self.minRT), dp(self.maxRT), dp(self.sumRT / self.count), dp(self.jitterRT), 
                   100 * float(loss_rt) / total_sent if total_sent > 0 else 0))
            if self.out_of_order_count > 0 or self.late_arrivals > 0 or self.duplicates > 0:
                print("  Reordering: Out-of-order=%d Late-arrivals=%d Duplicates=%d" % 
                      (self.out_of_order_count, self.late_arrivals, self.duplicates))
        else:
            print("--- Current Statistics at %s (received: 0, sent: %d) ---" % (timestamp, total_sent))
            print("  NO RESPONSES RECEIVED YET")
        sys.stdout.flush()

    def dump(self, total):
        print("===============================================================================")
        print("Direction         Min         Max         Avg          Jitter     Loss")
        print("-------------------------------------------------------------------------------")
        if self.count > 0:
            self.lossRT = total - self.count
            print("  Outbound:    %s  %s  %s  %s    %5.1f%%" % (dp(self.minOB), dp(self.maxOB), dp(self.sumOB / self.count), dp(self.jitterOB), 100 * float(self.lossOB) / total))
            print("  Inbound:     %s  %s  %s  %s    %5.1f%%" % (dp(self.minIB), dp(self.maxIB), dp(self.sumIB / self.count), dp(self.jitterIB), 100 * float(self.lossIB) / total))
            print("  Roundtrip:   %s  %s  %s  %s    %5.1f%%" % (dp(self.minRT), dp(self.maxRT), dp(self.sumRT / self.count), dp(self.jitterRT), 100 * float(self.lossRT) / total))
        else:
            print("  NO STATS AVAILABLE (100% loss)")
        print("-------------------------------------------------------------------------------")
        if self.out_of_order_count > 0 or self.late_arrivals > 0 or self.duplicates > 0:
            print("Reordering Statistics:")
            print("  Out-of-order packets: %d" % self.out_of_order_count)
            print("  Late arrivals: %d" % self.late_arrivals)
            print("  Duplicate packets: %d" % self.duplicates)
            print("-------------------------------------------------------------------------------")
        print("                                                    Jitter Algorithm [RFC1889]")
        print("===============================================================================")
        sys.stdout.flush()

#############################################################################


class twampySessionSender(udpSession):

    def __init__(self, args):
        # Session Sender / Session Reflector:
        #   get Address, UDP port, IP version from near_end/far_end attributes
        sip, spt, sipv = parse_addr(args.near_end, 20000)
        rip, rpt, ripv = parse_addr(args.far_end,  20001)

        ipversion = 6 if (sipv == 6) or (ripv == 6) else 4
        udpSession.__init__(self, sip, spt, args.tos, args.ttl, args.do_not_fragment, ipversion)

        self.remote_addr = rip
        self.remote_port = rpt
        self.interval = float(args.interval) / 1000
        self.count = args.count
        self.stats = twampStatistics()
        self.stats_interval = args.stats_interval
        self.print_responses = args.print_responses
        self.packet_timeout = args.packet_timeout
        
        # Sequence tracking for out-of-order detection
        self.received_packets = set()
        self.expected_next_seq = 0
        self.missing_ranges = []  # Track ranges of missing packets
        self.timed_out_packets = set()  # Track packets that have been declared timed out

        if args.padding != -1:
            self.padmix = [args.padding]
        elif ipversion == 6:
            self.padmix = [0, 0, 0, 0, 0, 0, 0, 514, 514, 514, 514, 1438]
        else:
            self.padmix = [8, 8, 8, 8, 8, 8, 8, 534, 534, 534, 534, 1458]

    def analyze_sequence(self, sseq):
        """
        Analyze received sequence for ordering issues.
        Returns: ('in_order'|'gap_detected'|'out_of_order'|'late_arrival', gap_info)
        """
        timestamp = datetime.datetime.now().strftime('%y/%m/%d %H:%M:%S')
        
        # Check if this packet was already received (duplicate)
        if sseq in self.received_packets:
            return 'duplicate', None
            
        # Check if this packet was previously timed out (late arrival)
        if sseq in self.timed_out_packets:
            self.timed_out_packets.remove(sseq)
            self.received_packets.add(sseq)
            return 'late_arrival', None
            
        # Add to received set
        self.received_packets.add(sseq)
        
        # Check if packet arrived in order
        if sseq == self.expected_next_seq:
            # In-order packet - advance expected sequence
            self.expected_next_seq += 1
            
            # Check if this fills any gaps (removes missing ranges)
            self.missing_ranges = [(start, end) for start, end in self.missing_ranges 
                                 if not (start <= sseq <= end)]
            
            return 'in_order', None
            
        elif sseq > self.expected_next_seq:
            # Gap detected - missing packets between expected and received
            gap_start = self.expected_next_seq
            gap_end = sseq - 1
            
            # Add missing range
            self.missing_ranges.append((gap_start, gap_end))
            
            # Update expected sequence
            self.expected_next_seq = sseq + 1
            
            # Format gap info for notification
            if gap_start == gap_end:
                gap_info = f"packet [{gap_start}] missing"
            else:
                gap_info = f"packets [{gap_start}-{gap_end}] missing"
                
            return 'gap_detected', gap_info
            
        else:  # sseq < self.expected_next_seq
            # Out-of-order arrival - all packets arriving out of sequence are "out_of_order"
            # regardless of whether they fill gaps or not
            
            # Remove this sequence from missing ranges if it was missing
            was_missing = any(start <= sseq <= end for start, end in self.missing_ranges)
            if was_missing:
                new_ranges = []
                for start, end in self.missing_ranges:
                    if start <= sseq <= end:
                        # Split the range if needed
                        if start < sseq:
                            new_ranges.append((start, sseq - 1))
                        if sseq < end:
                            new_ranges.append((sseq + 1, end))
                    else:
                        new_ranges.append((start, end))
                self.missing_ranges = new_ranges
            
            return 'out_of_order', None

    def run(self):
        schedule = now()
        endtime = schedule + self.count * self.interval + 5
        next_stats_print = now() + self.stats_interval if self.stats_interval > 0 else endtime + 1
        sent_packets = {}  # Track sent packets: {seq_num: send_time}

        idx = 0
        while self.running:
            while select.select([self.socket], [], [], 0)[0]:
                t4 = now()
                data, address = self.recvfrom()

                if len(data) < 36:
                    log.error("short packet received: %d bytes", len(data))
                    continue

                t3 = time_ntp2py(data[4:12])
                t2 = time_ntp2py(data[16:24])
                t1 = time_ntp2py(data[28:36])

                delayRT = max(0, 1000 * (t4 - t1 + t2 - t3))  # round-trip delay
                delayOB = max(0, 1000 * (t2 - t1))            # out-bound delay
                delayIB = max(0, 1000 * (t4 - t3))            # in-bound delay

                rseq = struct.unpack('!I', data[0:4])[0]
                sseq = struct.unpack('!I', data[24:28])[0]

                # Analyze sequence ordering
                order_status, gap_info = self.analyze_sequence(sseq)
                timestamp = datetime.datetime.now().strftime('%y/%m/%d %H:%M:%S')

                # Print ordering notifications
                if order_status == 'gap_detected' and self.print_responses:
                    print("%s Gap detected: %s (received seq=%d)" % (timestamp, gap_info, sseq))
                elif order_status == 'late_arrival' and self.print_responses:
                    print("%s Out-of-order: packet [seq=%d] arrived late" % (timestamp, sseq))
                elif order_status == 'out_of_order' and self.print_responses:
                    print("%s Out-of-order: packet [seq=%d] arrived out of sequence" % (timestamp, sseq))
                elif order_status == 'duplicate':
                    if self.print_responses:
                        print("%s Duplicate: packet [seq=%d] already received" % (timestamp, sseq))
                    # Still track duplicate in statistics but don't process timing
                    self.stats.add(0, 0, 0, rseq, sseq, order_status)
                    continue  # Skip timing processing for duplicates

                # Remove from sent packets tracking (packet received)
                if sseq in sent_packets:
                    del sent_packets[sseq]

                if self.print_responses:
                    print("Reply from %s [seq=%d] RTT=%s Outbound=%s Inbound=%s" % 
                          (address[0], sseq, dp(delayRT), dp(delayOB), dp(delayIB)))

                log.info("Reply from %s [rseq=%d sseq=%d rtt=%.2fms outbound=%.2fms inbound=%.2fms]", address[0], rseq, sseq, delayRT, delayOB, delayIB)
                self.stats.add(delayRT, delayOB, delayIB, rseq, sseq, order_status)

                # Check if all packets have been sent AND all sent packets received/timed out
                if len(sent_packets) == 0 and idx >= self.count:
                    log.info("All packets sent and received back")
                    self.running = False

            t1 = now()
            
            # Check for timed out packets
            timed_out_packets = []
            for seq_num, send_time in list(sent_packets.items()):
                if t1 - send_time > self.packet_timeout:
                    timed_out_packets.append(seq_num)
                    del sent_packets[seq_num]
                    # Track that this packet timed out for late arrival detection
                    self.timed_out_packets.add(seq_num)
            
            # Print timeout notifications
            if self.print_responses and timed_out_packets:
                for seq_num in sorted(timed_out_packets):
                    print("Timeout: packet [seq=%d] lost (no response after %.1fs)" % (seq_num, self.packet_timeout))
            
            # Check if it's time to print periodic statistics
            if self.stats_interval > 0 and t1 >= next_stats_print:
                self.stats.print_current(idx)
                next_stats_print = t1 + self.stats_interval
            
            if (t1 >= schedule) and (idx < self.count):
                schedule = schedule + self.interval

                data = struct.pack('!L2IH', idx, int(TIMEOFFSET + t1), int((t1 - int(t1)) * ALLBITS), 0x3fff)
                pbytes = zeros(self.padmix[int(len(self.padmix) * random.random())])

                # Track this packet for timeout detection
                sent_packets[idx] = t1

                self.sendto(data + pbytes, (self.remote_addr, self.remote_port))
                log.info("Sent to %s [sseq=%d]", self.remote_addr, idx)

                idx = idx + 1
                if schedule > t1:
                    r, w, e = select.select([self.socket], [], [], schedule - t1)

            if (t1 > endtime):
                log.info("Receive timeout for last packet (don't wait anymore)")
                self.running = False

        self.stats.dump(idx)


class twampySessionReflector(udpSession):

    def __init__(self, args):
        addr, port, ipversion = parse_addr(args.near_end, 20001)

        if args.padding != -1:
            self.padmix = [args.padding]
        elif ipversion == 6:
            self.padmix = [0, 0, 0, 0, 0, 0, 0, 514, 514, 514, 514, 1438]
        else:
            self.padmix = [8, 8, 8, 8, 8, 8, 8, 534, 534, 534, 534, 1458]

        udpSession.__init__(self, addr, port, args.tos, args.ttl, args.do_not_fragment, ipversion)
        
        # Testing mode parameters
        self.test_mode = getattr(args, 'test_mode', False)
        self.drop_rate = getattr(args, 'drop_rate', 0)
        self.reorder_rate = getattr(args, 'reorder_rate', 0)
        self.delay_rate = getattr(args, 'delay_rate', 0)
        self.max_delay = getattr(args, 'max_delay', 2.0)
        self.duplicate_rate = getattr(args, 'duplicate_rate', 0)
        
        # Testing state tracking
        self.pending_responses = []  # Queue for delayed/reordered responses
        self.test_stats = {
            'dropped': 0,
            'reordered': 0, 
            'delayed': 0,
            'duplicated': 0,
            'normal': 0
        }
        
        if self.test_mode:
            log.info("Testing mode enabled: drop=%.1f%% reorder=%.1f%% delay=%.1f%% duplicate=%.1f%%", 
                     self.drop_rate, self.reorder_rate, self.delay_rate, self.duplicate_rate)

    def decide_test_action(self, sseq):
        """
        Decide what testing action to apply to this packet.
        Returns: ('normal'|'drop'|'delay'|'reorder'|'duplicate', delay_time)
        """
        if not self.test_mode:
            return 'normal', 0
            
        # Use cumulative probabilities to ensure only one action per packet
        rand = random.random() * 100
        
        if rand < self.drop_rate:
            self.test_stats['dropped'] += 1
            log.info("TEST: Dropping packet [sseq=%d]", sseq)
            return 'drop', 0
            
        elif rand < self.drop_rate + self.duplicate_rate:
            self.test_stats['duplicated'] += 1
            log.info("TEST: Duplicating packet [sseq=%d]", sseq)
            return 'duplicate', 0
            
        elif rand < self.drop_rate + self.duplicate_rate + self.delay_rate:
            delay_time = random.uniform(0.1, self.max_delay)
            self.test_stats['delayed'] += 1
            log.info("TEST: Delaying packet [sseq=%d] by %.1fs", sseq, delay_time)
            return 'delay', delay_time
            
        elif rand < self.drop_rate + self.duplicate_rate + self.delay_rate + self.reorder_rate:
            # Reorder this packet by adding a small delay (0.1-0.5 seconds)
            delay_time = random.uniform(0.1, 0.5)
            self.test_stats['reordered'] += 1
            log.info("TEST: Reordering packet [sseq=%d] with %.1fs delay", sseq, delay_time)
            return 'reorder', delay_time
        
        self.test_stats['normal'] += 1
        return 'normal', 0

    def run(self):
        index = {}
        reset = {}

        while self.running:
            # Process pending delayed responses
            current_time = now()
            responses_to_send = []
            remaining_responses = []
            
            for response in self.pending_responses:
                if current_time >= response['send_time']:
                    responses_to_send.append(response)
                else:
                    remaining_responses.append(response)
            
            # Send due responses
            for response in responses_to_send:
                self.sendto(response['data'], response['address'])
                if response['type'] == 'delayed':
                    log.info("TEST: Sending delayed packet [sseq=%d]", response['sseq'])
                elif response['type'] == 'reordered':
                    log.info("TEST: Sending reordered packet [sseq=%d]", response['sseq'])
            
            # Update pending responses list
            self.pending_responses = remaining_responses
            
            try:
                # Use select to check for incoming data with timeout
                ready = select.select([self.socket], [], [], 0.1)
                if ready[0]:
                    data, address = self.recvfrom()
                else:
                    # No data available, continue to process pending queue
                    continue

                t2 = now()
                sec = int(TIMEOFFSET + t2)              # seconds since 1-JAN-1900
                msec = int((t2 - int(t2)) * ALLBITS)    # 32bit fraction of the second

                sseq = struct.unpack('!I', data[0:4])[0]
                t1 = time_ntp2py(data[4:12])

                log.info("Request from %s:%d [sseq=%d outbound=%.2fms]", address[0], address[1], sseq, 1000 * (t2 - t1))

                idx = 0
                if address not in index.keys():
                    log.info("set rseq:=0     (new remote address/port)")
                elif reset[address] < t2:
                    log.info("reset rseq:=0   (session timeout, 30sec)")
                elif sseq == 0:
                    log.info("reset rseq:=0   (received sseq==0)")
                else:
                    idx = index[address]

                # Prepare response data
                rdata = struct.pack('!L2I2H2I', idx, sec, msec, 0x001, 0, sec, msec)
                pbytes = zeros(self.padmix[int(len(self.padmix) * random.random())])
                response_packet = rdata + data[0:14] + pbytes
                
                # Decide testing action
                test_action, delay_time = self.decide_test_action(sseq)
                
                if test_action == 'drop':
                    # Drop packet - no response sent
                    pass
                    
                elif test_action == 'duplicate':
                    # Send response twice
                    self.sendto(response_packet, address)
                    # Small delay before duplicate to ensure different timing
                    time.sleep(0.001)  
                    self.sendto(response_packet, address)
                    
                elif test_action == 'delay':
                    # Queue response for delayed sending
                    send_time = now() + delay_time
                    pending_response = {
                        'data': response_packet,
                        'address': address,
                        'send_time': send_time,
                        'sseq': sseq,
                        'type': 'delayed'
                    }
                    self.pending_responses.append(pending_response)
                    
                elif test_action == 'reorder':
                    # Queue response for reordering (small delay to create out-of-order arrival)
                    send_time = now() + delay_time
                    pending_response = {
                        'data': response_packet,
                        'address': address,
                        'send_time': send_time,
                        'sseq': sseq,
                        'type': 'reordered'
                    }
                    self.pending_responses.append(pending_response)
                        
                else:  # normal
                    # Send response immediately
                    self.sendto(response_packet, address)

                index[address] = idx + 1
                reset[address] = t2 + 30  # timeout is 30sec

            except Exception as e:
                log.debug('Exception: %s', str(e))
                # Don't break immediately - let the loop check self.running
                # This allows statistics to be printed when Ctrl-C closes the socket

        # Testing statistics are printed in signal handler, no need to duplicate here
            
        log.info("TWL session reflector stopped")


class twampyControlClient:

    def __init__(self, server="", tcp_port=862, tos=0x88, ipversion=4):
        if ipversion == 6:
            self.connect6(server, tcp_port, tos)
        else:
            self.connect(server, tcp_port, tos)

    def connect(self, server="", port=862, tos=0x88):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, tos)
        self.socket.connect((server, port))

    def connect6(self, server="", port=862, tos=0x88):
        self.socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_TCLASS, tos)
        self.socket.connect((server, port))

    def send(self, data):
        log.debug("CTRL.TX %s", binascii.hexlify(data))
        try:
            self.socket.send(data)
        except Exception as e:
            log.critical('*** Sending data failed: %s', str(e))

    def receive(self):
        data = self.socket.recv(9216)
        log.debug("CTRL.RX %s (%d bytes)", binascii.hexlify(data), len(data))
        return data

    def close(self):
        self.socket.close()

    def connectionSetup(self):
        log.info("CTRL.RX <<Server Greeting>>")
        data = self.receive()
        self.smode = struct.unpack('!I', data[12:16])[0]
        log.info("TWAMP modes supported: %d", self.smode)
        if self.smode & 1 == 0:
            log.critical('*** TWAMPY only supports unauthenticated mode(1)')

        log.info("CTRL.TX <<Setup Response>>")
        self.send(struct.pack('!I', 1) + zeros(160))

        log.info("CTRL.RX <<Server Start>>")
        data = self.receive()

        rval = data[15]
        if rval != 0:
            # TWAMP setup request not accepted by server
            log.critical("*** ERROR CODE %d in <<Server Start>>", rval)

        self.nbrSessions = 0

    def reqSession(self, sender="", s_port=20001, receiver="", r_port=20002, startTime=0, timeOut=3, dscp=0, padding=0):
        typeP = dscp << 24

        if startTime != 0:
            startTime += now() + TIMEOFFSET

        if sender == "":
            request = struct.pack('!4B L L H H 13L 4ILQ4L', 5, 4, 0, 0, 0, 0, s_port, r_port, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, padding, startTime, 0, timeOut, 0, typeP, 0, 0, 0, 0, 0)
        elif sender == "::":
            request = struct.pack('!4B L L H H 13L 4ILQ4L', 5, 6, 0, 0, 0, 0, s_port, r_port, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, padding, startTime, 0, timeOut, 0, typeP, 0, 0, 0, 0, 0)
        elif ':' in sender:
            s = socket.inet_pton(socket.AF_INET6, sender)
            r = socket.inet_pton(socket.AF_INET6, receiver)
            request = struct.pack('!4B L L H H 16s 16s 4L L 4ILQ4L', 5, 6, 0, 0, 0, 0, s_port, r_port, s, r, 0, 0, 0, 0, padding, startTime, 0, timeOut, 0, typeP, 0, 0, 0, 0, 0)
        else:
            s = socket.inet_pton(socket.AF_INET, sender)
            r = socket.inet_pton(socket.AF_INET, receiver)
            request = struct.pack('!4B L L H H 16s 16s 4L L 4ILQ4L', 5, 4, 0, 0, 0, 0, s_port, r_port, s, r, 0, 0, 0, 0, padding, startTime, 0, timeOut, 0, typeP, 0, 0, 0, 0, 0)

        log.info("CTRL.TX <<Request Session>>")
        self.send(request)
        log.info("CTRL.RX <<Session Accept>>")
        data = self.receive()

        rval = data[0]
        if rval != 0:
            log.critical("ERROR CODE %d in <<Session Accept>>", rval)
            return False
        return True

    def startSessions(self):
        request = struct.pack('!B', 2) + zeros(31)
        log.info("CTRL.TX <<Start Sessions>>")
        self.send(request)
        log.info("CTRL.RX <<Start Accept>>")
        self.receive()

    def stopSessions(self):
        request = struct.pack('!BBHLQQQ', 3, 0, 0, self.nbrSessions, 0, 0, 0)
        log.info("CTRL.TX <<Stop Sessions>>")
        self.send(request)

        self.nbrSessions = 0

#############################################################################


def twl_responder(args):
    reflector = twampySessionReflector(args)
    reflector.daemon = True
    reflector.name = "twl_responder"
    reflector.start()

    signal.signal(signal.SIGINT, reflector.stop)

    while reflector.is_alive():
        time.sleep(0.1)


def twl_sender(args):
    sender = twampySessionSender(args)
    sender.daemon = True
    sender.name = "twl_responder"
    sender.start()

    signal.signal(signal.SIGINT, sender.stop)

    while sender.is_alive():
        time.sleep(0.1)


def twamp_controller(args):
    # Session Sender / Session Reflector:
    #   get Address, UDP port, IP version from near_end/far_end attributes
    sip, spt, ipv = parse_addr(args.near_end, 20000)
    rip, rpt, ipv = parse_addr(args.far_end,  20001)

    client = twampyControlClient(server=rip, ipversion=ipv)
    client.connectionSetup()

    if client.reqSession(s_port=spt, r_port=rpt):
        client.startSessions()

        sender = twampySessionSender(args)
        sender.daemon = True
        sender.name = "twl_responder"
        sender.start()
        signal.signal(signal.SIGINT, sender.stop)

        while sender.is_alive():
            time.sleep(0.1)
        time.sleep(5)

        client.stopSessions()


def twamp_ctclient(args):
    # Session Sender / Session Reflector:
    #   get Address, UDP port, IP version from twamp sender/server attributes
    sip, spt, ipv = parse_addr(args.twl_send, 20000)
    rip, rpt, ipv = parse_addr(args.twserver, 20001)

    client = twampyControlClient(server=rip, ipversion=ipv)
    client.connectionSetup()

#    if client.reqSession(sender=sip, s_port=spt, receiver=rip, r_port=rpt):
    if client.reqSession(sender=sip, s_port=spt, receiver="0.0.0.0", r_port=rpt):
        client.startSessions()

        while True:
            time.sleep(0.1)

        client.stopSessions()

#############################################################################

dscpmap = {"be":   0, "cp1":   1,  "cp2":  2,  "cp3":  3, "cp4":   4, "cp5":   5, "cp6":   6, "cp7":   7,
           "cs1":  8, "cp9":   9, "af11": 10, "cp11": 11, "af12": 12, "cp13": 13, "af13": 14, "cp15": 15,
           "cs2": 16, "cp17": 17, "af21": 18, "cp19": 19, "af22": 20, "cp21": 21, "af23": 22, "cp23": 23,
           "cs3": 24, "cp25": 25, "af31": 26, "cp27": 27, "af32": 28, "cp29": 29, "af33": 30, "cp31": 31,
           "cs4": 32, "cp33": 33, "af41": 34, "cp35": 35, "af42": 36, "cp37": 37, "af43": 38, "cp39": 39,
           "cs5": 40, "cp41": 41, "cp42": 42, "cp43": 43, "cp44": 44, "cp45": 45, "ef":   46, "cp47": 47,
           "nc1": 48, "cp49": 49, "cp50": 50, "cp51": 51, "cp52": 52, "cp53": 53, "cp54": 54, "cp55": 55,
           "nc2": 56, "cp57": 57, "cp58": 58, "cp59": 59, "cp60": 60, "cp61": 61, "cp62": 62, "cp63": 63}
           
def dscpTable():
    print("""
============================================================
DSCP Mapping
============================================================
DSCP Name      DSCP Value     TOS (bin)      TOS (hex)
------------------------------------------------------------
be             0              0000 0000      00
cp1            1              0000 0100      04
cp2            2              0000 1000      08
cp3            3              0000 1100      0C
cp4            4              0001 0000      10
cp5            5              0001 0100      14
cp6            6              0001 1000      18
cp7            7              0001 1100      1C
cs1            8              0010 0000      20
cp9            9              0010 0100      24
af11           10             0010 1000      28
cp11           11             0010 1100      2C
af12           12             0011 0000      30
cp13           13             0011 0100      34
af13           14             0011 1000      38
cp15           15             0011 1100      3C
cs2            16             0100 0000      40
cp17           17             0100 0100      44
af21           18             0100 1000      48
cp19           19             0100 1100      4C
af22           20             0101 0000      50
cp21           21             0101 0100      54
af23           22             0101 1000      58
cp23           23             0101 1100      5C
cs3            24             0110 0000      60
cp25           25             0110 0100      64
af31           26             0110 1000      68
cp27           27             0110 1100      6C
af32           28             0111 0000      70
cp29           29             0111 0100      74
af33           30             0111 1000      78
cp31           31             0111 1100      7C
cs4            32             1000 0000      80
cp33           33             1000 0100      84
af41           34             1000 1000      88
cp35           35             1000 1100      8C
af42           36             1001 0000      90
cp37           37             1001 0100      94
af43           38             1001 1000      98
cp39           39             1001 1100      9C
cs5            40             1010 0000      A0
cp41           41             1010 0100      A4
cp42           42             1010 1000      A8
cp43           43             1010 1100      AC
cp44           44             1011 0000      B0
cp45           45             1011 0100      B4
ef             46             1011 1000      B8
cp47           47             1011 1100      BC
nc1            48             1100 0000      C0
cp49           49             1100 0100      C4
cp50           50             1100 1000      C8
cp51           51             1100 1100      CC
cp52           52             1101 0000      D0
cp53           53             1101 0100      D4
cp54           54             1101 1000      D8
cp55           55             1101 1100      DC
nc2            56             1110 0000      E0
cp57           57             1110 0100      E4
cp58           58             1110 1000      E8
cp59           59             1110 1100      EC
cp60           60             1111 0000      F0
cp61           61             1111 0100      F4
cp62           62             1111 1000      F8
cp63           63             1111 1100      FC
============================================================""")
    sys.stdout.flush()

#############################################################################

if __name__ == '__main__':
    debug_parser = argparse.ArgumentParser(add_help=False)

    debug_options = debug_parser.add_argument_group("Debug Options")
    debug_options.add_argument('-l', '--logfile', metavar='filename', type=argparse.FileType('w', 0), default='-', help='Specify the logfile (default: <stdout>)')
    group = debug_options.add_mutually_exclusive_group()
    group.add_argument('-q', '--quiet',   action='store_true', help='disable logging')
    group.add_argument('-v', '--verbose', action='store_true', help='enhanced logging')
    group.add_argument('-d', '--debug',   action='store_true', help='extensive logging')

    ipopt_parser = argparse.ArgumentParser(add_help=False)
    group = ipopt_parser.add_argument_group("IP socket options")
    group.add_argument('--tos',     metavar='type-of-service', default=0x88, type=int, help='IP TOS value')
    group.add_argument('--dscp',    metavar='dscp-value', help='IP DSCP value')
    group.add_argument('--ttl',     metavar='time-to-live', default=64,   type=int, help='[1..128]')
    group.add_argument('--padding', metavar='bytes', default=0,    type=int, help='IP/UDP mtu value')
    group.add_argument('--do-not-fragment',  action='store_true', help='keyword (do-not-fragment)')

    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--version', action='version', version='%(prog)s ' + __version__)

    subparsers = parser.add_subparsers(help='twampy sub-commands')

    p_responder = subparsers.add_parser('responder', help='TWL responder', parents=[debug_parser, ipopt_parser])
    group = p_responder.add_argument_group("TWL responder options")
    group.add_argument('near_end', nargs='?', metavar='local-ip:port', default=":20001")
    group.add_argument('--timer', metavar='value',   default=0,     type=int, help='TWL session reset')
    
    test_group = p_responder.add_argument_group("Testing options")
    test_group.add_argument('--test-mode', action='store_true', help='Enable testing mode to simulate network issues')
    test_group.add_argument('--drop-rate', metavar='percent', default=0, type=float, help='Percentage of packets to drop (0-100, default: 0)')
    test_group.add_argument('--reorder-rate', metavar='percent', default=0, type=float, help='Percentage of packets to reorder (0-100, default: 0)')
    test_group.add_argument('--delay-rate', metavar='percent', default=0, type=float, help='Percentage of packets to delay (0-100, default: 0)')
    test_group.add_argument('--max-delay', metavar='seconds', default=2.0, type=float, help='Maximum delay for delayed packets in seconds (default: 2.0)')
    test_group.add_argument('--duplicate-rate', metavar='percent', default=0, type=float, help='Percentage of packets to duplicate (0-100, default: 0)')

    p_sender = subparsers.add_parser('sender', help='TWL sender', parents=[debug_parser, ipopt_parser])
    group = p_sender.add_argument_group("TWL sender options")
    group.add_argument('far_end', nargs='?', metavar='remote-ip:port', default="127.0.0.1:20001")
    group.add_argument('near_end', nargs='?', metavar='local-ip:port', default=":20000")
    group.add_argument('-i', '--interval', metavar='msec', default=100,  type=int, help="[100,1000]")
    group.add_argument('-c', '--count',    metavar='packets', default=100,  type=int, help="[1..9999]")
    group.add_argument('--stats-interval', metavar='seconds', default=5, type=int, help="Print statistics every N seconds (default: 5, 0=disable)")
    group.add_argument('--print-responses', action='store_true', help="Print latency for each response received")
    group.add_argument('--packet-timeout', metavar='seconds', default=5.0, type=float, help="Per-packet timeout in seconds (default: 5.0)")

    p_control = subparsers.add_parser('controller', help='TWAMP controller', parents=[debug_parser, ipopt_parser])
    group = p_control.add_argument_group("TWAMP controller options")
    group.add_argument('far_end', nargs='?', metavar='remote-ip:port', default="127.0.0.1:20001")
    group.add_argument('near_end', nargs='?', metavar='local-ip:port', default=":20000")
    group.add_argument('-i', '--interval', metavar='msec', default=100,  type=int, help="[100,1000]")
    group.add_argument('-c', '--count',    metavar='packets', default=100,  type=int, help="[1..9999]")

    p_ctclient = subparsers.add_parser('controlclient', help='TWAMP control client', parents=[debug_parser, ipopt_parser])
    group = p_ctclient.add_argument_group("TWAMP control client options")
    group.add_argument('twl_send', nargs='?', metavar='twamp-sender-ip:port', default="127.0.0.1:20001")
    group.add_argument('twserver', nargs='?', metavar='twamp-server-ip:port', default=":20000")
    group.add_argument('-c', '--count',    metavar='packets', default=100,  type=int, help="[1..9999]")

    p_dscptab = subparsers.add_parser('dscptable', help='print DSCP table', parents=[debug_parser])

    # methods to call
    p_sender.set_defaults(parseop=True, func=twl_sender)
    p_control.set_defaults(parseop=True, func=twamp_controller)
    p_ctclient.set_defaults(parseop=True, func=twamp_ctclient)
    p_responder.set_defaults(parseop=True, func=twl_responder)
    p_dscptab.set_defaults(parseop=False, func=dscpTable)

#############################################################################

    options = parser.parse_args()

    if not vars(options):
        parser.print_help()
        parser.exit(1)

    if not options.parseop:
        print(options)
        options.func()
        exit(-1)

#############################################################################
# SETUP logging level:
#   logging.NOTSET, logging.CRITICAL, logging.ERROR,
#   logging.WARNING, logging.INFO, logging.DEBUG
#############################################################################

    if options.quiet:
        logfile = open(os.devnull, 'a')
        loghandler = logging.StreamHandler(logfile)
        loglevel = logging.NOTSET
    elif options.debug:
        logformat = '%(asctime)s,%(msecs)-3d %(levelname)-8s %(message)s'
        timeformat = '%y/%m/%d %H:%M:%S'
        loghandler = logging.StreamHandler(options.logfile)
        loghandler.setFormatter(logging.Formatter(logformat, timeformat))
        loglevel = logging.DEBUG
    elif options.verbose:
        logformat = '%(asctime)s,%(msecs)-3d %(levelname)-8s %(message)s'
        timeformat = '%y/%m/%d %H:%M:%S'
        loghandler = logging.StreamHandler(options.logfile)
        loghandler.setFormatter(logging.Formatter(logformat, timeformat))
        loglevel = logging.INFO
    else:
        logformat = '%(asctime)s,%(msecs)-3d %(levelname)-8s %(message)s'
        timeformat = '%y/%m/%d %H:%M:%S'
        loghandler = logging.StreamHandler(options.logfile)
        loghandler.setFormatter(logging.Formatter(logformat, timeformat))
        loglevel = logging.WARNING

    log = logging.getLogger("twampy")
    log.setLevel(loglevel)
    log.addHandler(loghandler)

#############################################################################

    if options.dscp:
        if options.dscp in dscpmap:
            options.tos = dscpmap[options.dscp]
        else:
            parser.error("Invalid DSCP Value '%s'" % options.dscp)

    options.func(options)

# EOF
