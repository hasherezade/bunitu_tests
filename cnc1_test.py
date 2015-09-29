#!/usr/bin/env python2.7
"Registers your host as a proxy bot in the Bunitu botnet - use at your own risk"

__AUTHOR__ = 'Sergei Frankoff, hasherezade'
__VERSION__ = '1.0'

import sys
import os
import time
import struct
import socket
import argparse

from bunitucommon import *

HOST_1 = 'ns3.joinparty4beer.xyz'
PORT_1 = 53
MALWARE_VERSION = 0xf0b9
XORVALUE = 0x16ec1a31 # old: 0x13107579

HARD_TICKS = 0x67701bf6
TIMEOUT = 1

####
# classes:
#
class BotPayload1_t():
    #public:
    _HEADER = '\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    _HARDCODED1 = 5
    
    def __init__(self, bot_id, port1=43879, port2=12960):
        self.port1 = port1
        self.port2 = port2
        self.bot_id = bot_id
        self.bot_id_len = 10
        self.hours = 0x02 #dummy value
        self.minutes = 0x02 #dummy value
        
    def update_time(self, hours, minutes):
        self.hours = hours
        self.minutes = minutes
             
    def get_bytes(self):
        request = bytearray()
        request += bytearray(BotPayload1_t._HEADER)
        request += bytearray(struct.pack("<H", self.port1))
        request += bytearray(struct.pack("<H", self.port2))
        request += bytearray(struct.pack("<H", BotPayload1_t._HARDCODED1))
        request += bytearray(struct.pack("<B", self.minutes))
        request += bytearray(struct.pack("<B", self.hours))
        request += bytearray(self.bot_id)
        request += bytearray(struct.pack("<I", 0)) #PADDING
        request += bytearray(struct.pack("<H", 0)) #PADDING
        request += bytearray(struct.pack("<I", MALWARE_VERSION))
        request += bytearray(struct.pack("<I", 0)) #PADDING
        return request  

def main():
    parser = argparse.ArgumentParser(description="This script can be used to register your host as a proxy in the Bunitu botnet.")
    parser.add_argument('--id',dest="new_id",default=None,help="Specify a new bot id to use. This must be a binary string. Use the --genid command to generate one.")
    parser.add_argument('--genid',dest="gen_id",default=False, action='store_true',help="Generate a new bot id string and quit.")
    parser.add_argument('--once',dest="once",default=False, action='store_true',help="Only send one request. The default is to repeatedly send requests ever 10min to mimic the real bot.")
    parser.add_argument('--ip', dest="cnc_ip",default=None, help="C&C (explicit) IP")
    parser.add_argument('--host', dest="cnc_host",default=None, help="C&C Host (alternative for explicit IP, use internal algorithm to get C&C IP)")
    parser.add_argument('--port', dest="cnc_port",default=PORT_1, help="C&C port, default=%d" % PORT_1, type=int)
    parser.add_argument('--xorval', dest="cnc_xorval",default=str(XORVALUE), help="XOR value used to resolve C&C IP, default=%d (0x%x)" % (XORVALUE, XORVALUE))
    args = parser.parse_args()
    
    #if they just want a new bot id generate it and print
    if args.gen_id:
        bot_id = make_new_bot_id()
        dump_bytes(bot_id, "\\x", True)
        exit()

    if args.cnc_ip is None and args.cnc_host is None:
        print "Invalid parameters: either C&C IP or Host Name must be filled!"
        exit()

    if args.new_id:
        bot_id = get_bytes(args.new_id)
    else:
        bot_id = make_new_bot_id()
    print "Bot ID:"
    dump_bytes(bot_id)
    print "#"

    target_port = args.cnc_port
    xorv = str_to_int(args.cnc_xorval)
    print "XOR = %x" % xorv

    if args.cnc_ip:
        target_ip = socket.gethostbyname(args.cnc_ip)
    else:
        target_ip = get_c2_ip(args.cnc_host, xorv)
    print "C&C#1: %s:%d" % (target_ip, target_port)

    payload = BotPayload1_t(bot_id)
    
    while True:
        hours, minutes = get_fake_reboot_hours_min()
        print "time since rebooot: %d:%d" % (hours, minutes)
        payload.update_time(hours, minutes)
        
        request = payload.get_bytes()
        print "REQUEST:"
        dump_bytes(request)
        
        #socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target_ip, target_port))
        send_count= s.send(request)
        print "sent!"
        response = recv_timeout(s, TIMEOUT)
        s.close()
        print "response len: %d" % len(response)
        
        #exit if only one request is required 
        if args.once:
            exit()  
        time.sleep(600)

if __name__ == '__main__':
    main()

