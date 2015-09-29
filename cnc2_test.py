#!/usr/bin/env python2.7
"Script for checking if the given host is a Bunitu Tunneling C&C - use at your own risk"

__AUTHOR__ = 'hasherezade'
__VERSION__ = '1.0'

import sys
import time
import struct
import socket
import random
import argparse

from bunitucommon import *

VERBOSE = False

#TUNNEL_IPS = ['95.211.178.145' , '95.211.15.37']
TUNNEL_HOST = 'ns1.joinparty4beer.xyz'
PORT_1 = 53
MALWARE_VERSION = 0xf0b9
XORVALUE = 0x16ec1a31 # old: 0x13107579

TIMEOUT = 3

####
# classes:
#
class BotPayload_t():
    _CMD_START = 0x421

    def __init__(self, bot_id):
        self.bot_id = bot_id

    def get_start_req(self):
        bot_id_len = 8
        bid = self.bot_id[0:bot_id_len]
        request = bytearray()
        request += bytearray(bid)
        request += bytearray(struct.pack("<H", BotPayload_t._CMD_START))
        request += bytearray(struct.pack("<H", 0)) #PADDING
        req_len = len(request) + 2 # len + this WORD
        req_len_arr = bytearray(struct.pack("<H", req_len)) # prompt with request len
        request = req_len_arr + request
        return request

    def get_req(self):
        #TODO: more states
        return self.get_start_req()

####
  
class RespParser_t:

    def __init__(self, bot_id):
        self.bot_id = bot_id

    def get_packages(self, resp_bytes, len_start=0):
        packages = []
        len_end = len_start + 4
        while len_end < len(resp_bytes):
            p_len = resp_bytes[len_start : len_end]
            p_len = struct.unpack("<I", bytes(p_len))[0]
            print "LEN : %x = %d" % (p_len, p_len)
            if len_end > len(resp_bytes):
                break
            p_bytes = resp_bytes[len_end : len_end+p_len]
            len_start = len_end + p_len
            len_end = len_start + 4

            package = Package_t(self.bot_id, p_bytes)
            packages.append(package)
        return packages
####

class Package_t():
    CMD_DNS_QUERY = bytearray([0x01, 0x00, 0x00, 0x01])
    
    def __init__(self, bot_id, p_bytes):
        self.bot_id = bot_id
        self.p_bytes = p_bytes
        #alignments
        self.cmd_start = 4 * 4
        self.cli_session = self.cmd_start + 2 * 4
        self.srv_session = self.cmd_start + 3 * 4
        self.sequencer = self.cmd_start + 4 * 4

    def is_dns_query(self):
        if self.get_cmd_bytes() == Package_t.CMD_DNS_QUERY:
            hostname = self.p_bytes[self.sequencer+1:len(self.p_bytes)-2]
            print "> DNS_QUERY: " + hostname
            return True
        return False

    def get_package_bot_id(self):
        len_end = 4
        if len_end > len(self.p_bytes):
            return
        p_bot_id = self.p_bytes[0:len_end]
        return p_bot_id
    
    def is_bot_id_valid(self):
        p_bot_id = self.get_package_bot_id()
        is_valid = (p_bot_id == self.bot_id[0:len(p_bot_id)])
        if not is_valid:
            print "Bot ID mismatch:"
            dump_bytes(p_bot_id)
        return is_valid
    
    def get_field(self, p_bytes, f_start, f_len=4):
        f_end = f_start + f_len
        if f_end > len(p_bytes):
            return None
        field = p_bytes[f_start:f_end]
        return field
        
    def get_cmd_bytes(self):
        return self.get_field(self.p_bytes, self.cmd_start)

    def get_client_session_id(self):
        return self.get_field(self.p_bytes, self.cli_session)
        
    def get_srv_session_id(self):
        return self.get_field(self.p_bytes, self.srv_session)
        
    def get_sequencer(self):
        return self.get_field(self.p_bytes, self.sequencer, 1)

    def dump_info(self):
        print "----"
        print "BOT id:\t" + bytes_to_str(self.get_package_bot_id())
        print "CMD bytes:\t" + bytes_to_str(self.get_cmd_bytes())
        print "Client session:\t" + bytes_to_str(self.get_client_session_id())
        print "Server session:\t" + bytes_to_str(self.get_srv_session_id())
        print "Sequencer:\t" + bytes_to_str(self.get_sequencer())
        print "----"

def main():
    parser = argparse.ArgumentParser(description="This script can be used to register your host as a proxy in the Bunitu botnet.")
    parser.add_argument('--id',dest="new_id",default=None,help="Specify a new bot id to use. This must be a binary string. Use the --genid command to generate one.")
    parser.add_argument('--genid',dest="gen_id",default=False, action='store_true',help="Generate a new bot id string and quit.")
    parser.add_argument('--verbose', dest="verbose",default=VERBOSE, action='store_true',help="Deploy script in verbose mode.")
    parser.add_argument('--host', dest="cnc_host",default=None, help="C&C Host Name (alternative for explicit IP, use internal algorithm to get C&C IP)")
    parser.add_argument('--ip', dest="cnc_ip",default=None, help="C&C (explicit) IP")
    parser.add_argument('--port', dest="cnc_port",default=PORT_1, help="C&C port, default=%d" % PORT_1, type=int)
    parser.add_argument('--xorval', dest="cnc_xorval",default=str(XORVALUE), help="XOR value used to resolve C&C IP, default=%d (0x%x)" % (XORVALUE, XORVALUE))
    parser.add_argument('--timeout', dest="cnc_timeout",default=PORT_1, help="Timeout fot C&C response, default=%d" % TIMEOUT, type=int)

    args = parser.parse_args()
    args.once = True # hardcoded for tests only!
    
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
    print "C&C#2 (Tunnel): %s:%d" % (target_ip, target_port)
    
    payload = BotPayload_t(bot_id)
    resp_parser = RespParser_t(bot_id)
    is_CnC_confirmed = False
    
    request = payload.get_req()
    if args.verbose : print "REQUEST:"
    if args.verbose : dump_bytes(request)

    #socket start
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((target_ip, target_port))
    send_count= s.send(request)
    if args.verbose : print "sent!"
    response = recv_timeout(s, args.cnc_timeout)
    s.close()

    print "RESPONSE, len: %d" % len(response)
    response_arr = bytearray(response)
    dump_bytes(response_arr)
    packages = resp_parser.get_packages(response_arr)
    print "Packages: %d" % len(packages)
    for pkg in packages:
        if args.verbose : pkg.dump_info()
        if pkg.is_dns_query():
            is_CnC_confirmed = True
    if args.verbose: print is_CnC_confirmed
    print is_CnC_confirmed
    return is_CnC_confirmed

if __name__ == '__main__':
    sys.exit(main())

