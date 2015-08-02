#!/usr/bin/env python2.7
"Set of common functions for scripts to communicate with bunitu C&Cs"

__AUTHOR__ = 'Sergei Frankoff, hasherezade'
__VERSION__ = '1.0'

from util import *

###bitbang lib##
# Author: Satoshi Tanda
def _rol(val, bits, bit_size):
    return (val << bits % bit_size) & (2 ** bit_size - 1) | \
           ((val & (2 ** bit_size - 1)) >> (bit_size - (bits % bit_size)))
### end bitbang ##

####
# bot id util:
#
def get_rtdsc():
    return int (time.time()*1000000000)

def make_new_bot_id():
    eax = get_rtdsc()
    eax = _rol(eax, 3, 32)
    return _make_bot_id(eax, 10)
    
def _make_bot_id(chunk1, id_len=10):
    botID = bytearray()
    eax = chunk1
    botID += bytearray(struct.pack("<I", eax))
    eax -= 1
    eax = (_rol(eax, 2, 32)) + 1
    botID += bytearray(struct.pack("<I", eax)) 
    eax = (_rol(eax, 1, 32)) & 0xFFFF
    botID += bytearray(struct.pack("<H", eax)) 
    return botID[0:id_len]
    
####
# calculate C&C IP
#
def get_c2_ip(hostname, xorval=0x16ec1a31):
    orig_ip = socket.gethostbyname(hostname)
    b_orig_ip = struct.unpack('<L', socket.inet_aton(orig_ip))[0]
    return socket.inet_ntoa(struct.pack('<L',b_orig_ip ^ xorval))
