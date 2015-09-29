#!/usr/bin/env python2.7
"Set of general utility functions for scripts to communicate with bunitu C&Cs"

__AUTHOR__ = 'Sergei Frankoff, hasherezade'
__VERSION__ = '1.0'

import time
import struct
import socket
import random
import re

####
# convertion util
#
def str_to_int(string):
    string = string.lower()
    if string.startswith("0x"):
        return int(string,16)
    return int(string)

####
# byte util
#
def dump_bytes(bytes_arr, delim=" ", prompt_by_delim=False):
    if not bytes_arr:
        return ""
    str = delim.join("%02x" % b for b in bytes_arr)
    if (prompt_by_delim):
        str = delim + str
    print str

def bytes_to_str(bytes_arr):
    if not bytes_arr:
        return ""
    return "".join("%02x" % b for b in bytes_arr)
    
def get_bytes(buf):
    if not buf:
        return None
    t = re.findall ('[0-9a-fA-F]{2}', buf)
    byte_buf = []
    for chunk in t:
        num = int (chunk, 16)
        byte_buf.append(num)
    return byte_buf

####
# time util:
#
#fake time of last system reboot in millisec:
REBOOT_TIME = 1434924029619

#this is the millisecond time since the system was last rebooted
def get_fake_tick_count():
    #getTickCount has a rollover at 49.7 days
    tick_limit = 4294080000
    tick_delta= int(round(time.time() * 1000)) - REBOOT_TIME
    return tick_delta % tick_limit

#number of hours, min since the system was last rebooted
def get_fake_reboot_hours_min():
    tick_count = get_fake_tick_count()
    total_min = (tick_count/1000)/60
    #fake the cutoff at 255 hours since the bot just wraps
    r_hours = int(int(total_min / 60) % 255)
    r_min = int(total_min % 60)
    return (r_hours, r_min)

#instead of implementing rdtsc and associated bitbang fake it
def get_fake_rdtsc_str():
    rdtsc = time.time()*1000000000
    return struct.pack('>Q',rdtsc)

####
# socket util
#
def recv_timeout(the_socket,timeout=2):
    #make socket non blocking
    the_socket.setblocking(0)
     
    #total data partwise in an array
    total_data=[];
    data='';
     
    #beginning time
    begin=time.time()
    while 1:
        #if you got some data, then break after timeout
        if total_data and time.time()-begin > timeout:
            break
         
        #if you got no data at all, wait a little longer, twice the timeout
        elif time.time()-begin > timeout*2:
            break
         
        #recv something
        try:
            data = the_socket.recv(8192)
            if data:
                total_data.append(data)
                #change the beginning time for measurement
                begin=time.time()
            else:
                #sleep for sometime to indicate a gap
                time.sleep(0.1)
        except:
            pass
               
    #join all parts to make final string
    return ''.join(total_data)
