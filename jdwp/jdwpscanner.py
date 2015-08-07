#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""A quick scanner for JDWP(java debugger) vulnerability """

import socket
import time
import struct
import urllib
import argparse
import select
import signal
import threading
from multiprocessing.dummy import Pool
from jdwpshellifier import JDWPClient

lock = threading.Lock()
threadpool = Pool(processes=50)
socket.setdefaulttimeout(5)
scan_results = []

def signal_handler(signal, frame):
    print "Ctrl+C pressed.. aborting..."
    threadpool.terminate()
    threadpool.done = True

def handle_result(host, port, result):
    tm = time.time()
    with lock:
        scan_results.append([host, port, result])



def jdwp_connect_check(*kw):

    result = False
    retcode = 0

    port = 8000
    #print len(kw), len(*kw), kw
    if len(*kw) == 1:
        host = kw[0][0]
    elif len(*kw) == 2:
        host, port = kw[0][0], int(kw[0][1])
    else:
        print "get para error"

    try:
        cli = JDWPClient(host, port)
        cli.start()
        print "connect target:", host, port
        result = True
        raise KeyboardInterrupt

    except KeyboardInterrupt:
        pass

    except socket.timeout, e:
        print "[-] Timeout: %s" %(e)

    except Exception, e:
        print ("[-] Exception: %s" % e)

    finally:
        try:
            cli.leave()
        except:
            pass

    handle_result(host, port, result)
    return result


def jdwp_file_check(check_file, result_file = None):
    port = 8000

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

    task = threadpool.map(jdwp_connect_check, scan_list)

    threadpool.close()
    threadpool.join()

    vul_results = []
    for x in scan_results:
        print x
        if x[2]:
            vul_results.append(x)

    if result_file:
        with open(result_file, 'w') as f:
            f.write("[JDWP Scan]Scan %d hosts, Find %d jdwp vul\n\n" % (len(scan_results), len(vul_results)))
            for x in vul_results:
                h, p, r = x
                f.write("%s %s\n" %(h, p))

if __name__ == '__main__':


    #target, port = "10.240.137.145", 443
    #jdwp_connect_check([target, port])

    input_file = "host.txt"
    output_file = "jdwp.txt"

    jdwp_file_check(input_file, output_file)