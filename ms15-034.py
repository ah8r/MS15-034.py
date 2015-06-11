#!/usr/bin/python

import requests
import argparse
import sys
import re
import socket

# Copyright (c) 2007 Brandon Sterne
# Licensed under the MIT license.
# http://brandon.sternefamily.net/files/mit-license.txt
# CIDR Block Converter - 2007

# convert an IP address from its dotted-quad format to its
# 32 binary digit representation
def ip2bin(ip):
    b = ""
    inQuads = ip.split(".")
    outQuads = 4
    for q in inQuads:
        if q != "":
            b += dec2bin(int(q),8)
            outQuads -= 1
    while outQuads > 0:
        b += "00000000"
        outQuads -= 1
    return b

# convert a decimal number to binary representation
# if d is specified, left-pad the binary number with 0s to that length
def dec2bin(n,d=None):
    s = ""
    while n>0:
        if n&1:
            s = "1"+s
        else:
            s = "0"+s
        n >>= 1
    if d is not None:
        while len(s)<d:
            s = "0"+s
    if s == "": s = "0"
    return s

# convert a binary string into an IP address
def bin2ip(b):
    ip = ""
    for i in range(0,len(b),8):
        ip += str(int(b[i:i+8],2))+"."
    return ip[:-1]

# return a list of IP addresses based on the CIDR block specified
def getCIDR(c):
    ips = []
    parts = c.split("/")
    baseIP = ip2bin(parts[0])
    subnet = int(parts[1])
    # Python string-slicing weirdness:
    # "myString"[:-1] -> "myStrin" but "myString"[:0] -> ""
    # if a subnet of 32 was specified simply print the single IP
    if subnet == 32:
        ips.append(bin2ip(baseIP))
        return ips
    # for any other size subnet, print a list of IP addresses by concatenating
    # the prefix with each of the suffixes in the subnet
    else:
        ipPrefix = baseIP[:-(32-subnet)]
        for i in range(2**(32-subnet)):
            ips.append(bin2ip(ipPrefix+dec2bin(i, (32-subnet))))
        return ips

# input validation routine for the CIDR block specified
def validateCIDRBlock(b):
    # appropriate format for CIDR block ($prefix/$subnet)
    p = re.compile("^([0-9]{1,3}\.){0,3}[0-9]{1,3}(/[0-9]{1,2}){1}$")
    if not p.match(b):
        #print "Error: Invalid CIDR format!"
        return False
    # extract prefix and subnet size
    prefix, subnet = b.split("/")
    # each quad has an appropriate value (1-255)
    quads = prefix.split(".")
    for q in quads:
        if (int(q) < 0) or (int(q) > 255):
            #print "Error: quad "+str(q)+" wrong size."
            return False
    # subnet is an appropriate value (1-32)
    if (int(subnet) < 1) or (int(subnet) > 32):
        #print "Error: subnet "+str(subnet)+" wrong size."
        return False
    # passed all checks -> return True
    return True

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--resources', type=str, help='The path to a file containing a newline separated list of resources to test. (default: /, /iisstart.htm, /iis-85.png, /iis-8.png, /ws8-brand.png, /msweb-brand.png, /welcome.png')
    parser.add_argument('-p', '--ports', type=str, default='80,ssl:443', help='Comma separated list of ports to check. Prefix port with \'ssl:\' to connect over SSL/TLS (default: 80,ssl:443)')
    parser.add_argument('-v', '--verbose', action='store_true', default=False, help='Verbose output.')
    parser.add_argument('targets', metavar='target', nargs='+', help='A target to scan.')
    args = parser.parse_args()

    verbose = args.verbose
    
    ports = args.ports.split(',')
    for port in ports:
        if port.startswith('ssl:'):
            port = port.split('ssl:')[1]
        if not port.isdigit():
            print('Port \'' + port + '\' is not an integer.', file=sys.stderr)
            sys.stderr.flush()
            sys.exit(1)
        port = int(port)
        if port <= 0 or port > 65535:
            print('Port \'' + str(port) + '\' is not a valid port number.', file=sys.stderr)
            sys.stderr.flush()
            sys.exit(1)

    if args.resources:
        try:
            with open(args.resources) as f:
                resources = f.readlines()
                resources = [x.strip('\n') for x in resources]
        except:
            print('File \'' + args.resources + '\' did not exist or could not be read.', file=sys.stderr)
            sys.stderr.flush()
            sys.exit(1)
    else:
        resources = ['/', '/iisstart.htm', '/iis-85.png', '/iis-8.png', '/ws8-brand.png', '/msweb-brand.png', '/welcome.png']
        
    targets = []
    
    for t in args.targets:
        for t2 in t.split(','):
            t2 = t2.strip()
            if validateCIDRBlock(t2):
                for t3 in getCIDR(t2):
                    if t3 not in targets:
                        targets.append(t3)
            else:
                if t2 and t2 not in targets:
                    targets.append(t2)
    
    for target in targets:
        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror as e:
            print('[INFO] Testing target: ' + target)
            sys.stdout.flush()
            print('\033[93m[ERROR] Could not resolve an IP address for the given target.\033[0m\n')
            sys.stderr.flush()
            continue
        
        vulnerable = False
        success = False
        for port in ports:
            ssl = False
            ssl_text = ''
            if port.startswith('ssl:'):
                ssl = True
                port = port.split('ssl:')[1]
                ssl_text = ' (SSL)'
            
            if ip == target:
                print('[INFO] Testing target: ' + target + ':' + port + ssl_text)
            else:
                print('[INFO] Testing target: ' + target + ':' + port + ' (' + str(ip) + ':' + port + ')' + ssl_text)
            sys.stdout.flush()
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15)
            result = sock.connect_ex((target, int(port)))
            if result != 0:
                print('\033[93m[ERROR] Port ' + str(port) + ' is closed. Skipping tests on this port.\033[0m')
                sys.stderr.flush()
                continue
                
            for resource in resources:
                schema = 'http'
                if ssl:
                    schema = 'https'
                targetString = schema + '://' + target + ':' + port + resource
                
                if verbose:
                    print('[INFO] Attempting to trigger vulnerability on ' + targetString)
                try:
                    r = requests.get(targetString, headers={'Range':'bytes=0-18446744073709551615'}, verify=False, timeout=15)
                except Exception as e:
                    print('\033[93m[ERROR] Exception! Likely a connection timeout / misconfigured web server.\033[0m')
                    continue
                
                if verbose:
                    print('[INFO] Status Code: ' + str(r.status_code))
                    if 'server' in r.headers:
                        print('[INFO] Server: ' + r.headers['server'])
                
                if r.status_code == 416: # Vulnerable
                    success = True
                    vulnerable = True
                    error = False
                    break
                elif r.status_code == 400: # Patched
                    success = True
                    error = False
                    break
            
            if success: # If the vulnerability or patch is confirmed, skip remaining tests.
                break
        
        if success:
            if vulnerable:
                print('\033[91m\033[1m[FAIL] Received "416 Requested Range Not Satisfiable" response code. ' + target + ' is vulnerable!\033[0m\n')
            else:
                print('\033[1m[PASS] Received "400 Bad Request" response code. ' + target + ' has been patched!\033[0m\n')
        else:
            print('\033[93m[ERROR] The response codes received could not be used to determine whether the host was vulnerable or whether it had been patched. Other resources are required for ' + target +'.\033[0m\n')
