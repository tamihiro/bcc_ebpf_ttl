#!/usr/bin/python

from __future__ import print_function
from bcc import BPF
from ctypes import *
import struct

import os
import sys
import argparse
import socket
from urlparse import urlparse

interface = "enp0s31f6"

def parse_dst(target_uri):
  af_map = dict([('tcp', socket.AF_INET), ('tcp4', socket.AF_INET), ('tcp6', socket.AF_INET6), ])
  try:
    o = urlparse(target_uri)
    afk = o.scheme
    if afk not in af_map.keys():
      raise
    af = af_map[afk]
    host, port = o.netloc.rsplit(':', 1)
    ai = socket.getaddrinfo(host, port, af, 0, socket.IPPROTO_TCP)[0][4]
    return ai[0], int(port), af
  except:
    raise ValueError("Invalid URI: %s" % target_uri)
  
def encode_dst(addr, port, af):
  try:
    b = bytearray()
    if af == socket.AF_INET:
      b.extend([0]*10 + [255]*2)
    b.extend(socket.inet_pton(af, addr))
    b.append(255)
    b.extend(struct.pack('>H', port))
    return b
  except:
    raise ValueError("Invalid URI: %s, %d, %d" % (addr, port, af))

g_ttlmap = dict()  
def add_ttlmap_entry(ttlmap, target_uri):
  g_ttlmap[target_uri] = encode_dst(*parse_dst(target_uri))
  key = ttlmap.Key()
  key.p = (c_ubyte * 19).from_buffer(g_ttlmap[target_uri])
  leaf = ttlmap.Leaf()
  leaf.ttl = c_ubyte()
  ttlmap[key] = leaf

parser = argparse.ArgumentParser(usage='For detailed information about usage,\
 try with -h option',
                                 description='Extract IPv4/IPv6 TTL values from TCP connections.', )
parser.add_argument('target_uri', nargs='+', type=str, help='target URI (up to 128 destinations.)')
args = parser.parse_args()

# can't exceed BPF_HASH() size
if len(args.target_uri) > 128:
  print("%s: error: too many arguments" % parser.prog)
  parser.print_help()
  sys.exit(-1)

# initialize BPF - load source code from ebpf_ttl.c
bpf = BPF(src_file="ebpf_ttl.c", debug=0)

#load eBPF program synack_ttl of type SOCKET_FILTER into the kernel eBPF vm
function_synack_ttl = bpf.load_func("synack_ttl", BPF.SOCKET_FILTER)

#create raw socket, bind it to interface
#attach bpf program to socket created
BPF.attach_raw_socket(function_synack_ttl, interface)

# Get the table.
ttlmap = bpf.get_table("ttlmap")

# Add cache entries
for t in args.target_uri:
  print(">>>> Adding map entry: ", t)
  add_ttlmap_entry(ttlmap, t)

socket.setdefaulttimeout(1)  
for t in args.target_uri:
  addr, port, af = parse_dst(t)
  s = socket.socket(af, socket.SOCK_STREAM)
  s.connect((addr, port))
  
  for k, v in ttlmap.items():
    if k.p == encode_dst(addr, port, af):
      # https://github.com/cloudflare/cloudflare-blog/blob/master/2018-03-ebpf/ebpf.go#L169
      if v.ttl > 128:
        dist = 255 - v.ttl
      elif v.ttl > 64:
        dist = 128 - v.ttl
      elif v.ttl > 32:
        dist = 64 - v.ttl
      else:
        dist = 32 - v.ttl
      h = [t for t in g_ttlmap.keys() if g_ttlmap[t] == k.p][0]
      print("TTL distatnce to %s %s is %d (ttl %d)" % (h, addr, dist, v.ttl))
      break
  s.close()
  
