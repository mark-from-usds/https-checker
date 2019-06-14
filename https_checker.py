#!/usr/bin/env python
"""
Determine whether a website supports HSTS.
"""

import requests
import sys
import socket

def is_ipv4(s):
    # Feel free to improve this: https://stackoverflow.com/questions/11827961/checking-for-ip-addresses
    return ':' not in s

dns_cache = {}

def add_custom_dns(domain, port, ip):
    key = (domain, port)
    # Strange parameters explained at:
    # https://docs.python.org/2/library/socket.html#socket.getaddrinfo
    # Values were taken from the output of `socket.getaddrinfo(...)`
    if is_ipv4(ip):
        value = (socket.AddressFamily.AF_INET, 1, 6, '', (ip, port))
    else: # ipv6
        value = (socket.AddressFamily.AF_INET6, 1, 6, '', (ip, port, 0, 0))
    dns_cache[key] = [value]

# Inspired by: https://stackoverflow.com/a/15065711/868533
prv_getaddrinfo = socket.getaddrinfo
def new_getaddrinfo(*args):
    # Uncomment to see what calls to `getaddrinfo` look like.
    try:
        return dns_cache[args[:2]] # hostname and port
    except KeyError:
        return prv_getaddrinfo(*args)

socket.getaddrinfo = new_getaddrinfo

def has_hsts(site, ip_address):
  """
  Connect to target site and check its headers."
  """
  add_custom_dns(site, 443, ip_address)
  try:
    req = requests.get('https://' + site)
  except requests.exceptions.SSLError as error:
    print("doesn't have SSL working properly (%s)" % (error, ))
    return False
  if req.headers.get('strict-transport-security') == 'max-age=31536000; includeSubDomains; preload':
    print("yes")
    return True
  else:
    print("no")
    return False


def main(domain, ip_address):
  """
  Main functionality.
  """
  print('[+] checking whether %s supports HSTS...' % (domain, ),)
  return has_hsts(domain, ip_address)

if __name__ == '__main__':
  print(sys.argv)
  if len(sys.argv) < 2:
    print('usage: %s domain IP' % (sys.argv[0], ))
    exit(1)

  main(sys.argv[1], sys.argv[2])

