#!/usr/bin/env python
"""
Determine whether a website supports HSTS.
"""

import dns.resolver
import requests
import sys
import socket

dns_cache = {}

def check_all_addresses(hostname):
  for address in get_addresses(hostname, record_type='A'):
    has_hsts(hostname, address, is_ipv6=False)
  for address in get_addresses(hostname, record_type='AAAA'):
    has_hsts(hostname, address, is_ipv6=False)

def get_addresses(hostname, record_type='A'):
  try:
    answers = dns.resolver.query(hostname, record_type)
  except dns.resolver.NoAnswer:
    print('No records of type %s found for %s .' % (record_type, hostname))
    return []
  addresses = list(map(lambda a: a.address, answers))
  print('addresses found: %s' % (addresses,))
  return addresses

def add_custom_dns(hostname, port, ip_string, is_ipv6=False):
  key = (hostname, port)
  # Strange parameters explained at:
  # https://docs.python.org/2/library/socket.html#socket.getaddrinfo
  # Values were taken from the output of `socket.getaddrinfo(...)`
  if is_ipv6:
    value = (socket.AddressFamily.AF_INET6, 1, 6, '', (ip_string, port, 0, 0))
  else:
    value = (socket.AddressFamily.AF_INET, 1, 6, '', (ip_string, port))
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

def has_hsts(site, ip_string, is_ipv6=False):
  # print("checking %s at address %s" % (site, ip_string))
  add_custom_dns(site, 443, ip_string, is_ipv6)
  try:
    req = requests.get('https://' + site)
  except requests.exceptions.SSLError as error:
    print("%s(%s) doesn't have SSL working properly (%s)" %
          (site, ip_string, error, ))
    return False
  sts_header = req.headers.get('strict-transport-security')
  if sts_header == 'max-age=31536000; includeSubDomains; preload':
    print("%s(%s) appears to have correct HSTS!" %
          (site, ip_string,))
    return True
  else:
    print('%s(%s) did not return the expected strict-transport security '
          'header. Header returned: %s' % (site, ip_string, sts_header,))
    return False


def main(hostname):
  """
  Main functionality.
  """
  check_all_addresses(hostname)

if __name__ == '__main__':
  print(sys.argv)
  if len(sys.argv) != 2:
    print('usage: %s hostname' % (sys.argv[0], ))
    exit(1)

  main(sys.argv[1])

