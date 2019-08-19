#!/usr/bin/env python
"""
Determine whether a website supports HSTS.
"""

import boto3
import dns.resolver
import requests
import sys
import socket

# TODO: Stop using globals for all this stuff.
global_dns_cache = {}

# Inspired by: https://stackoverflow.com/a/15065711/868533
prv_getaddrinfo = socket.getaddrinfo
def new_getaddrinfo(*args):
  # Uncomment to see what calls to `getaddrinfo` look like.
  try:
    return global_dns_cache[args[:2]] # hostname and port
  except KeyError:
    return prv_getaddrinfo(*args)

socket.getaddrinfo = new_getaddrinfo

def check_all_addresses(hostname):
  verdicts = {}
  for address in get_addresses(hostname, record_type='A'):
    verdicts[address] = has_hsts(hostname, address, is_ipv6=False)
  for address in get_addresses(hostname, record_type='AAAA'):
    verdicts[address] = has_hsts(hostname, address, is_ipv6=True)
  return verdicts

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
  global_dns_cache[key] = [value]

def has_hsts(site, ip_string, is_ipv6=False):
  # print("checking %s at address %s" % (site, ip_string))
  add_custom_dns(site, 443, ip_string, is_ipv6)
  try:
    response = requests.get('https://' + site)
  except requests.exceptions.ConnectionError as error:
    message = '%s(%s) couldn\'t be reached: %s' % (site, ip_string, error, )
    if is_ipv6:
      message = ('%s - are you able to reach ipv6 addresses from this '
                      'network?' % (message,))
    print(message)
    return False
  except requests.exceptions.SSLError as error:
    print("%s(%s) doesn't have SSL working properly (%s)" %
          (site, ip_string, error, ))
    return False

  all_responses_good = True
  if response.history:
    for resp in response.history:
      all_responses_good &= check_response_hsts(ip_string, resp)
  # Either way check the final redirect landing point.
  all_responses_good = check_response_hsts(ip_string, response)
  return all_responses_good

def check_response_hsts(ip_string, response):
  sts_header = response.headers.get('strict-transport-security')
  if sts_header == 'max-age=31536000; includeSubDomains; preload':
    print("%s(%s) appears to have correct HSTS!" %
          (response.url, ip_string,))
    return True
  else:
    print('%s(%s) did not return the expected strict-transport security '
          'header. Header returned: %s' % (
            response.url, ip_string, sts_header,))
    return False

def put_cloudwatch_metric(client, hostname, address, verdict):
  response = client.put_metric_data(
    Namespace = 'mark-test-hsts',
        MetricData=[
          {
              'MetricName': 'hsts_correct',
              'Dimensions': [
                  {
                      'Name': 'hostname',
                      'Value': hostname
                  },
                  {
                      'Name': 'ip_address',
                      'Value': address
                  },
              ],
              # Cloudwatch metrics cannot be boolean so we return 1 or 0
              'Value': int(verdict),
          },
      ]
  )
  print('response: {response}'.format(response=response))

def check_and_report_all_addresses(cloudwatch, hostname):
  verdicts = check_all_addresses(hostname)
  for address in verdicts:
    put_cloudwatch_metric(cloudwatch, hostname, address, verdicts[address])

def lambda_handler(event, context):
  print('Beginning Lambda handler for event: {a}'.format(a=event))
  hostname = event['hostname']
  cloudwatch = boto3.client('cloudwatch')
  check_and_report_all_addresses(cloudwatch, hostname)

def main(hostname):
  """
  Main functionality.
  """
  cloudwatch = boto3.client('cloudwatch')
  check_and_report_all_addresses(cloudwatch, hostname)

if __name__ == '__main__':
  print(sys.argv)
  if len(sys.argv) != 2:
    print('usage: %s hostname' % (sys.argv[0], ))
    exit(1)

  main(sys.argv[1])

