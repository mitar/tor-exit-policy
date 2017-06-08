#!/usr/bin/env python3

import ipaddress
import logging
import multiprocessing
import pyjsparser
import socket
from urllib.parse import urlparse
from urllib.request import urlopen

logger = logging.getLogger(__file__)

PROXY_PAC_URL = 'http://proxy.lib.berkeley.edu/proxy.pac'
PARALLELISM = 10

def resolve_domain(hostname):
  result = []

  try:
    for family, type, proto, canonname, sockaddr in socket.getaddrinfo(host=hostname, port=None, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP):
      if family == socket.AF_INET:
        result.append(ipaddress.IPv4Network(sockaddr[0]))
      elif family == socket.AF_INET6:
        result.append(ipaddress.IPv6Network(sockaddr[0]))
  except socket.gaierror as error:
    logger.info("Cannot resolve '{hostname}': {error}".format(hostname=hostname, error=error))

  return result

if __name__ == '__main__':
  with urlopen(PROXY_PAC_URL) as request:
    proxy_pac = request.read().decode('utf8')

  parsed_proxy_pac = pyjsparser.PyJsParser().parse(proxy_pac)

  def find_assignment_to(parsed, variable_name):
    type = parsed['type']
    if type in ('Program', 'BlockStatement'):
      for body in parsed['body']:
        found = find_assignment_to(body, variable_name)
        if found:
          return found
    elif type in ('FunctionDeclaration', 'WhileStatement'):
      return find_assignment_to(parsed['body'], variable_name)
    elif type == 'IfStatement':
      return find_assignment_to(parsed['consequent'], variable_name) or (parsed['alternate'] and find_assignment_to(parsed['alternate'], variable_name))
    elif type == 'VariableDeclaration':
      for declaration in parsed['declarations']:
        if declaration['id']['name'] == variable_name:
          return declaration['init']
    elif type == 'ExpressionStatement':
      if parsed['expression']['operator'] == '=' and parsed['expression']['left']['name'] == variable_name:
        return parsed['expression']['right']
    elif type in ('EmptyStatement', 'ReturnStatement'):
      return
    else:
      logger.warn("Unknown type {type}.".format(type=type))

  def convert_value(parsed):
    if parsed is None:
      return None

    type = parsed['type']
    if type == 'ArrayExpression':
      return [convert_value(element) for element in parsed['elements']]
    if type == 'Literal':
      return parsed['value']
    else:
      logger.warn("Unknown type {type}.".format(type=type))
      print(parsed)

  ips_to_never_proxy = convert_value(find_assignment_to(parsed_proxy_pac, 'ips_to_never_proxy'))
  shexps_to_never_proxy = convert_value(find_assignment_to(parsed_proxy_pac, 'shexps_to_never_proxy'))
  domains_to_proxy = convert_value(find_assignment_to(parsed_proxy_pac, 'domains_to_proxy'))
  shexps_to_proxy = convert_value(find_assignment_to(parsed_proxy_pac, 'shexps_to_proxy'))

  # Some DNS entries resolve to invalid addresses. Filter some of them out.
  def valid_address(address):
    return not (address.is_multicast or address.is_private or address.is_reserved or address.is_loopback or address.is_link_local)

  def rejected_addresses():
    addresses_ipv4 = [
      # OVH
      ipaddress.IPv4Network('5.39.0.0/17'),
      ipaddress.IPv4Network('158.69.0.0/16'),
      # Akamai Technologies
      ipaddress.IPv4Network('23.32.0.0/11'),
      ipaddress.IPv4Network('23.64.0.0/14'),
      ipaddress.IPv4Network('23.72.0.0/13'),
      ipaddress.IPv4Network('23.192.0.0/11'),
      ipaddress.IPv4Network('23.195.112.0/20'),
      ipaddress.IPv4Network('96.6.0.0/15'),
      ipaddress.IPv4Network('104.64.0.0/10'),
      ipaddress.IPv4Network('184.24.0.0/13'),
      # Amazon Technologies
      ipaddress.IPv4Network('34.192.0.0/10'),
      ipaddress.IPv4Network('50.16.0.0/14'),
      ipaddress.IPv4Network('52.0.0.0/11'),
      ipaddress.IPv4Network('52.32.0.0/11'),
      ipaddress.IPv4Network('54.64.0.0/11'),
      ipaddress.IPv4Network('52.84.0.0/14'),
      ipaddress.IPv4Network('52.88.0.0/13'),
      ipaddress.IPv4Network('52.192.0.0/11'),
      ipaddress.IPv4Network('54.208.0.0/12'),
      ipaddress.IPv4Network('54.224.0.0/12'),
      # Linode
      ipaddress.IPv4Network('45.33.0.0/17'),
      # Leaseweb
      ipaddress.IPv4Network('162.210.192.0/21'),
      # Google
      ipaddress.IPv4Network('216.58.192.0/19'),
      # Incapsula
      ipaddress.IPv4Network('192.230.64.0/18'),
    ]
    addresses_ipv6 = [
      # Pantheon
      ipaddress.IPv6Network('2620:12A:8000::/44'),
      # Incapsula
      ipaddress.IPv6Network('2a02:e980::/29'),
    ]

    # We add both entries to proxy and entries not to proxy to the reject policy.
    # We do not want to allow tor exit to any of those Internet addresses.

    for address, mask in ips_to_never_proxy:
      # Two-tuple form for the address constructor parameter was added in Python 3.5.
      addresses_ipv4.append(ipaddress.IPv4Network((address, mask)))

    domains = []
    for shexps in shexps_to_never_proxy:
      domains.append(urlparse(shexps).hostname)
    for shexps in shexps_to_proxy:
      domains.append(urlparse(shexps).hostname)
    domains += domains_to_proxy

    with multiprocessing.Pool(PARALLELISM) as pool:
      # We have to flatten resolved addresses.
      addresses = [address for resolved_addresses in pool.imap_unordered(resolve_domain, domains) for address in resolved_addresses]

    addresses_ipv4 += [address for address in addresses if isinstance(address, ipaddress.IPv4Network)]
    addresses_ipv6 += [address for address in addresses if isinstance(address, ipaddress.IPv6Network)]
    
    addresses_ipv4 = [address.supernet(new_prefix=24) if address.prefixlen > 24 else address for address in addresses_ipv4]
    addresses_ipv6 = [address.supernet(new_prefix=48) if address.prefixlen > 48 else address for address in addresses_ipv6]

    # Collapse and filter addresses.
    addresses_ipv4 = [address for address in ipaddress.collapse_addresses(addresses_ipv4) if valid_address(address)]
    addresses_ipv6 = [address for address in ipaddress.collapse_addresses(addresses_ipv6) if valid_address(address)]

    return sorted(addresses_ipv4) + sorted(addresses_ipv6)

  for address in rejected_addresses():
    if isinstance(address, ipaddress.IPv4Network):
      print('reject {address}:*'.format(address=address))
    elif isinstance(address, ipaddress.IPv6Network):
      print('reject6 [{address}]/{mask}:*'.format(address=address.network_address, mask=address.prefixlen))
    else:
      raise TypeError("Unknown address type: {address}".format(address=address))

