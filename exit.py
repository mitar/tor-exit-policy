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

def resolve_networks(addresses):
  content = '\n'.join((
    'begin',
    'prefix',
    'noasname',
    'noheader',
    'noallocdate',
    'noregistry',
    'noasnumber',
    'nocountrycode',
  ))

  content += '\n' + '\n'.join([str(address.network_address) for address in addresses]) + '\nend\n'

  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect(('whois.cymru.com', 43))
    s.sendall(content.encode())
    s.shutdown(socket.SHUT_WR)

    response = ''
    while True:
      data = s.recv(4096)
      if not data:
        break
      response += data.decode('utf8')

  lines = response.splitlines()

  networks = []

  assert lines[0].startswith('Bulk mode')
  for i, line in enumerate(lines[1:]):
    network_string = line.split('|')[2].strip()
    try:
       networks.append(ipaddress.ip_network(network_string))
    except ValueError as error:
      logger.error("Invalid network '{network}' for address '{address}': {error}".format(network=network_string, address=addresses[i], error=error))
      networks.append(addresses[i])

  return networks

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

  ips_to_never_proxy = convert_value(find_assignment_to(parsed_proxy_pac, 'ips_to_never_proxy'))
  shexps_to_never_proxy = convert_value(find_assignment_to(parsed_proxy_pac, 'shexps_to_never_proxy'))
  domains_to_proxy = convert_value(find_assignment_to(parsed_proxy_pac, 'domains_to_proxy'))
  shexps_to_proxy = convert_value(find_assignment_to(parsed_proxy_pac, 'shexps_to_proxy'))

  # Some DNS entries resolve to invalid addresses. Filter some of them out.
  def valid_address(address):
    # Private IPs are rejected by Tor by default.
    return not (address.is_multicast or address.is_private or address.is_reserved or address.is_loopback or address.is_link_local)

  def rejected_addresses():
    addresses = []

    # We add both entries to proxy and entries not to proxy to the reject policy.
    # We do not want to allow tor exit to any of those Internet addresses.

    for address, mask in ips_to_never_proxy:
      # Two-tuple form for the address constructor parameter was added in Python 3.5.
      addresses.append(ipaddress.IPv4Network((address, mask)))

    domains = []
    for shexps in shexps_to_never_proxy:
      domains.append(urlparse(shexps).hostname)
    for shexps in shexps_to_proxy:
      domains.append(urlparse(shexps).hostname)
    domains += domains_to_proxy

    with multiprocessing.Pool(PARALLELISM) as pool:
      # We have to flatten resolved addresses.
      addresses += [address for resolved_addresses in pool.imap_unordered(resolve_domain, domains) for address in resolved_addresses]

    addresses = [address for address in addresses if valid_address(address)]

    addresses = resolve_networks(addresses)

    addresses_ipv4 = [address for address in addresses if isinstance(address, ipaddress.IPv4Network)]
    addresses_ipv6 = [address for address in addresses if isinstance(address, ipaddress.IPv6Network)]

    # Collapse addresses.
    addresses_ipv4 = ipaddress.collapse_addresses(addresses_ipv4)
    addresses_ipv6 = ipaddress.collapse_addresses(addresses_ipv6)

    return sorted(addresses_ipv4) + sorted(addresses_ipv6)

  for address in rejected_addresses():
    if isinstance(address, ipaddress.IPv4Network):
      print('reject {address}:*'.format(address=address))
    elif isinstance(address, ipaddress.IPv6Network):
      print('reject6 [{address}]/{mask}:*'.format(address=address.network_address, mask=address.prefixlen))
    else:
      raise TypeError("Unknown address type: {address}".format(address=address))

