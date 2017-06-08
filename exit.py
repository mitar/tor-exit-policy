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

  def rejected_addresses():
    tor_exit_policy_reject_ipv4 = []
    tor_exit_policy_reject_ipv6 = []

    # We add both entries to proxy and entries not to proxy to the reject policy.
    # We do not want to allow tor exit to any of those Internet addresses.

    for address, mask in ips_to_never_proxy:
      # Two-tuple form for the address constructor parameter was added in Python 3.5.
      tor_exit_policy_reject_ipv4.append(ipaddress.IPv4Network((address, mask)))

    domains = []
    for shexps in shexps_to_never_proxy:
      domains.append(urlparse(shexps).hostname)
    for shexps in shexps_to_proxy:
      domains.append(urlparse(shexps).hostname)
    domains += domains_to_proxy

    with multiprocessing.Pool(PARALLELISM) as pool:
      addresses = [address for resolved_addresses in pool.imap_unordered(resolve_domain, domains) for address in resolved_addresses]

    tor_exit_policy_reject_ipv4 += [address for address in addresses if isinstance(address, ipaddress.IPv4Network)]
    tor_exit_policy_reject_ipv6 += [address for address in addresses if isinstance(address, ipaddress.IPv6Network)]

    for address in sorted(ipaddress.collapse_addresses(tor_exit_policy_reject_ipv4)):
      # Some DNS entries resolve to invalid addresses. Filter some of them out.
      if address.is_multicast or address.is_private or address.is_reserved or address.is_loopback or address.is_link_local:
        continue
      yield address

    for address in sorted(ipaddress.collapse_addresses(tor_exit_policy_reject_ipv6)):
      # Some DNS entries resolve to invalid addresses. Filter some of them out.
      if address.is_multicast or address.is_private or address.is_reserved or address.is_loopback or address.is_link_local:
        continue
      yield address

  for address in rejected_addresses():
    if isinstance(address, ipaddress.IPv4Network):
      print('reject {address}:*'.format(address=address))
    elif isinstance(address, ipaddress.IPv6Network):
      print('reject6 [{address}]/{mask}:*'.format(address=address.network_address, mask=address.prefixlen))
    else:
      raise TypeError("Unknown address type: {address}".format(address=address))

