import argparse
from time import time

from scapy.layers.inet import *

conf.verb = False
supported_protocols = {
    'tcp',
    'udp',
    'icmp'
}


def trace(addr, ttl, max_ttl, type, timeout=2):
    if ttl > max_ttl:
        return

    start = time.time()
    if type == 'icmp':
        reply = sr1(IP(ttl=ttl, dst=addr[0]) / ICMP(), timeout=timeout)
    elif type == 'tcp':
        reply = sr1(IP(ttl=ttl, dst=addr[0]) / TCP(dport=addr[1]), timeout=timeout)
    else:
        reply = sr1(IP(ttl=ttl, dst=addr[0]) / UDP(dport=addr[1]), timeout=timeout)
    end = time.time()

    print(f"{ttl} {reply.src if reply else 'No Reply'} {int((end - start) * 1000)}ms")

    if reply and reply.src == addr[0]:
        return True

    return trace(addr, ttl + 1, max_ttl, type, timeout=timeout)


def traceroute(addr, max_ttl, type, timeout):
    start = time.time()
    result = trace(addr, 1, max_ttl, type, timeout=timeout)
    end = time.time()
    if result:
        print(f"\nFound {addr[0]} in {int((end - start) * 1000)}ms")
    else:
        print(f"\nCould not trace {addr[0]} in {max_ttl} hops.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Traceroute с возможностью отправки пакетов по ICMP, TCP или UDP.')
    parser.add_argument('-t', help='таймаут ожидания ответа (по умолчанию 2с)', type=int, default=2)
    parser.add_argument('-p', help='порт (для tcp или udp)', type=int, default=-1)
    parser.add_argument('-n', help='максимальное количество запросов', type=int, default=64)
    parser.add_argument('-v', help='вывод номера автономной системы для каждого ip-адреса', action='store_true')
    parser.add_argument('ip_addr')
    parser.add_argument('type', help='{tcp|udp|icmp}')

    args = parser.parse_args()

    if args.type.lower() not in supported_protocols:
        print("The specified protocol is not supported.")
    elif args.type != 'icmp' and args.p == -1:
        print("Port is required argument for specified protocol.")
    else:
      traceroute((args.ip_addr, args.p), args.n, args.type, args.t)
