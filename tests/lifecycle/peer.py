#!/usr/bin/env python3
"""Synthetic WireGuard peer, DNS authority and UDP echo; pipe RPC never logs keys."""
import json
import os
import socket
import struct
import sys
import threading
import sandbox as s

s.HOST = json.loads(sys.argv[1])
s.guard()
s.CURRENT = {k: os.readlink('/proc/self/ns/' + k) for k in s.HOST}
seen = []
lock = threading.Lock()


def serve(address, port, dns):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IP, 8, 1)  # IP_PKTINFO
    sock.bind((address, port))

    def loop():
        while True:
            data, anc, flags, source = sock.recvmsg(4096, 256)
            ingress = next((socket.if_indextoname(struct.unpack('I', v[:4])[0])
                            for level, kind, v in anc if level == socket.IPPROTO_IP and kind == 8), None)
            if dns:
                pos = 12
                labels = []
                while data[pos]:
                    n = data[pos]
                    labels.append(data[pos + 1:pos + 1 + n].decode('ascii'))
                    pos += 1 + n
                end = pos + 5
                qtype = struct.unpack('!H', data[pos + 1:pos + 3])[0]
                name = '.'.join(labels)
                answer = '192.0.2.88' if address == '192.0.2.2' else '203.0.113.80'
                response = data[:2] + struct.pack('!HHHHH', 0x8180, 1, int(qtype == 1), 0, 0) + data[12:end]
                if qtype == 1:
                    response += b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 0, 4) + socket.inet_aton(answer)
                record = {'kind': 'dns', 'name': name, 'server': address, 'ingress': ingress}
            else:
                response = data
                record = {'kind': 'echo', 'token': data.decode('ascii'), 'ingress': ingress}
            with lock:
                seen.append(record)
            sock.sendto(response, source)
    threading.Thread(target=loop, daemon=True).start()


print(json.dumps({'pid': os.getpid(), 'netns': s.CURRENT['net']}), flush=True)
for line in sys.stdin:
    try:
        request = json.loads(line)
        op = request['op']
        if op == 'ip':
            out = {'output': s.cmd(['ip', *request['args']])}
        elif op == 'wg':
            s.cmd(['wg', 'setconf', 'wgpeer', '/dev/stdin'], request['config'])
            out = {'ok': True}
        elif op == 'start':
            serve('192.0.2.2', 53, True)
            serve('10.77.0.1', 53, True)
            serve('198.51.100.80', 39071, False)
            out = {'ok': True}
        elif op == 'seen':
            with lock:
                out = {'packets': list(seen)}
        else:
            raise RuntimeError('invalid peer operation')
        print(json.dumps(out), flush=True)
    except Exception as exc:
        print(json.dumps({'error': str(exc)}), flush=True)
