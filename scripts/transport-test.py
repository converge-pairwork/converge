#!/usr/bin/env python3
"""The bridge has one way to reach a peer, and says plainly when it cannot.

    python3 scripts/transport-test.py [path/to/converge-bridge]

It drives the real bridge binary over stdio MCP against a small fake relay in this process, so it
needs no network, no account and no real relay. What it holds the binary to:

  1. There is no gateway login. `--gateway-secret` is an unknown option, and no hello the bridge
     sends carries a `gateway` field: a bearer hello carries the key, an identity hello carries
     the handle and signatures and no key.
  2. A payload the bridge sends leaves it sealed: the frame the relay receives is binary and
     does not contain the message text.
  3. `converge_call` tells a relay it cannot reach apart from a peer that does not answer:
       relay never reachable      "relay unreachable: the call was not placed"
       relay lost while calling   "lost the connection to the relay while calling: ..."
       relay answers with error   that error, unchanged
       relay up, peer silent      "no answer: the peer's session has not accepted yet"
     A relay that comes up while the call is waiting is used; a call that was refused is not
     sent later, when the relay comes back.
  4. Nothing else is tried: an `ssh`, `scp` or `sftp` placed first on PATH is never run.
"""
import testhome  # noqa: F401  (isolates HOME before anything is launched)
import base64
import hashlib
import json
import os
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GUID = b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'


def bridge_path():
    if len(sys.argv) > 1:
        return Path(sys.argv[1])
    build = ROOT / 'bridge' / 'build'
    for candidate in (build / 'converge-bridge', build / 'converge-bridge.exe',
                      build / 'Release' / 'converge-bridge.exe', build / 'Debug' / 'converge-bridge.exe'):
        if candidate.is_file():
            return candidate
    return build / 'converge-bridge'


BRIDGE = bridge_path()
if not BRIDGE.is_file():
    sys.exit('transport test: no converge-bridge at %s; build it first, or name one as an argument' % BRIDGE)
ok = True


def check(c, what):
    global ok
    print(('PASS ' if c else 'FAIL ') + what, flush=True)
    ok &= bool(c)


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class FakeRelay:
    """Just enough of the relay's WebSocket side: challenge, hello, welcome, then one behaviour
    for `call`. mode is 'silent' (never answers), 'error' (answers with an error frame), 'drop'
    (closes the connection and stops listening) or 'connect' (connects the call to a peer whose
    key is 32 random bytes, so nobody here can open what the bridge seals)."""

    def __init__(self, mode, port=None):
        self.mode = mode
        self.hellos, self.calls, self.binary = [], [], []
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('127.0.0.1', port or 0))
        self.port = self.sock.getsockname()[1]
        self.sock.listen(8)
        self.open = True
        threading.Thread(target=self._accept, daemon=True).start()

    def close(self):
        self.open = False
        try:
            self.sock.close()
        except OSError:
            pass

    def _accept(self):
        while self.open:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    @staticmethod
    def _recv_exact(conn, n):
        buf = b''
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                raise ConnectionError('closed')
            buf += chunk
        return buf

    def _read(self, conn):
        b0, b1 = self._recv_exact(conn, 2)
        n = b1 & 0x7f
        if n == 126:
            n = struct.unpack('>H', self._recv_exact(conn, 2))[0]
        elif n == 127:
            n = struct.unpack('>Q', self._recv_exact(conn, 8))[0]
        mask = self._recv_exact(conn, 4) if b1 & 0x80 else b'\0\0\0\0'
        data = bytes(c ^ mask[i % 4] for i, c in enumerate(self._recv_exact(conn, n)))
        return b0 & 0x0f, data

    @staticmethod
    def _send(conn, obj):
        data = json.dumps(obj).encode()
        n = len(data)
        head = bytes([0x81]) + (bytes([n]) if n < 126 else bytes([126]) + struct.pack('>H', n))
        conn.sendall(head + data)

    def _serve(self, conn):
        try:
            req = b''
            while b'\r\n\r\n' not in req:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                req += chunk
            key = next(l.split(b':', 1)[1].strip() for l in req.split(b'\r\n')
                       if l.lower().startswith(b'sec-websocket-key:'))
            accept = base64.b64encode(hashlib.sha1(key + GUID).digest())
            conn.sendall(b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n'
                         b'Connection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + b'\r\n\r\n')
            self._send(conn, {'t': 'challenge', 'nonce': os.urandom(16).hex(), 'v': 3})
            _, data = self._read(conn)
            self.hellos.append(json.loads(data))
            self._send(conn, {'t': 'welcome', 'v': 3, 'handle': 'cvh_000000000000', 'alias': 'test',
                              'account': 'sol_test', 'balance': 0, 'policy': 'account',
                              'auto_accept': False, 'auth': 'bearer', 'identity': '',
                              'features': ['call-keys-v3', 'exchange-v3']})
            while True:
                op, data = self._read(conn)
                if op == 0x8:
                    return
                if op == 0x9:
                    continue
                if op == 0x2:
                    self.binary.append(data)
                    self._send(conn, {'t': 'usage', 'units': 1, 'balance': 0})
                    continue
                msg = json.loads(data)
                if msg.get('t') == 'ping':
                    self._send(conn, {'t': 'pong'})
                if msg.get('t') != 'call':
                    continue
                self.calls.append(msg)
                if self.mode == 'error':
                    self._send(conn, {'t': 'error', 'code': 'unknown_peer', 'msg': 'no such handle or alias'})
                elif self.mode == 'drop':
                    self.close()
                    conn.close()
                    return
                elif self.mode == 'connect':
                    call_id = 'call_' + os.urandom(6).hex()
                    self._send(conn, {'t': 'calling', 'call_id': call_id})
                    self._send(conn, {'t': 'connected', 'call_id': call_id, 'key_context_version': 3,
                                      'role': 'caller', 'peer': msg.get('to', ''), 'peer_alias': 'peer',
                                      'peer_pub': base64.b64encode(os.urandom(32)).decode(),
                                      'peer_identity': '', 'peer_pub_sig': ''})
        except (OSError, ConnectionError, ValueError, StopIteration):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


class Bridge:
    def __init__(self, port, *args, env=None):
        self.p = subprocess.Popen([str(BRIDGE), '--relay', 'ws://127.0.0.1:%d/v1/ws' % port, *args],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  env=env, encoding='utf-8', bufsize=1)
        self.n = 0
        self.rpc('initialize', {'protocolVersion': '2025-06-18', 'capabilities': {},
                                'clientInfo': {'name': 'transport-test'}})

    def rpc(self, method, params):
        self.n += 1
        self.p.stdin.write(json.dumps({'jsonrpc': '2.0', 'id': self.n, 'method': method, 'params': params}) + '\n')
        self.p.stdin.flush()
        return json.loads(self.p.stdout.readline()).get('result', {})

    def tool(self, name, **args):
        return json.loads(self.rpc('tools/call', {'name': name, 'arguments': args})['content'][0]['text'])

    def close(self):
        try:
            self.p.stdin.close()
            self.p.wait(timeout=5)
        except Exception:
            self.p.kill()
            self.p.wait()


def wait_for(fn, seconds=10):
    end = time.time() + seconds
    while time.time() < end:
        if fn():
            return True
        time.sleep(.05)
    return False


KEY = 'cvg_' + '0' * 32
with tempfile.TemporaryDirectory(prefix='converge-transport-') as tmp:
    trap = Path(tmp) / 'trap'
    trap.mkdir()
    tripped = Path(tmp) / 'ssh-was-run'
    if os.name != 'nt':
        for name in ('ssh', 'scp', 'sftp'):
            fake = trap / name
            fake.write_text('#!/bin/sh\necho "$0 $*" >> "%s"\nexit 1\n' % tripped)
            fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    env = dict(os.environ, PATH=str(trap) + os.pathsep + os.environ.get('PATH', ''))

    # --- 1. no gateway login ---------------------------------------------------------------
    r = subprocess.run([str(BRIDGE), '--relay', 'ws://127.0.0.1:1/v1/ws', '--handle', 'cvh_000000000000',
                        '--gateway-secret', 'anything'], capture_output=True, text=True, timeout=20)
    check(r.returncode == 2, '--gateway-secret is not an option: the bridge refuses it and exits 2')

    relay = FakeRelay('silent')
    b = Bridge(relay.port, '--key', KEY, env=env)
    check(wait_for(lambda: relay.hellos), 'a bearer bridge says hello to the relay')
    hello = relay.hellos[0]
    check(hello.get('key') == KEY and 'gateway' not in hello and 'sig' not in hello,
          'the bearer hello carries the key and no gateway field')
    b.close()
    ident = Bridge(relay.port, '--handle', 'cvh_000000000001', '--identity-file', str(Path(tmp) / 'identity'), env=env)
    check(wait_for(lambda: len(relay.hellos) > 1), 'an identity bridge says hello to the relay')
    hello = relay.hellos[-1]
    check(hello.get('handle') == 'cvh_000000000001' and hello.get('sig') and hello.get('pub_sig')
          and 'key' not in hello and 'gateway' not in hello,
          'the identity hello carries the handle and both signatures, no key and no gateway field')
    ident.close()
    relay.close()

    # --- 2. a payload leaves the bridge sealed -----------------------------------------------
    relay = FakeRelay('connect')
    b = Bridge(relay.port, '--key', KEY, env=env)
    call = b.tool('converge_call', to='cvh_000000000002', wait_sec=10)
    check(call.get('ok') is True, 'a call through a reachable relay connects')
    marker = 'plaintext-marker-' + os.urandom(8).hex()
    sent = b.tool('converge_send', body=marker, wait_sec=0)
    check(sent.get('ok') is True, 'a message is sent in the call')
    check(wait_for(lambda: relay.binary), 'the message reaches the relay as a binary frame')
    frame = relay.binary[0] if relay.binary else b''
    check(marker.encode() not in frame and b'plaintext-marker' not in frame and len(frame) >= 12 + 16 + len(marker),
          'and the frame is ciphertext: nonce, sealed body and tag, with no message text in it')
    b.close()
    relay.close()

    # --- 3. the four ways a call can end without a peer ----------------------------------------
    dead = free_port()
    b = Bridge(dead, '--key', KEY, env=env)
    started = time.time()
    call = b.tool('converge_call', to='cvh_000000000002', wait_sec=3)
    took = time.time() - started
    check(call.get('ok') is False and call.get('relay_connected') is False
          and call.get('error') == 'relay unreachable: the call was not placed',
          'relay never reachable: "%s"' % call.get('error'))
    check(took < 8, 'and the call gave up within its own wait (%.1f s)' % took)
    late = FakeRelay('silent', port=dead)
    check(wait_for(lambda: late.hellos, 40), 'the bridge reaches the relay once it is back')
    time.sleep(1.5)
    check(not late.calls, 'and the refused call is not sent to it afterwards')
    b.close()
    late.close()

    relay = FakeRelay('drop')
    b = Bridge(relay.port, '--key', KEY, env=env)
    wait_for(lambda: relay.hellos)
    call = b.tool('converge_call', to='cvh_000000000002', wait_sec=10)
    check(call.get('ok') is False and call.get('relay_connected') is False
          and call.get('error', '').startswith('lost the connection to the relay while calling'),
          'relay lost while calling: "%s"' % call.get('error'))
    b.close()

    relay = FakeRelay('error')
    b = Bridge(relay.port, '--key', KEY, env=env)
    call = b.tool('converge_call', to='cvh_000000000002', wait_sec=10)
    check(call.get('ok') is False and call.get('error') == 'unknown_peer: no such handle or alias'
          and 'relay_connected' not in call, 'relay error kept as it is: "%s"' % call.get('error'))
    b.close()
    relay.close()

    relay = FakeRelay('silent')
    b = Bridge(relay.port, '--key', KEY, env=env)
    call = b.tool('converge_call', to='cvh_000000000002', wait_sec=2)
    check(call.get('ok') is False and call.get('error') == "no answer: the peer's session has not accepted yet"
          and 'relay_connected' not in call, 'relay up, peer silent: "%s"' % call.get('error'))
    b.close()
    relay.close()

    port = free_port()
    b = Bridge(port, '--key', KEY, env=env)
    result = {}
    t = threading.Thread(target=lambda: result.update(b.tool('converge_call', to='cvh_000000000002', wait_sec=20)))
    t.start()
    time.sleep(1.5)
    relay = FakeRelay('connect', port=port)
    t.join(timeout=30)
    check(result.get('ok') is True, 'a relay that comes up while the call waits is used: the call connects')
    b.close()
    relay.close()

    # --- 4. nothing else was tried ------------------------------------------------------------
    if os.name != 'nt':
        check(not tripped.exists(), 'no ssh, scp or sftp was run: there is no other route')

print('TRANSPORT TEST ' + ('OK' if ok else 'FAILED'))
sys.exit(0 if ok else 1)
