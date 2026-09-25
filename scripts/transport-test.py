#!/usr/bin/env python3
"""The bridge has one way to reach a peer, and says plainly when it cannot.

    python3 scripts/transport-test.py [path/to/converge-bridge]

It drives the real bridge binary over stdio MCP against a small fake relay in this process, so it
needs no network, no account and no real relay. What it holds the binary to:

  1. There is no gateway login. `--gateway-secret` is an unknown option, and there is no bearer
     key: `--key` is not an option either, and the only credential is the identity key file.
  2. The first frame the bridge sends is a protocol v4 client_hello (QSF, code 1000, protocol 4):
     an ephemeral key and a nonce, and nothing that identifies or authenticates the bridge. The
     identity signs only inside the sealed stream, after the relay has proved its key, and this
     relay, which cannot prove one, never sees a second frame.
  3. `converge_call` tells a relay it cannot reach apart from one that answers: a relay that is
     never reachable, and one that accepts the socket and says nothing usable, both end in
     "relay unreachable: the call was not placed", within the call's own wait. A relay that comes
     up while the bridge is waiting is reached, with a fresh client_hello; a call that was
     refused is not sent later, when the relay comes back.
  4. Nothing else is tried: an `ssh`, `scp` or `sftp` placed first on PATH is never run.

The handshake, the sealed stream, the sealed payloads and the call outcomes against a relay that
answers are held by the CONVERGE service's own integration suites, against the real relay.
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
    """Just enough of the relay's WebSocket side to receive what the bridge sends first. It
    holds no key, so it cannot answer the v4 handshake: every connection ends after the opening
    frame, which is what the test looks at."""

    def __init__(self, port=None):
        self.hellos, self.frames = [], []
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
            # The relay says nothing: the bridge speaks first, with its client_hello. Anything
            # after it (there is nothing, since the handshake cannot complete) is kept too.
            first = True
            conn.settimeout(3)
            while True:
                op, data = self._read(conn)
                if op == 0x8:
                    return
                if op == 0x9:
                    continue
                if first:
                    self.hellos.append({'binary': op == 0x2, 'frame': data})
                    first = False
                else:
                    self.frames.append({'binary': op == 0x2, 'frame': data})
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


def opening(hello):
    """Is this the v4 client_hello: QSF magic 'QS', code 1000, protocol 4 in the body, and nothing
    that identifies or authenticates the bridge?"""
    frame = hello.get('frame', b'')
    return (hello.get('binary') and frame[:2] == b'SQ' and struct.unpack('<I', frame[4:8])[0] == 1000
            and struct.unpack('<H', frame[16:18])[0] == 4
            and b'cvg_' not in frame and b'ssh-ed25519' not in frame and b'cvh_' not in frame and len(frame) < 200)


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
    identity = ['--identity-file', str(Path(tmp) / 'identity')]

    # --- 1. no gateway login, no bearer key -------------------------------------------------------
    r = subprocess.run([str(BRIDGE), '--relay', 'ws://127.0.0.1:1/v1/ws', *identity,
                        '--gateway-secret', 'anything'], capture_output=True, text=True, timeout=20)
    check(r.returncode == 2, '--gateway-secret is not an option: the bridge refuses it and exits 2')
    r = subprocess.run([str(BRIDGE), '--relay', 'ws://127.0.0.1:1/v1/ws', '--key', 'cvg_' + '0' * 32],
                       capture_output=True, text=True, timeout=20)
    check(r.returncode == 2 and 'usage:' in r.stderr and '--key' not in r.stderr.split('usage:', 1)[1],
          '--key is not an option: there is no bearer credential, and the usage does not offer one')
    r = subprocess.run([str(BRIDGE), '--relay', 'ws://127.0.0.1:1/v1/ws', '--help'],
                       capture_output=True, text=True, timeout=20)
    check('CONVERGE_KEY' not in r.stderr and 'CONVERGE_TOKEN' not in r.stderr and 'gateway' not in r.stderr,
          'and no environment variable carries one')

    # --- 2. the opening frame -----------------------------------------------------------------------
    relay = FakeRelay()
    b = Bridge(relay.port, *identity, env=env)
    check(wait_for(lambda: relay.hellos), 'the bridge speaks first to the relay')
    check(opening(relay.hellos[0]),
          'and opens with a v4 client_hello: QSF, code 1000, protocol 4, no key, no identity, no signature')
    status = b.tool('converge_status')
    check(status.get('connected') is False and status.get('auth') != 'bearer',
          'a relay that cannot prove its key is not "connected", and nothing about the bridge is bearer')
    time.sleep(1.5)
    check(not relay.frames, 'the bridge sends nothing after its client_hello until the relay has proved its key')
    check(wait_for(lambda: len(relay.hellos) > 1, 20), 'it tries again, with a fresh client_hello')
    check(len(relay.hellos) > 1 and opening(relay.hellos[-1]) and relay.hellos[-1]['frame'] != relay.hellos[0]['frame'],
          'and a fresh one is a new ephemeral key and nonce, never the same frame twice')
    b.close()
    relay.close()

    # --- 3. a call without a relay ----------------------------------------------------------------
    dead = free_port()
    b = Bridge(dead, *identity, env=env)
    started = time.time()
    call = b.tool('converge_call', to='cvh_000000000002', wait_sec=3)
    took = time.time() - started
    check(call.get('ok') is False and call.get('relay_connected') is False
          and call.get('error') == 'relay unreachable: the call was not placed',
          'relay never reachable: "%s"' % call.get('error'))
    check(took < 8, 'and the call gave up within its own wait (%.1f s)' % took)
    late = FakeRelay(port=dead)
    check(wait_for(lambda: late.hellos, 40), 'the bridge reaches the relay once it is back, with a client_hello')
    time.sleep(1.5)
    check(not late.frames, 'and the refused call is not sent to it afterwards')
    b.close()
    late.close()

    relay = FakeRelay()
    b = Bridge(relay.port, *identity, env=env)
    wait_for(lambda: relay.hellos)
    started = time.time()
    call = b.tool('converge_call', to='cvh_000000000002', wait_sec=3)
    took = time.time() - started
    check(call.get('ok') is False and call.get('relay_connected') is False
          and call.get('error') == 'relay unreachable: the call was not placed',
          'a relay that accepts the socket but never proves its key is as good as none: "%s"' % call.get('error'))
    check(took < 8, 'and that call gave up within its own wait too (%.1f s)' % took)
    check(not relay.frames, 'nothing of the call went to a relay the bridge had not authenticated')
    b.close()
    relay.close()

    # --- 4. nothing else was tried ------------------------------------------------------------
    if os.name != 'nt':
        check(not tripped.exists(), 'no ssh, scp or sftp was run: there is no other route')

print('TRANSPORT TEST ' + ('OK' if ok else 'FAILED'))
sys.exit(0 if ok else 1)
