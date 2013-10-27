from twisted.internet import protocol, reactor, defer
from twisted.web.client import getPage, HTTPClientFactory
HTTPClientFactory.noisy = False

from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import AES

import struct
import hashlib
import base64
import json

# Protocol modes
PROTOCOL_INIT = 0
PROTOCOL_STATUS = 1
PROTOCOL_LOGIN = 2


class BufferUnderrun(Exception):
    pass


class Buffer(object):
    def __init__(self):
        self.buff1 = ""
        self.buff2 = ""

    def length(self):
        return len(self.buff1)

    def add(self, d):
        self.buff1 += d

    def save(self):
        self.buff2 = self.buff1

    def restore(self):
        self.buff1 = self.buff2

    def unpack_raw(self, l):
        if len(self.buff1) < l:
            raise BufferUnderrun()
        d, self.buff1 = self.buff1[:l], self.buff1[l:]
        return d

    def unpack(self, ty):
        s = struct.unpack(">"+ty, self.unpack_raw(struct.calcsize(ty)))
        return s[0] if len(ty) == 1 else s

    def unpack_string(self):
        l = self.unpack_varint()
        return self.unpack_raw(l).decode("utf-8")

    def unpack_array(self):
        l = self.unpack("h")
        return self.unpack_raw(l)

    def unpack_varint(self):
        d = 0
        for i in range(5):
            b = self.unpack('B')
            d |= (b & 0x7F) << 7*i
            if not b & 0x80:
                break
        return d

    @classmethod
    def pack(cls, ty, *data):
        return struct.pack(">"+ty, *data)

    @classmethod
    def pack_string(cls, data):
        data = data.encode('utf-8')
        return cls.pack_varint(len(data)) + data

    @classmethod
    def pack_array(cls, data):
        return cls.pack("h", len(data)) + data

    @classmethod
    def pack_varint(cls, d):
        o = ""
        while True:
            b = d & 0x7F
            d >>= 7
            o += cls.pack('B', b | (0x80 if d > 0 else 0))
            if d == 0:
                break
        return o


# Authentication
class AuthTools:
    @classmethod
    def make_keypair(cls):
        return RSA.generate(1024)

    @classmethod
    def make_server_id(cls):
        return "".join("%02x" % ord(c) for c in Random.get_random_bytes(10))

    @classmethod
    def make_verify_token(cls):
        return Random.get_random_bytes(4)

    @classmethod
    def make_digest(cls, *data):
        sha1 = hashlib.sha1()
        for d in data: sha1.update(d)

        digest = long(sha1.hexdigest(), 16)
        if digest >> 39*4 & 0x8:
            return"-%x" % ((-digest) & (2**(40*4)-1))
        else:
            return "%x" % digest

    @classmethod
    def export_public_key(cls, keypair):
        return keypair.publickey().exportKey(format="DER")

    @classmethod
    def decrypt(cls, keypair, data):
        data = keypair.decrypt(data)
        #remove pkcs1
        pos = data.find('\x00')
        if pos > 0:
            data = data[pos+1:]

        return data

    @classmethod
    def get_cipher(cls, key):
        return AES.new(key, AES.MODE_CFB, key).encrypt


class ProtocolError(Exception):
    @classmethod
    def mode_mismatch(cls, ident, mode):
        return cls("Unexpected packet; ID: {0}; Mode: {1}".format(ident, mode))
    @classmethod
    def step_mismatch(cls, ident, step):
        return cls("Unexpected packet; ID: {0}; Step: {1}".format(ident, step))


# Protocol logic
class AuthProtocol(protocol.Protocol):
    protocol_mode = PROTOCOL_INIT
    protocol_version = 0
    login_step = 0
    def __init__(self, factory, addr):
        self.factory = factory
        self.client_addr = addr.host
        self.buff = Buffer()
        self.cipher = lambda d: d

        self.server_id    = AuthTools.make_server_id()
        self.verify_token = AuthTools.make_verify_token()

        self.timeout = reactor.callLater(self.factory.player_timeout, self.kick, "Took too long to log in")

    def dataReceived(self, data):
        self.buff.add(data)
        while True:
            try:
                packet_length = self.buff.unpack_varint()
                packet_body = self.buff.unpack_raw(packet_length)
                try:
                    self.packet_received(packet_body)
                except ProtocolError as e:
                    print "Protocol error:", e
                    self.kick("Protocol error")
                    break
                self.buff.save()
            except BufferUnderrun:
                break

    def packet_received(self, data):
        buff = Buffer()
        buff.add(data)
        try:
            ident = buff.unpack("B")

            if self.protocol_mode == PROTOCOL_INIT:
                if ident == 0: #recv handshake
                    self.protocol_version = buff.unpack_varint()
                    self.server_addr = buff.unpack_string()
                    self.server_port = buff.unpack('H')
                    self.protocol_mode = buff.unpack_varint()
                else:
                    raise ProtocolError.mode_mismatch(ident, self.protocol_mode)

            elif self.protocol_mode == PROTOCOL_STATUS:
                if ident == 0: #recv status request
                    #send status response
                    self.send_packet(0, Buffer.pack_string(json.dumps(self.factory.get_status(self.protocol_version))))
                elif ident == 1: #recv ping
                    time = buff.unpack('Q')
                    #send ping
                    self.send_packet(1, Buffer.pack('Q', time))
                    self.close()
                else:
                    raise ProtocolError.mode_mismatch(ident, self.protocol_mode)

            elif self.protocol_mode == PROTOCOL_LOGIN:
                if ident == 0: #recv login start
                    if self.login_step != 0:
                        raise ProtocolError.step_mismatch(ident, self.login_step)
                    self.login_step = 1

                    self.username = buff.unpack_string()

                    #send encryption request
                    self.send_packet(1,
                        Buffer.pack_string(self.server_id) +
                        Buffer.pack_array(self.factory.public_key) +
                        Buffer.pack_array(self.verify_token))
                elif ident == 1: # recv encryption response
                    if self.login_step != 1:
                        raise ProtocolError.step_mismatch(ident, self.login_step)
                    self.login_step = 2

                    shared_secret = AuthTools.decrypt(self.factory.keypair, buff.unpack_array())
                    verify_token  = AuthTools.decrypt(self.factory.keypair, buff.unpack_array())
                    if verify_token != self.verify_token:
                        raise ProtocolError("Verify token incorrect")

                    #enable encryption
                    self.cipher = AuthTools.get_cipher(shared_secret)

                    #set up auth handlers
                    def auth_worked(authed):
                        d = defer.maybeDeferred(self.factory.handle_auth,
                            self.client_addr,
                            self.server_addr,
                            self.username,
                            authed)
                        d.addCallback(self.kick)

                    def auth_ok(data):
                        auth_worked(True)

                    def auth_err(e):
                        if e.value.status == "204":
                            auth_worked(False)
                        else:
                            self.kick("Couldn't contact session server")

                    #do auth!
                    digest = AuthTools.make_digest(self.server_id, shared_secret, self.factory.public_key)
                    d = getPage(
                        "https://sessionserver.mojang.com/session/minecraft/hasJoined?username={username}&serverId={serverId}".format(
                            username = self.username,
                            serverId = digest),
                        timeout = self.factory.auth_timeout)
                    d.addCallbacks(auth_ok, auth_err)
                else:
                    raise ProtocolError.mode_mismatch(ident, self.protocol_mode)
            else:
                raise ProtocolError.mode_mismatch(ident, self.protocol_mode)

        except BufferUnderrun:
            raise ProtocolError("Packet is too short!")

        if buff.length() > 0:
            raise ProtocolError("Packet is too long!")

    def send_packet(self, ident, data):
        data = Buffer.pack_varint(ident) + data
        data = Buffer.pack_varint(len(data)) + data
        data = self.cipher(data)
        self.transport.write(data)

    def close(self):
        if self.timeout.active():
            self.timeout.cancel()
        self.transport.loseConnection()

    def kick(self, message):
        self.send_packet(0, Buffer.pack_string(json.dumps({'text': message})))
        self.close()


class AuthServer(protocol.Factory):
    noisy = False
    def __init__(self, motd="Auth Server", favicon=None, auth_timeout=30, player_timeout=30):
        self.auth_timeout = auth_timeout
        self.player_timeout = player_timeout

        self.keypair = AuthTools.make_keypair()
        self.public_key = AuthTools.export_public_key(self.keypair)

        self.status = {
            "description": motd,
            "players": {"max": 20, "online": 0},
            "version": {"name": "", "protocol": 0}
        }

        if favicon:
            with open(favicon, "rb") as f:
                self.status['favicon'] = "data:image/png;base64," + base64.encodestring(f.read())

    def listen(self, interface, port, backlog=50):
        reactor.listenTCP(port, self, backlog=backlog, interface=interface)

    def run(self):
        reactor.run()

    def buildProtocol(self, addr):
        return AuthProtocol(self, addr)

    def get_status(self, protocol_version):
        d = dict(self.status)
        d['version']['protocol'] = protocol_version
        return d

    def handle_auth(self, client_addr, server_addr, username, authed):
        raise NotImplementedError