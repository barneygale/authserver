from twisted.internet import protocol, reactor, defer
from twisted.web.client import getPage, HTTPClientFactory
HTTPClientFactory.noisy = False

import struct
import M2Crypto
import hashlib
import base64
import json

# Protocol modes
PROTOCOL_INIT = 0
PROTOCOL_STATUS = 1
PROTOCOL_LOGIN = 2

class Crypto:
    @classmethod
    def make_keypair(cls):
        return M2Crypto.RSA.gen_key(1024, 257, callback=lambda *a: None)

    @classmethod
    def make_server_id(cls):
        return "".join("%02x" % ord(c) for c in M2Crypto.Rand.rand_bytes(10))

    @classmethod
    def make_verify_token(cls):
        return M2Crypto.Rand.rand_bytes(4)

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
        pem_start = "-----BEGIN PUBLIC KEY-----"
        pem_end = "-----END PUBLIC KEY-----"

        #First extract a PEM file
        bio = M2Crypto.BIO.MemoryBuffer("")
        keypair.save_pub_key_bio(bio)
        d = bio.getvalue()

        #Get just the key data
        s = d.find(pem_start)
        e = d.find(pem_end)
        assert s != -1 and e != -1
        out = d[s+len(pem_start):e]

        #Decode
        return base64.decodestring(out)

    @classmethod
    def decrypt(cls, keypair, data):
        return keypair.private_decrypt(data, M2Crypto.m2.pkcs1_padding)


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

class NOOPCipher:
    def update(self, d):
        return d
    def final(self):
        return ""

class AESCipher(M2Crypto.EVP.Cipher):
    def __init__(self, key):
        M2Crypto.EVP.Cipher.__init__(self, 'aes_128_cfb', key, key, 1)


class ProtocolError(Exception):
    @classmethod
    def mode_mismatch(cls, ident, mode):
        return cls("Unexpected packet; ID: {0}; Mode: {1}".format(ident, mode))
    @classmethod
    def step_mismatch(cls, ident, step):
        return cls("Unexpected packet; ID: {0}; Step: {1}".format(ident, step))


class AuthProtocol(protocol.Protocol):
    protocol_mode = PROTOCOL_INIT
    protocol_version = 0
    login_step = 0
    def __init__(self, factory, addr):
        self.factory = factory
        self.client_addr = addr.host
        self.buff = Buffer()
        self.cipher = NOOPCipher()

        self.server_id    = Crypto.make_server_id()
        self.verify_token = Crypto.make_verify_token()

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
                    print "Protocol error: ", e
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
                    print "<-- handshake"
                    self.protocol_version = buff.unpack_varint()
                    self.server_addr = buff.unpack_string()
                    self.server_port = buff.unpack('H')
                    self.protocol_mode = buff.unpack_varint()
                else:
                    raise ProtocolError.mode_mismatch(ident, self.protocol_mode)

            elif self.protocol_mode == PROTOCOL_STATUS:
                if ident == 0: #recv status request
                    print "<-- status request"
                    #send status response
                    print "--> status response"
                    self.send_packet(0, Buffer.pack_string(json.dumps(self.factory.get_status(self.protocol_version))))

                elif ident == 1: #recv ping
                    print "<-- ping"
                    time = buff.unpack('Q')
                    #send ping
                    print "--> ping"
                    self.send_packet(1, Buffer.pack('Q', time))
                    self.close()
                else:
                    raise ProtocolError.mode_mismatch(ident, self.protocol_mode)

            elif self.protocol_mode == PROTOCOL_LOGIN:
                if ident == 0: #recv login start
                    print "<-- login start"
                    if self.login_step != 0:
                        raise ProtocolError.step_mismatch(ident, self.login_step)

                    self.username = buff.unpack_string()
                    self.login_step = 1

                    #send encryption request
                    print "--> encryption request"
                    self.send_packet(1,
                        Buffer.pack_string(self.server_id) +
                        Buffer.pack_array(self.factory.public_key) +
                        Buffer.pack_array(self.verify_token))
                elif ident == 1: # recv encryption response
                    print "<-- encryption response"
                    if self.login_step != 1:
                        raise ProtocolError.step_mismatch(ident, self.login_step)

                    shared_secret = Crypto.decrypt(self.factory.keypair, buff.unpack_array())
                    verify_token  = Crypto.decrypt(self.factory.keypair, buff.unpack_array())
                    if verify_token != self.verify_token:
                        raise ProtocolError("Verify token incorrect")

                    #enable encryption
                    self.cipher = AESCipher(shared_secret)

                    #do auth
                    digest = Crypto.make_digest(self.server_id, shared_secret, self.factory.public_key)
                    d = getPage(
                        "https://sessionserver.mojang.com/session/minecraft/hasJoined?username={username}&serverId={serverId}".format(
                            username = self.username,
                            serverId = digest),
                        timeout = self.factory.auth_timeout)
                    d.addCallbacks(self.auth_ok, self.auth_err)
                else:
                    raise ProtocolError.mode_mismatch(ident, self.protocol_mode)
            else:
                raise ProtocolError.mode_mismatch(ident, self.protocol_mode)

        except BufferUnderrun:
            raise ProtocolError("Packet is too short!")

        if buff.length() > 0:
            raise ProtocolError("Packet is too long!")

    def auth_ok(self, data):
        data = json.loads(data)
        print "AUTH OK"
        self.kick("This kick should work")

    def auth_err(self, err):
        print "AUTH ERR", err

    def send_packet(self, ident, data):
        data = Buffer.pack_varint(ident) + data
        data = Buffer.pack_varint(len(data)) + data
        data = self.cipher.update(data)
        self.transport.write(data)

    def close(self):
        if self.timeout.active():
            self.timeout.cancel()
        self.transport.write(self.cipher.final())
        self.transport.loseConnection()

    def kick(self, message):
        print "--> kick"
        self.send_packet(0, Buffer.pack_string(json.dumps({'text': message})))
        self.close()


class AuthServer(protocol.Factory):
    noisy = False
    def __init__(self, motd="Auth Server", favicon = None, auth_timeout=30, player_timeout=30):
        self.motd = motd
        self.favicon = favicon

        self.auth_timeout = auth_timeout
        self.player_timeout = player_timeout

        self.keypair = Crypto.make_keypair()
        self.public_key = Crypto.export_public_key(self.keypair)

        if self.favicon:
            with open(self.favicon, "rb") as f:
                self.favicon = "data:image/png;base64," + base64.encodestring(f.read())

    def listen(self, interface, port, backlog=50):
        reactor.listenTCP(port, self, backlog=backlog, interface=interface)

    def run(self):
        reactor.run()

    def buildProtocol(self, addr):
        return AuthProtocol(self, addr)

    def get_status(self, protocol_version):
        d = {
            "description": self.motd,
            "players": {"max": 20, "online": 0},
            "version": {"name": "", "protocol": protocol_version}
        }
        if self.favicon:
            d["favicon"] = self.favicon
        return d

    def handle_auth(self, client_addr, server_addr, username, authed):
        raise NotImplementedError