from twisted.internet import protocol, reactor, defer
from twisted.web.client import getPage, HTTPClientFactory
HTTPClientFactory.noisy = False

import struct
import M2Crypto
import hashlib
import base64

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

    def empty(self):
        return len(self.buff1) == 0

    def add(self, d):
        self.buff1 += d
        self.buff2 = self.buff1

    def restore(self):
        self.buff1 = self.buff2

    def peek(self):
        if len(self.buff1) < 1:
            raise BufferUnderrun()
        return ord(self.buff1[0])

    def unpack_raw(self, l):
        if len(self.buff1) < l:
            raise BufferUnderrun()
        d, self.buff1 = self.buff1[:l], self.buff1[l:]
        return d

    def unpack(self, ty):
        s = struct.unpack(">"+ty, self.unpack_raw(struct.calcsize(ty)))
        return s[0] if len(ty) == 1 else s

    def unpack_string(self):
        l = self.unpack("h")
        return self.unpack_raw(l*2).decode("utf-16be")

    def unpack_array(self):
        l = self.unpack("h")
        return self.unpack_raw(l)

    @classmethod
    def pack(cls, ty, *data):
        return struct.pack(">"+ty, *data)

    @classmethod
    def pack_string(cls, data):
        return cls.pack("h", len(data)) + data.encode("utf-16be")

    @classmethod
    def pack_array(cls, data):
        return cls.pack("h", len(data)) + data


class AuthProtocol(protocol.Protocol):
    def __init__(self, factory, addr):
        self.factory = factory
        self.client_addr = addr.host
        self.buff = Buffer()

        self.server_id    = Crypto.make_server_id()
        self.verify_token = Crypto.make_verify_token()

        self.timeout = reactor.callLater(self.factory.player_timeout, self.kick, "E01: Took too long to log in")

    def dataReceived(self, data):
        self.buff.add(data)

        try:
            ident = self.buff.unpack("B")

            #Server List Ping
            if ident == 0xFE:
                self.buff.unpack("BB")    # 01 FA
                self.buff.unpack_string() # MC|PingHost
                self.buff.unpack("H")     # length of rest of data
                protocol_version = self.buff.unpack("B")
                self.buff.unpack_string() # server addr
                self.buff.unpack("I")     # server port

                #Send Kick
                self.kick(u"\u0000".join((
                    u"\u00a71",
                    str(protocol_version),
                    "0",
                    self.factory.motd,
                    "0",
                    "20")))

            #Handshake
            elif ident == 0x02:
                self.buff.unpack("B") #protocol version
                self.username = self.buff.unpack_string()
                self.server_addr = self.buff.unpack_string()
                self.buff.unpack("I") #port

                #Send Encryption Key Request
                self.transport.write(
                    "\xFD" +
                    Buffer.pack_string(self.server_id) +
                    Buffer.pack_array(self.factory.public_key) +
                    Buffer.pack_array(self.verify_token))

            #Excryption Key Response
            elif ident == 0xFC:
                shared_secret = Crypto.decrypt(self.factory.keypair, self.buff.unpack_array())
                verify_token  = Crypto.decrypt(self.factory.keypair, self.buff.unpack_array())

                if verify_token != self.verify_token:
                    return self.kick("E02 verify token incorrect")

                digest = Crypto.make_digest(self.server_id, shared_secret, self.factory.public_key)

                def auth_ok(data):
                    d = defer.maybeDeferred(self.factory.handle_auth,
                        self.client_addr,
                        self.server_addr,
                        self.username,
                        data=="YES")

                    d.addCallback(self.kick)

                def auth_err(e):
                    self.kick("E03 minecraft.net is down")

                d = getPage(
                    "http://session.minecraft.net/game/checkserver.jsp?user={user}&serverId={serverId}".format(
                        user = self.username,
                        serverId = digest),
                    timeout = self.factory.auth_timeout)
                d.addCallbacks(auth_ok, auth_err)

            else:
                self.kick("E04 protocol error")

        except BufferUnderrun:
            self.buff.restore()

    def kick(self, message):
        if self.timeout and self.timeout.active():
            self.timeout.cancel()

        self.transport.write("\xFF" + Buffer.pack_string(message))


class AuthServer(protocol.Factory):
    noisy = False
    def __init__(self, motd="Auth Server", auth_timeout=30, player_timeout=30):
        self.motd = motd
        self.auth_timeout = auth_timeout
        self.player_timeout = player_timeout

        self.keypair = Crypto.make_keypair()
        self.public_key = Crypto.export_public_key(self.keypair)

    def listen(self, interface, port, backlog=50):
        reactor.listenTCP(port, self, backlog=backlog, interface=interface)

    def run(self):
        reactor.run()

    def buildProtocol(self, addr):
        return AuthProtocol(self, addr)

    def handle_auth(self, client_addr, server_addr, username, authed):
        raise NotImplementedError