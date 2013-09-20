# -*- coding: utf-8 -*-

from authserver import AuthServer

HOST = ""
PORT = 25565
MOTD = u"§eExample Auth Server"

class ExampleAuthServer(AuthServer):
    def handle_auth(self, client_addr, server_addr, username, authed):
        print "%s/%s logged in" % (username, client_addr)

        if authed:
            print " --> OK!"

            # Do some logic here, e.g. update a DB or make a HTTP call

            return u"§lThanks! §rPlease check your web browser."

        else:
            print " --> FAILED!"
            return u"§4Couldn't authenticate you!"


if __name__ == "__main__":
    server = ExampleAuthServer(MOTD)
    server.listen(HOST, PORT)
    server.run()