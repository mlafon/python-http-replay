
from SocketServer import TCPServer, BaseRequestHandler
import dpkt, ssl, os, hashlib, OpenSSL

from .rules import HttpReplayRules
from .log import HttpReplayLog

DONOTLOG_EXT = None
#DONOTLOG_EXT = ('gif', 'png', 'jpg', 'jpeg', 'css', 'js')

class HttpReplayHandler(BaseRequestHandler):
    def __init__(self, request, hp, server):
        self.srv = server
        self.socket = request
        self.sslsk = None
        BaseRequestHandler.__init__(self, request, hp, server)

    def dumplog(self, req, rep):
        if DONOTLOG_EXT:
            uri = req.uri
            if '?' in uri:
                uri = uri[:uri.index('?')]
            if '.' in uri:
                ext = uri[uri.rindex('.')+1:]
                if ext.lower() in DONOTLOG_EXT:
                    return
        HttpReplayLog.request(req, rep)

    def recv_request(self):
        req = ''
        while True:
            r = self.socket.recv(512)
            if not r:
                return None
            req += r
            try:
                request = dpkt.http.Request(req)
            except dpkt.NeedData:
                continue
            except dpkt.UnpackError:
                continue
            break
        return request

    def find_reply(self, request):
        reply = None
        if self.srv.db:
            reply = self.srv.db.response_for(request)
            if reply:
                reply = HttpReplayRules.reply_callback(request, reply)
        if not reply:
            reply = dpkt.http.Response(status='404', reason='Not found')
            reply.body = '<html><body><h1>Not found</h1></body></html>'
        return reply

    def get_cert_for(self, host):
        if host in self.srv.certcache:
            return self.srv.certcache[host]

        cert, pkey, ca = self.srv.certstore.get_cert(host, ())
        cadir = os.path.dirname(self.srv.certstore.default_chain_file)
        certfile = os.path.join(cadir, '%s.pem' % hashlib.sha1(host).hexdigest())

        data  = '# Certificate for %s\n\n' % host
        data += cert.to_pem()
        data += OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey)

        open(certfile, 'w').write(data)
        self.srv.certcache[host] = certfile
        return certfile

    def recv_request_over_ssl(self, request):
        self.socket.send(str(dpkt.http.Response(status='200', reason='OK')))

        cert = self.get_cert_for(request.uri.split(':')[0])
        self.sslsk = ssl.wrap_socket(self.socket, keyfile=cert, certfile=cert,
            cert_reqs=ssl.CERT_NONE, server_side=True, do_handshake_on_connect=True)
        self.socket = self.sslsk

        req = self.recv_request()
        if req:
            newuri = 'https://%s' % request.uri
            if newuri.endswith(':443'):
                newuri = newuri[:-4]
            newuri += req.uri
            req.uri = newuri
        return req

    def handle(self):
        request = self.recv_request()
        if request and request.method == 'CONNECT' and self.srv.certstore:
            request = self.recv_request_over_ssl(request)

        if request:
            request = HttpReplayRules.request_callback(request)
            reply = self.find_reply(request)
            self.dumplog(request, reply)
            self.socket.send(str(reply))

class HttpReplayServer(TCPServer):
    allow_reuse_address = True

    def __init__(self, host='127.0.0.1', port=3128, db=None, certstore=None):
        TCPServer.__init__(self, (host, port), HttpReplayHandler)
        self.hp = (host, port)
        self.db = db
        self.certstore = certstore
        self.certcache = {}

    def start(self):
        print('Listening for HTTP requests on %s:%u...' % self.hp)
        self.serve_forever()

