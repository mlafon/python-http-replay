
from SocketServer import TCPServer, BaseRequestHandler
import dpkt

DONOTLOG_EXT = None
#DONOTLOG_EXT = ('gif', 'png', 'jpg', 'jpeg', 'css', 'js')

class HttpReplayHandler(BaseRequestHandler):
    def __init__(self, request, hp, server):
        self.srv = server
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
        print('%s - %s %s (%d)' % \
            (rep.status, req.method, req.uri, len(rep.body)))

    def recv_request(self):
        req = ''
        while True:
            r = self.request.recv(512)
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
        if not reply:
            reply = dpkt.http.Response(status='404', reason='Not found')
            reply.body = '<html><body><h1>Not found</h1></body></html>'
        return reply

    def handle(self):
        request = self.recv_request()
        if request:
            reply = self.find_reply(request)
            self.dumplog(request, reply)
            self.request.send(str(reply))

class HttpReplayServer(TCPServer):
    allow_reuse_address = True

    def __init__(self, host='127.0.0.1', port=3128, db=None):
        TCPServer.__init__(self, (host, port), HttpReplayHandler)
        self.hp = (host, port)
        self.db = db

    def start(self):
        print('Listening for HTTP requests on %s:%u...' % self.hp)
        self.serve_forever()

