
import logging, string

class HttpReplayLogClass:
    def __init__(self):
        self.log = logging.getLogger('http_replay')

    def debug(self, dbg):
        self.log.debug(dbg)

    def warning(self, dbg):
        self.log.warn(dbg)

    def info(self, dbg):
        self.log.info(dbg)

    def request(self, req, rep, loading=False):
        log = '%s - %s %s' % (rep.status, req.method, req.uri)
        if len(rep.body) > 0:
            log += ' (%d)' % len(rep.body)
        if hasattr(rep, 'rawid'):
            log += ' {%s}' % rep.rawid
        if not loading and rep.status == '404' and req.method == 'POST':
            body = req.body
            if len(body) > 64:
                body = body[:64] + '...'
            body = ''.join([c if (c in string.printable) else '.' for c in body])
            log += '\n  [%s] (%d)' % (body, len(req.body))
        print log

HttpReplayLog = HttpReplayLogClass()

