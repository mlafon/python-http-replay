
import logging

class HttpReplayLogClass:
    def __init__(self):
        self.log = logging.getLogger('http_replay')

    def debug(self, dbg):
        self.log.debug(dbg)

    def warning(self, dbg):
        self.log.warn(dbg)

    def info(self, dbg):
        self.log.info(dbg)

HttpReplayLog = HttpReplayLogClass()

