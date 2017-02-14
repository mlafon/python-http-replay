
import imp, os

class HttpReplayRulesClass:
    def __init__(self):
        self.modules = []

    def add_module(self, path):
        if not os.path.isdir(path):
            raise Exception('%s is not a directory' % path)
        initpath = os.path.join(path, '__init__.py')
        if not os.path.exists(initpath):
            raise Exception('%s does not exist' % initpath)
        mod = imp.load_source(os.path.basename(path), initpath)
        self.modules.append(mod)

    def static_files(self):
        st = []
        for mod in self.modules:
            if not hasattr(mod, 'STATIC_FILES'):
                continue
            for url, path in mod.STATIC_FILES:
                if not os.path.isabs(path):
                    path = os.path.join(os.path.dirname(mod.__file__), path)
                st.append((url, path))
        return st

    def redirect_rules(self):
        redir = []
        for mod in self.modules:
            if not hasattr(mod, 'REDIRECTS'):
                continue
            for url1, url2 in mod.REDIRECTS:
                redir.append((url1, url2))
        return redir

    def request_callback(self, request):
        for mod in self.modules:
            if callable(getattr(mod, 'request_callback', None)):
                request = mod.request_callback(request)
        return request

    def reply_callback(self, request, reply):
        for mod in self.modules:
            if callable(getattr(mod, 'reply_callback', None)):
                reply = mod.reply_callback(request, reply)
        return reply

    def choose_reply(self, request, lst):
        for mod in self.modules:
            if callable(getattr(mod, 'choose_reply', None)):
                return mod.choose_reply(request, lst)
        print 'Warning: %d req/rep found for %s, using first' % (len(lst), request.uri)
        return lst[0][1]

HttpReplayRules = HttpReplayRulesClass()

