
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

    def reply_callback(self, request, reply):
        for mod in self.modules:
            if callable(getattr(mod, 'reply_callback', None)):
                reply = mod.reply_callback(request, reply)
        return reply

HttpReplayRules = HttpReplayRulesClass()

