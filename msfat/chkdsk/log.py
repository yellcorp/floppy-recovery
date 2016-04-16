import re
import string


# Log levels match values of equivalent severity in python logging module
# Short names privately...
_INVALID = 40
_UNCOMMON = 30
_INFO = 20

# ...long names publicly
CHKDSK_LOG_INVALID = _INVALID
CHKDSK_LOG_UNCOMMON = _UNCOMMON
CHKDSK_LOG_INFO = _INFO


class _BaseLogger(object):
    def __init__(self, next_log_func):
        self._next_log_func = next_log_func

    def log(self, level, *args, **kwargs):
        self._next_log_func(level, *args, **kwargs)

    def info(self, *args, **kwargs):
        self.log(_INFO, *args, **kwargs)

    def uncommon(self, *args, **kwargs):
        self.log(_UNCOMMON, *args, **kwargs)

    def invalid(self, *args, **kwargs):
        self.log(_INVALID, *args, **kwargs)


class _UserFunctionLogger(_BaseLogger):
    def __init__(self, user_log_func, formatter=None):
        _BaseLogger.__init__(self, user_log_func)
        self._formatter = formatter or string.Formatter()

    def log(self, level, template, *args, **kwargs):
        message = self._formatter.vformat(template, args, kwargs)
        self._next_log_func(level, re.sub("[\r\n\t]+", " ", message.strip()))


class _DefaultArgsLogger(_BaseLogger):
    def __init__(self, next_log_func, **kwargs):
        _BaseLogger.__init__(self, next_log_func)
        self._default_format_dict = kwargs

    def log(self, level, template, *args, **kwargs):
        # slow but whatever
        if kwargs:
            format_dict = dict(self._default_format_dict, **kwargs)
        else:
            format_dict = self._default_format_dict

        _BaseLogger.log(self, level, template, *args, **format_dict)


class _PrefixLogger(_BaseLogger):
    @staticmethod
    def template_escape(s):
        return re.sub(r"[{}]", lambda m: m.group(0) * 2, s)

    def __init__(self, next_log_func, prefix):
        _BaseLogger.__init__(self, next_log_func)
        self.prefix = prefix
        self._escaped_prefix = self.template_escape(prefix)

    def log(self, level, template, *args, **kwargs):
        _BaseLogger.log(self, level, self._escaped_prefix + template, *args, **kwargs)

    def extend(self, prefix_extra):
        return _PrefixLogger(self._next_log_func, self.prefix + prefix_extra)
