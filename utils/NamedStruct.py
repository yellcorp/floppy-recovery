import struct


_ENDIAN_TO_GLYPH = dict(native='=', little='<', big='>')


class NamedStruct(object):
    @classmethod
    def struct_string(cls):
        return _ENDIAN_TO_GLYPH.get(cls.endian, "=") + \
            ''.join(p[0] for p in cls.fields)

    @classmethod
    def packer(cls):
        if not hasattr(cls, "_packer"):
            cls._packer = struct.Struct(cls.struct_string())
        return cls._packer

    @classmethod
    def size(cls):
        return cls.packer().size

    @classmethod
    def from_stream(cls, stream):
        return cls(stream.read(cls.size()))

    def __init__(self, bindata=None):
        if bindata is None:
            bindata = "\0" * self.__class__.size()
        self.unpack(bindata)

    def unpack(self, bindata):
        values = self.__class__.packer().unpack(bindata)
        for f, v in zip(self.__class__.fields, values):
            setattr(self, f[1], v)

    def pack(self):
        values = [ getattr(self, f[1]) for f in self.__class__.fields ]
        return self.__class__.packer().pack(*values)
