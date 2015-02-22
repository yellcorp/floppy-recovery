TYPE_FAT12 = "FAT12"
TYPE_FAT16 = "FAT16"
TYPE_FAT32 = "FAT32"


ATTR_READ_ONLY =      0x01
ATTR_HIDDEN =         0x02
ATTR_SYSTEM =         0x04
ATTR_VOLUME_ID =      0x08
ATTR_DIRECTORY =      0x10
ATTR_ARCHIVE =        0x20
ATTR_LONG_NAME =      ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID
ATTR_LONG_NAME_MASK = ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID | ATTR_DIRECTORY | ATTR_ARCHIVE
ATTR_RESERVED_MASK =  0xC0


def _inline_hexdump(thing):
	if isinstance(thing, basestring):
		iterable = (ord(c) for c in thing)
	else:
		iterable = thing
	return " ".join("{0:02X}".format(n) for n in iterable)


def _bytes_to_str(byte_iter):
	return str(bytearray(byte_iter))
