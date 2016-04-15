TYPE_FAT12 = b"FAT12"
TYPE_FAT16 = b"FAT16"
TYPE_FAT32 = b"FAT32"


ATTR_READ_ONLY =      0x01
ATTR_HIDDEN =         0x02
ATTR_SYSTEM =         0x04
ATTR_VOLUME_ID =      0x08
ATTR_DIRECTORY =      0x10
ATTR_ARCHIVE =        0x20
ATTR_LONG_NAME =      ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID
ATTR_LONG_NAME_MASK = ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID | ATTR_DIRECTORY | ATTR_ARCHIVE
ATTR_VALID_MASK =     ATTR_LONG_NAME_MASK
ATTR_RESERVED_MASK =  0xFF ^ ATTR_VALID_MASK


def _inline_hexdump(thing):
	return " ".join("{0:02X}".format(n) for n in iterable)


class MediaError(Exception):
	pass


class SeekError(MediaError):
	pass


class AllocationError(MediaError):
	pass
