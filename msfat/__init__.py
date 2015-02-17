TYPE_FAT12 = "FAT12"
TYPE_FAT16 = "FAT16"
TYPE_FAT32 = "FAT32"


def _inline_hexdump(string):
	return " ".join("{0:02X}".format(ord(c)) for c in string)
