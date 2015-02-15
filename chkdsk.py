#!/usr/local/bin/python

import sys

import disklib.mediageom
import disklib.msfat
import disklib.validity


LOGLEVEL_TO_PREFIX = {
	disklib.msfat.CHKDSK_LOG_INVALID:  u'\u274c  ', # cross
	disklib.msfat.CHKDSK_LOG_UNCOMMON: u'\u26a0\ufe0f  ', # warning sign with emoji variant suffix
	disklib.msfat.CHKDSK_LOG_INFO:     "\xF0\x9F\x92\xAC  " # UTF8 for speech balloon U+1F4AC
}


def main():
	path = sys.argv[1]
	validity = disklib.validity.read_validity_for_file(path)
	stream = open(path, "rb")
	geometry = disklib.mediageom.DiskGeometry.from_image_size(validity.domain)

	volume = disklib.msfat.FATVolume(stream, geometry)
	for level, message in volume.chkdsk():
		print LOGLEVEL_TO_PREFIX.get(level, "") + message

	stream.close()


if __name__ == '__main__':
	main()
