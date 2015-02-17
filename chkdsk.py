#!/usr/local/bin/python

import sys

import disklib.mediageom
import msfat.chkdsk
import msfat.volume
import disklib.validity


LOGLEVEL_TO_PREFIX = {
	msfat.chkdsk.CHKDSK_LOG_INVALID:  u'\u274c  ', # cross
	msfat.chkdsk.CHKDSK_LOG_UNCOMMON: u'\u26a0\ufe0f  ', # warning sign with emoji variant suffix
	msfat.chkdsk.CHKDSK_LOG_INFO:     "\xF0\x9F\x92\xAC  " # UTF8 for speech balloon U+1F4AC
}


def main():
	prog_errs = [ ]

	for path in sys.argv[1:]:
		print path

		try:
			validity = disklib.validity.read_validity_for_file(path)
			stream = open(path, "rb")
			geometry = disklib.mediageom.DiskGeometry.from_image_size(validity.domain)

			volume = msfat.volume.FATVolume(stream, geometry)
			for level, message in volume.chkdsk():
				print LOGLEVEL_TO_PREFIX.get(level, "") + message

			stream.close()
		except Exception as e:
			print u"{0}Program error: {1}".format(
				LOGLEVEL_TO_PREFIX[msfat.chkdsk.CHKDSK_LOG_INVALID], e)
			prog_errs.append((path, e))
		print ""

	if prog_errs:
		print "Program errors ({0}):".format(len(prog_errs))
		for path, e in prog_errs:
			print u"{0}: {1!s}".format(path, e)


if __name__ == '__main__':
	main()
