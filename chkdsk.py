#!/usr/local/bin/python

import os.path
import sys

import disklib.mediageom
import disklib.validity
import msfat.chkdsk
import msfat.volume


LOGLEVEL_TO_PREFIX = {
	msfat.chkdsk.CHKDSK_LOG_INVALID:  u'X ',
	msfat.chkdsk.CHKDSK_LOG_UNCOMMON: u'! ',
	msfat.chkdsk.CHKDSK_LOG_INFO:     u'i ' 
}


def log(level, message):
	print LOGLEVEL_TO_PREFIX[level] + message


def main():
	prog_errs = [ ]

	for path in sys.argv[1:]:
		print path

		try:
			validity = disklib.validity.read_validity_for_file(path)
			stream = open(path, "rb")
			geometry = disklib.mediageom.DiskGeometry.from_image_size(validity.domain)

			volume = msfat.volume.FATVolume(stream, geometry)
			volume.chkdsk(log)

			stream.close()
		except Exception as e:
			log(
				msfat.chkdsk.CHKDSK_LOG_INVALID,
				"Program error: {0!s}".format(e)
			)
			prog_errs.append((path, e))
		print ""

	if prog_errs:
		print "Program errors ({0}):".format(len(prog_errs))
		for path, e in prog_errs:
			print u"{0}: {1!s}".format(path, e)


if __name__ == '__main__':
	main()
