#!/usr/local/bin/python

import sys

import disklib.mediageom
import disklib.msfat
import disklib.validity


def main():
	path = sys.argv[1]
	validity = disklib.validity.read_validity_for_file(path)
	stream = open(path, "rb")
	geometry = disklib.mediageom.DiskGeometry.from_image_size(validity.domain)

	volume = disklib.msfat.FATVolume(stream, geometry)
	for message in volume.chkdsk():
		print message

	stream.close()


if __name__ == '__main__':
	main()
