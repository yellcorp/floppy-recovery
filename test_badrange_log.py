#!/usr/local/bin/python

import sys

import badranges


if __name__ == '__main__':
	for start, size in badranges.read_badranges_for_file(sys.argv[1]):
		print "0x{0:08X}  0x{1:08X}".format(start, size)
