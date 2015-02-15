#!/usr/local/bin/python

import sys

import disklib.validity


if __name__ == '__main__':
	for start, end in disklib.validity.read_validity_for_file(sys.argv[1]).itergood():
		print "+ 0x{0:08X} 0x{1:08X}".format(start, end)
