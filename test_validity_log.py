#!/usr/bin/env python3

import sys

import disklib.validity


if __name__ == '__main__':
    for start, end in disklib.validity.read_validity_for_file(sys.argv[1]).itergood():
        print("+ {0:#010x} {1:#010x}".format(start, end))
