#!/usr/bin/env python3

# Checks that the presumed good areas of disk images match

# This script takes multiple disk image files, and loads their associated error
# log files that mark bad ranges. With the assumption that these image files
# are multiple reads of the same image, warns about any data in 'good' areas
# that differ between files.

import disklib.validity

import collections
import operator
import sys


# status dingbats
CHAR_NO_MAJORITY = "X"
CHAR_NOT_UNANIMOUS = "x"
SINGLE_SOURCE = "1"
NO_SOURCE = "-"


def compare_span(start, expected_size, buffers, indices):
	indexed_buffers = [ (i, buffers[i]) for i in indices ]
	for char_index in range(expected_size):
		char_to_indexset = collections.defaultdict(set)

		# map characters to the index of the stream that read them
		# if they all agree the resultant dict will have a single key
		for i, buf in indexed_buffers:
			char = buf[char_index:char_index + 1]
			char_to_indexset[char].add(i)

		# if not, there was a disagreement
		if len(char_to_indexset) > 1:
			# sort by length of set, descending. this means the character that
			# was read the most occurs first
			by_votes = sorted(
				char_to_indexset.items(), key=lambda p: len(p[1]), reverse=True
			)

			# is there a clear winner? the first set should have more members
			# than the next
			if len(by_votes[0][1]) > len(by_votes[1][1]):
				# there is, but it wasn't unanimous
				statchar = CHAR_NOT_UNANIMOUS
			else:
				# nobody knows. mark with a ?
				statchar = CHAR_NO_MAJORITY

			print("{0} {1:#010x}".format(statchar, start + char_index), end=' ')
			for char, indexset in by_votes:
				if char == "":
					print(" /", end=' ')
				else:
					print("{0:02x}".format(ord(char)), end=' ')
				print(repr(sorted(indexset)), end=' ')
			print()


ADDS = 0
REMOVES = 1
def check_good(streams_and_validity):
	streams = [ s for s, _ in streams_and_validity ]

	events_by_offset = collections.defaultdict(lambda: (set(), set()))
	for i, sv in enumerate(streams_and_validity):
		for good_start, good_end in sv[1].itergood():
			# an event occurs at <good_start> bytes which ADDS stream i
			# to the set of expected good streams
			events_by_offset[good_start][ADDS].add(i)
			# an event occurs at <good_end> bytes which REMOVES stream i
			# from the set of expected good streams
			events_by_offset[good_end][REMOVES].add(i)

	events = [
		(offset, sets[ADDS], sets[REMOVES]) for offset, sets in
		sorted(events_by_offset.items(), key=operator.itemgetter(0))
	]

	current_offset = 0
	currently_good_indices = set()
	for next_offset, adds, removes in events:
		if next_offset > current_offset:
			# advance all buffers, not just the good ones
			span_size = next_offset - current_offset
			buffers = [ s.read(span_size) for s in streams ]

			if max(len(b) for b in buffers) > 0:
				if len(currently_good_indices) == 0:
					print(NO_SOURCE, end=' ')
					print("{0:#010x}-{1:#010x}".format(
						current_offset, next_offset))

				elif len(currently_good_indices) == 1:
					print(SINGLE_SOURCE, end=' ')
					print("{0:#010x}-{1:#010x} ({2})".format(
						current_offset, next_offset, list(currently_good_indices)[0]))

				else:
					compare_span(current_offset, span_size, buffers, currently_good_indices)

		currently_good_indices.difference_update(removes)
		currently_good_indices.update(adds) # ADDS beat REMOVES, although these should never conflict
		current_offset = next_offset


def main():
	paths = sys.argv[1:]

	for i, path in enumerate(paths):
		print("{0:3} {1}".format(i, path))

	try:
		streams_and_validity = [
			(open(path, "rb"), disklib.validity.read_validity_for_file(path))
			for path in paths
		]
		check_good(streams_and_validity)

	finally:
		for stream, _ in streams_and_validity:
			stream.close()


if __name__ == '__main__':
	main()
