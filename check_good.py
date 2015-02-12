#!/usr/local/bin/python

# Checks that the presumed good areas of disk images match

# This script takes multiple disk image files, and loads their associated error
# log files that mark bad ranges. With the assumption that these image files
# are multiple reads of the same image, warns about any data in 'good' areas
# that differ between files.

import collections
import operator
import sys

import validity


def compare_span(start, expected_size, buffers, indices):
	indexed_buffers = [ (i, buffers[i]) for i in indices ]
	for char_index in xrange(expected_size):
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
				char_to_indexset.iteritems(), key=lambda p: len(p[1]), reverse=True
			)

			# is there a clear winner? the first set should have more members
			# than the next
			if len(by_votes[0][1]) > len(by_votes[1][1]):
				# there is, but it wasn't unanimous
				statchar = "~"
			else:
				# nobody knows. mark with an x
				statchar = "x"

			print "{0} 0x{1:08X}".format(statchar, start + char_index),
			for char, indexset in by_votes:
				if char == "":
					print " /",
				else:
					print "{0:02X}".format(ord(char)),
				print repr(sorted(indexset)),
			print


ADDS = 0
REMOVES = 1
def check_good(streams_and_validity):
	streams = [ s for s, _ in streams_and_validity ]

	events_by_offset = collections.defaultdict(lambda: (set(), set()))
	for i, sb in enumerate(streams_and_validity):
		for good_start, good_end in sb[1]:
			# an event occurs at <good_start> bytes which ADDS stream i
			# to the set of expected good streams
			events_by_offset[good_start][ADDS].add(i)
			# an event occurs at <good_end> bytes which REMOVES stream i
			# to the set of expected good streams
			events_by_offset[good_end][REMOVES].add(i)

	events = [
		(offset, sets[ADDS], sets[REMOVES]) for offset, sets in
		sorted(events_by_offset.iteritems(), key=operator.itemgetter(0))
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
					print "- 0x{0:08X}-0x{1:08X}".format(
						current_offset, next_offset)

				elif len(currently_good_indices) == 1:
					print "1 0x{0:08X}-0x{1:08X} ({2})".format(
						current_offset, next_offset, list(currently_good_indices)[0])

				else:
					compare_span(current_offset, span_size, buffers, currently_good_indices)

		currently_good_indices.difference_update(removes)
		currently_good_indices.update(adds) # ADDS beat REMOVES, although these should never conflict
		current_offset = next_offset


def main():
	paths = sys.argv[1:]

	for i, path in enumerate(paths):
		print "{0:3} {1!s}".format(i, path)

	try:
		streams_and_validity = [
			(open(path, "rb"), validity.read_validity_for_file(path))
			for path in paths
		]
		check_good(streams_and_validity)

	finally:
		for stream, _ in streams_and_validity:
			stream.close()


if __name__ == '__main__':
	main()
