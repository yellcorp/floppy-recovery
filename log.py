import codecs
import itertools
import json
import operator
import os
import re
import sys

from mediageom import DiskGeometry


_PREFIX_TO_ENCODING = (
	(codecs.BOM_UTF8,     "utf_8_sig"),
	(codecs.BOM_UTF16_BE, "utf_16"),
	(codecs.BOM_UTF16_LE, "utf_16"),
	(None,                "utf_8")
)
def _detect_open(path):
	with open(path, "rb") as bin_stream:
		leader = bin_stream.read(3)

	for prefix, encoding in _PREFIX_TO_ENCODING:
		if prefix is None or leader.startswith(prefix):
			return codecs.open(path, "rU", encoding)

	return None


_COMMON_SIZES = [ 737280, 1474560 ] # must be sorted ascending
def _minimum_common_size(s):
	if s == 0:
		return 0
	for cs in _COMMON_SIZES:
		if s <= cs:
			return cs
	raise ValueError("No common size that can acommodate an image of {0} bytes".format(s))


_WINIMAGE_ERROR = re.compile(
	r"^Disk error on track (?P<track>\d+), head (?P<head>\d+)" )
def _parse_winimage_error(geometry, text):
	match = _WINIMAGE_ERROR.match(text)
	if match:
		track, head = map(int, match.group("track", "head"))
		bad_start = geometry.chs_to_byte(track, head, 1)
		bad_len = geometry.sectors * geometry.sector_size
		return (bad_start, bad_len)
	return None


def _read_winimage_pasted(image_size, log_line_iter):
	expected_size = _minimum_common_size(image_size)
	geometry = DiskGeometry.from_image_size(expected_size)

	bad_ranges = set()
	for line in log_line_iter:
		bad_range = _parse_winimage_error(geometry, line)
		if bad_range is not None:
			bad_ranges.add(bad_range)

	return (expected_size, bad_ranges)


def _read_winimage_scripted(image_size, log_line_iter):
	expected_size = _minimum_common_size(image_size)
	geometry = DiskGeometry.from_image_size(expected_size)

	bad_ranges = [ ]
	for line in log_line_iter:
		enc_dialog, success_str, retries_str = line.split("\t")
		if success_str == "True":
			continue
		dialog_text = json.loads('"' + enc_dialog + '"')
		for dialog_line in re.split(r"[\n\r]+", dialog_text):
			bad_range = _parse_winimage_error(geometry, dialog_line)
			if bad_range is not None:
				bad_ranges.append(bad_range)

	return (expected_size, bad_ranges)


_FAUDD_EXPECT_SIZE = re.compile(
	r"^\tEstimated Total Size:\t(?P<size>\d+)")
_FAUDD_BAD_RANGE = re.compile(
	r"^File data in the range 0x(?P<start>[0-9A-Fa-f]+)-0x(?P<end>[0-9A-Fa-f]+) could not be read\.")
def _read_faudd_log(image_size, log_line_iter):
	expected_size = None
	bad_ranges = [ ]
	for line in log_line_iter:
		if expected_size is None:
			m = _FAUDD_EXPECT_SIZE.match(line)
			if m:
				expected_size = int(m.group("size"))

		m = _FAUDD_BAD_RANGE.match(line)
		if m:
			start, end = [ int(s, 16) for s in m.group("start", "end") ]
			bad_ranges.append((start, end - start))

	return (expected_size, bad_ranges)


_DDRESCUE_BLOCK = re.compile(
	r"^0x(?P<start>[0-9A-Fa-f]+)\s+0x(?P<size>[0-9A-Fa-f]+)\s+(?P<status>[?*/FG+-])")
def _read_ddrescue_log(image_size, log_line_iter):
	bad_ranges = [ ]
	seen_current_status = False

	for line in log_line_iter:
		if line.startswith("#"):
			continue

		if not seen_current_status:
			seen_current_status = True
			continue

		m = _DDRESCUE_BLOCK.match(line)
		if m:
			if m.group("status") != "+":
				start, size = [ int(s, 16) for s in m.group("start", "size") ]
				bad_ranges.append((start, size))

	return (image_size, bad_ranges)


_PREFIX_TO_READFUNC = (
	("-" * 20,                                    _read_winimage_pasted),
	("Forensic Acquisition Utilities,",           _read_faudd_log),
	("# Rescue Logfile. Created by GNU ddrescue", _read_ddrescue_log),
	(None,                                        _read_winimage_scripted)
)
def _read_log_autodetect(image_size, log_line_iter):
	try:
		first_line = next(log_line_iter)
	except StopIteration:
		return (image_size, [ ])

	read_func = None
	for prefix, func in _PREFIX_TO_READFUNC:
		if prefix is None or first_line.startswith(prefix):
			read_func = func
			break

	return read_func(image_size, itertools.chain([ first_line ], log_line_iter))


def _normalize_ranges(ranges):
	intervals = [ (start, start + size) for start, size in ranges ]
	if len(intervals) == 0:
		return [ ]
	ordered_intervals = sorted(intervals, key=operator.itemgetter(0))
	merged_intervals = ordered_intervals[0:1]
	for start, end in ordered_intervals[1:]:
		last_interval = merged_intervals[-1]
		if start == last_interval[1]:
			merged_intervals[-1] = (last_interval[0], end)
		else:
			if start < last_interval[1]:
				print >> sys.stderr, "Overlapping range"
			merged_intervals.append((start, end))
	return [ (start, end - start) for start, end in merged_intervals ]


def _read_badranges_for_file(image_path):
	log_path = image_path + ".log"
	image_size = os.path.getsize(image_path)
	try:
		with _detect_open(log_path) as log_stream:
			expected_size, bad_ranges = _read_log_autodetect(image_size, log_stream)
	except EnvironmentError:
		expected_size = image_size
		bad_ranges = [ ]

	if expected_size > image_size:
		print >> sys.stderr, "Expected size for {0} is {1}, but is actually {2}".format(
			image_path, expected_size, image_size)
		bad_ranges.append((image_size, expected_size - image_size))

	return _normalize_ranges(bad_ranges)


if __name__ == '__main__':
	for start, size in _read_badranges_for_file(sys.argv[1]):
		print "0x{0:08X}  0x{1:08X}".format(start, size)
