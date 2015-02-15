import codecs
import itertools
import json
import operator
import os
import re
import sys

from disklib.mediageom import DiskGeometry


def _normalize_ranges(ranges):
	if len(ranges) == 0:
		return [ ]
	ordered_ranges = sorted(ranges, key=operator.itemgetter(0))
	merged_ranges = ordered_ranges[0:1]
	for start, end in ordered_ranges[1:]:
		if start == end:
			continue
		last_range = merged_ranges[-1]
		if start == last_range[1]:
			merged_ranges[-1] = (last_range[0], end)
		else:
			if start < last_range[1]:
				print >> sys.stderr, "Overlapping range"
			merged_ranges.append((start, end))
	return merged_ranges


def _invert_ranges(ranges, domain):
	inverted = [ ]
	last_end = 0
	for start, end in _normalize_ranges(ranges):
		inverted.append((last_end, start))
		last_end = end
	inverted.append((last_end, domain))
	return [ r for r in inverted if r[0] != r[1] ]


class ValidityRanges(object):
	def __init__(self, domain, range_tuple_iter=None, normalize=True, invert=False):
		self.domain = domain

		if range_tuple_iter:
			self.good_ranges = list(range_tuple_iter)
			if invert:
				self.invert()
			elif normalize:
				self.normalize()
		else:
			# if no ranges provided, assume the entire domain is good
			self.good_ranges = [ (0, domain) ]

	def normalize(self):
		self.good_ranges = _normalize_ranges(self.good_ranges)

	def invert(self):
		self.good_ranges = _invert_ranges(self.good_ranges, self.domain)

	def itergood(self):
		"Returns an iterator over all good ranges, each in a (start, end) tuple"
		return iter(self.good_ranges)

	def iterbad(self):
		"Returns an iterator over all bad ranges, each in a (start, end) tuple"
		for is_good, start, end in self.iterall():
			if is_good:
				yield (start, end)

	def iterall(self):
		"Returns an iterator over all ranges, each in an (is_good, start, end) tuple"
		expect_good_start = 0
		for start, end in self.good_ranges:
			if start != expect_good_start:
				yield (False, expect_good_start, start)
			yield (True, start, end)
			expect_good_start = end
		if expect_good_start != self.domain:
			yield (False, expect_good_start, self.domain)


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
		return (bad_start, bad_start + bad_len)
	return None


def read_winimage_pasted(image_size, log_line_iter):
	expected_size = _minimum_common_size(image_size)
	geometry = DiskGeometry.from_image_size(expected_size)

	bad_ranges = set(filter(None,
		(_parse_winimage_error(geometry, line) for line in log_line_iter)
	))

	if image_size < expected_size:
		bad_ranges.append((image_size, expected_size))

	return ValidityRanges(expected_size, bad_ranges, invert=True)


def read_winimage_scripted(image_size, log_line_iter):
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

	if image_size < expected_size:
		bad_ranges.append((image_size, expected_size))

	return ValidityRanges(expected_size, bad_ranges, invert=True)


_FAUDD_EXPECT_SIZE = re.compile(
	r"^\tEstimated Total Size:\t(?P<size>\d+)")
_FAUDD_BAD_RANGE = re.compile(
	r"^File data in the range 0x(?P<start>[0-9A-Fa-f]+)-0x(?P<end>[0-9A-Fa-f]+) could not be read\.")
def read_faudd_log(image_size, log_line_iter):
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
			bad_ranges.append((start, end))

	# faudd may have burped errors about ranges it didn't commit to the image file
	clamped_bad_ranges = [ ]
	for start, end in bad_ranges:
		if start <= image_size:
			if end <= image_size:
				clamped_bad_ranges.append((start, end))
			else:
				clamped_bad_ranges.append((start, image_size))

	if image_size != expected_size:
		clamped_bad_ranges.append((image_size, expected_size))

	return ValidityRanges(expected_size, clamped_bad_ranges, invert=True)


_DDRESCUE_BLOCK = re.compile(
	r"^0x(?P<start>[0-9A-Fa-f]+)\s+0x(?P<size>[0-9A-Fa-f]+)\s+(?P<status>[?*/FG+-])")
def read_ddrescue_log(image_size, log_line_iter):
	good_ranges = [ ]
	seen_current_status = False

	for line in log_line_iter:
		if line.startswith("#"):
			continue

		if not seen_current_status:
			seen_current_status = True
			continue

		m = _DDRESCUE_BLOCK.match(line)
		if m:
			if m.group("status") == "+":
				start, size = [ int(s, 16) for s in m.group("start", "size") ]
				good_ranges.append((start, start + size))

	return ValidityRanges(image_size, good_ranges)


_PREFIX_TO_READFUNC = (
	("-" * 20,                                    read_winimage_pasted),
	("Forensic Acquisition Utilities,",           read_faudd_log),
	("# Rescue Logfile. Created by GNU ddrescue", read_ddrescue_log),
	(None,                                        read_winimage_scripted)
)
def read_log_autodetect(image_size, log_line_iter):
	try:
		first_line = next(log_line_iter)
	except StopIteration:
		return ValidityRanges(image_size)

	log_reader_func = None
	for prefix, func in _PREFIX_TO_READFUNC:
		if prefix is None or first_line.startswith(prefix):
			log_reader_func = func
			break

	return log_reader_func(image_size, itertools.chain([ first_line ], log_line_iter))


def read_validity_for_file(image_path):
	log_path = image_path + ".log"
	image_size = os.path.getsize(image_path)
	try:
		with _detect_open(log_path) as log_stream:
			return read_log_autodetect(image_size, log_stream)
	except EnvironmentError:
		return ValidityRanges(image_size)
