import calendar
import time


from utils.NamedStruct import NamedStruct

from msfat import ATTR_READ_ONLY, ATTR_HIDDEN, ATTR_SYSTEM, ATTR_VOLUME_ID, \
	ATTR_DIRECTORY, ATTR_ARCHIVE, ATTR_LONG_NAME, ATTR_LONG_NAME_MASK, \
	ATTR_RESERVED_MASK


_LAST_MARKER = "\x00"
_FREE_MARKER = "\xE5"

_THISDIR_NAME = ".          "
_UPDIR_NAME =   "..         "

def allowed_in_short_name(char):
	return char == '\x05' or char >= '\x20' and char not in '"*+,./:;<=>?[\\]|'

def allowed_in_long_name(char):
	return char >= '\x20' and char not in '"*/:<>?\\|'

def short_name_checksum(short_name):
	"""Calculates a single-byte checksum of a short name for use in
	its associated long filename entries. The short name should be exactly 11
	characters long, in the space-padded format as is stored on disk."""
	if len(short_name) != 11:
		raise ValueError("short_name must be exactly 11 characters long")
	s = 0
	for ch in short_name:
		# 8-bit rotate right and add (the add is 8 bit too!!)
		s = ((s >> 1) + (s << 7) + ord(ch)) & 0xFF
	return s

def unpack_fat_date(date16):
	day =    date16 & 0x001F
	month = (date16 & 0x01E0) >> 5
	year =  (date16 & 0xFE00) >> 9
	return (year + 1980, month, day)

def unpack_fat_time(time16):
	seconds = (time16 & 0x001F) << 1
	minutes = (time16 & 0x07E0) >> 5
	hours =   (time16 & 0xF800) >> 11
	return (hours, minutes, seconds)

def fat_time_to_unix(date16, time16, add_seconds=0, timezone=None):
	"""Given a FAT date Uint16, a FAT time Uint16, an optional number of seconds
	to add, and a timezone, returns the time expressed as the number of seconds
	since the Unix epoch.

	timezone should be the number of seconds difference from UTC. Positive is
	West of UTC, negative is East. This is the same convention as time.timezone.
	If it is omitted or None, the timestamp is interpreted in the current
	timezone."""

	struct_time = unpack_fat_date(date16) + unpack_fat_time(date16)
	if timezone is None:
		epoch = time.mktime(struct_time)
	else:
		epoch = calendar.timegm(struct_time) - timezone

	return epoch + add_seconds


class FATShortDirEntryStruct(NamedStruct):
	endian = "little"
	fields = [
		# 8.3 name. restrictions:
		# 0x20 can't be in [0]

		# allowed nowhere:
		# 0x00-0x04, 0x06-0x1F, 0x22, 0x2A-0x2C, 0x2E, 0x2F, 0x3A-0x3F, 0x5B-0x5D, 0x7C

		# 0x2E (.) IS allowed in the thisdir an updir entries, which should be
		# the first two entries in a non-root dir

		# must be unique within a directory
		("11s", "DIR_Name"),

		("B",   "DIR_Attr"), # 0xC0 bits are reserved, set to 0
		("B",   "DIR_NTRes"), # Reserved by Win NT, set to 0
		("B",   "DIR_CrtTimeTenth"), # / 100 and add to create time
		("H",   "DIR_CrtTime"),
		("H",   "DIR_CrtDate"),
		("H",   "DIR_LstAccDate"),

		# << 16 and | with first cluster. should be 0 on FAT12/16
		# must be 0 when ATTR_VOLUME_ID set
		("H",   "DIR_FstClusHI"),
		("H",   "DIR_WrtTime"),
		("H",   "DIR_WrtDate"),

		# must be 0 when ATTR_VOLUME_ID set
		# if this is a .. entry and the parent is root, must be 0 
		# (along with DIR_FstClusHI)
		("H",   "DIR_FstClusLO"),

		# must be 0 when ATTR_DIRECTORY set
		("I",   "DIR_FileSize")
	]

_LAST_LONG_ENTRY = 0x40
_LONG_ENTRY_ORD_MASK = 0x3F
class FATLongDirEntryStruct(NamedStruct):
	endian = "little"
	fields = [
		("B",   "LDIR_Ord"),       # | with LAST_LONG_ENTRY
		("10s", "LDIR_Name1"),     # UCS2 chars 1-5 of this segment
		("B",   "LDIR_Attr"),      # Must be ATTR_LONG_NAME
		("B",   "LDIR_Type"),      # Must be zero. Non-zero for future expansion (which is safe to say never happened)
		("B",   "LDIR_Chksum"),    # Check byte
		("12s", "LDIR_Name2"),     # UCS2 chars 6-11 of this segment
		("H",   "LDIR_FstClusLO"), # Must be 0 for non LFN-aware disk utils
		("4s",  "LDIR_Name3")      # UCS2 chars 12-13 of this segment
	]

def _buffer_is_long_entry(buf):
	return (ord(buf[11]) & ATTR_LONG_NAME_MASK) == ATTR_LONG_NAME

def _buffer_is_free(buf):
	return buf[0] == _FREE_MARKER

def _buffer_is_last(buf):
	return buf[0] == _LAST_MARKER

# TODO: may be preferable to do this all in the directory read function? There
# are still other things to check, like the final LFN segment being null
# terminated if shorter than 13 chars and padded with 0xFF if shorter than 12
# chars
def _assemble_long_entries(long_entries):
	if long_entries is None:
		return None

	count = 0

	# max length of an LFN is 255 U16s. each entry can store 13 UCS2 chars, so
	# use a buffer of 510 rounded up to the next multiple of 26
	buf = bytearray(520)
	for e in long_entries:
		order = e.LDIR_Ord & _LONG_ENTRY_ORD_MASK
		base = (order - 1) * 26
		buf[base : base + 10] = e.LDIR_Name1
		buf[base + 10 : base + 22] = e.LDIR_Name2
		buf[base + 22 : base + 26] = e.LDIR_Name3
		count += 1

	if count == 0:
		return None

	name = buf.decode("utf_16_le")
	return name[:name.find(u"\0")]

class FATDirEntry(object):
	def __init__(self, short_entry, long_entries=None):
		self.short_entry = short_entry
		self.long_entries = long_entries
		self.long_name = _assemble_long_entries(long_entries)

	def name(self):
		if self.long_name is None:
			return self.short_name()
		return self.long_name

	def short_name(self):
		prefix = self.short_entry.DIR_Name[:8].rstrip()
		if prefix[0:1] == "\x05":
			prefix = "\xE5" + prefix[1:]
		suffix = self.short_entry.DIR_Name[8:].rstrip()
		if suffix:
			return prefix + "." + suffix
		return prefix

	def is_free(self):
		return self.short_entry.DIR_Name[0] == "\xE5"

	def is_last(self):
		return self.short_entry.DIR_Name[0] == "\x00"

	def is_read_only(self):
		return self.short_entry.DIR_Attr & ATTR_READ_ONLY != 0

	def is_hidden(self):
		return self.short_entry.DIR_Attr & ATTR_HIDDEN != 0

	def is_system(self):
		return self.short_entry.DIR_Attr & ATTR_SYSTEM != 0

	def is_volume_id(self):
		return self.short_entry.DIR_Attr & ATTR_VOLUME_ID != 0

	def is_directory(self):
		return self.short_entry.DIR_Attr & ATTR_DIRECTORY != 0

	def is_archive(self):
		return self.short_entry.DIR_Attr & ATTR_ARCHIVE != 0

	def attr_string(self):
		return "".join(
			(b and ch or "-") for ch, b in [
				("A", self.is_archive()),
				("D", self.is_directory()),
				("V", self.is_volume_id()),
				("S", self.is_system()),
				("H", self.is_hidden()),
				("R", self.is_read_only())
			]
		)

	def create_time(self, timezone=None):
		return fat_time_to_unix(
			self.short_entry.DIR_CrtDate,
			self.short_entry.DIR_CrtTime,
			self.short_entry.DIR_CrtTimeTenth * 0.01,
			timezone
		)

	def access_time(self, timezone=None):
		return fat_time_to_unix(
			self.short_entry.DIR_LstAccDate,
			0, 0, timezone
		)

	def start_cluster(self):
		return (
			(self.short_entry.DIR_FstClusHI << 16) |
			self.short_entry.DIR_FstClusLO
		)

	def write_time(self, timezone=None):
		return fat_time_to_unix(
			self.short_entry.DIR_WrtDate,
			self.short_entry.DIR_WrtTime,
			0, timezone
		)

	def file_size(self):
		return self.short_entry.DIR_FileSize

	def __str__(self):
		return "{0!r} [{1}] {2}".format(
			self.name(),
			self.attr_string(),
			self.file_size()
		)


def read_dir(stream):
	long_entries = [ ]
	while True:
		bytes = stream.read(32)
		if len(bytes) == 0:
			# this is unexpected if we're not intentionally reading beyond end
			break
		elif _buffer_is_last(bytes):
			break
		elif _buffer_is_free(bytes):
			continue
		elif _buffer_is_long_entry(bytes):
			entry = FATLongDirEntryStruct(bytes)
			if len(long_entries) == 0:
				long_entries.append(entry)
			else:
				if entry.LDIR_Ord & _LAST_LONG_ENTRY:
					# begins a new entry
					long_entries = [ entry ]
				elif (
					# we can add it if the checksum is the same as the last
					# and the ordinal is one less than the last
					entry.LDIR_Chksum == long_entries[-1].LDIR_Chksum and
					(entry.LDIR_Ord + 1) == (long_entries[-1].LDIR_Ord & _LONG_ENTRY_ORD_MASK)
				):
					long_entries.append(entry)
				else:
					# it's not the last in a new sequence, it's not part of
					# this one. what is it? dunno
					long_entries = [ ]
		else:
			entry = FATShortDirEntryStruct(bytes)
			# we should have hit long entry 1 (they're 1-based to prevent 0s
			# in the first byte)
			if (
				len(long_entries) > 0 and
				(long_entries[-1].LDIR_Ord & _LONG_ENTRY_ORD_MASK) == 1 and
				long_entries[-1].LDIR_Chksum == short_name_checksum(entry.DIR_Name)
			):
				yield FATDirEntry(entry, long_entries)
			else:
				yield FATDirEntry(entry)
			long_entries = [ ]
