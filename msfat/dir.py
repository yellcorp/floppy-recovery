from ctypes import LittleEndianStructure, Union, sizeof, c_ubyte, c_uint16, c_uint32
import calendar
import itertools
import time


from msfat import ATTR_READ_ONLY, ATTR_HIDDEN, ATTR_SYSTEM, ATTR_VOLUME_ID, \
	ATTR_DIRECTORY, ATTR_ARCHIVE, ATTR_LONG_NAME, ATTR_LONG_NAME_MASK, \
	ATTR_RESERVED_MASK


THISDIR_NAME = "{0:11s}".format(".")
UPDIR_NAME =   "{0:11s}".format("..")


def allowed_in_short_name(char):
	return char == '\x05' or char >= '\x20' and char not in '"*+,./:;<=>?[\\]|'

def is_valid_short_name(s):
	return s == THISDIR_NAME or s == UPDIR_NAME or (
		s[0] != ' ' and all(allowed_in_short_name(c) for c in s)
	)

def allowed_in_long_name(char):
	return char >= '\x20' and char not in '"*/:<>?\\|'

def is_valid_long_name(s):
	return all(allowed_in_long_name(c) for c in s)

def is_long_name_correctly_padded(s):
	null_pos = s.find("\0")
	if null_pos == -1:
		return True
	return all(c == "\uFFFF" for c in s[null_pos + 1:])

def short_name_checksum(short_name_bytes):
	"""Calculates a single-byte checksum of a short name for use in
	its associated long filename entries. The short name should be an iterable
	of exactly 11 unsigned 8-bit ints, in the space-padded format as is stored
	on disk."""
	if len(short_name_bytes) != 11:
		raise ValueError("short_name_bytes must be exactly 11 bytes long")
	s = 0
	for b in short_name_bytes:
		# 8-bit rotate right and add (the add is 8 bit too!!)
		s = ((s >> 1) + (s << 7) + b) & 0xFF
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


_LAST_MARKER = 0x00
_FREE_MARKER = 0xE5
_INITIAL_0XE5_PLACEHOLDER = 0x05

class _FATShortDirEntry(LittleEndianStructure):
	_pack_ = 1
	_fields_ = [
		# 8.3 name. restrictions:
		# 0x20 can't be in [0]

		# allowed nowhere:
		# 0x00-0x04, 0x06-0x1F, 0x22, 0x2A-0x2C, 0x2E, 0x2F, 0x3A-0x3F, 0x5B-0x5D, 0x7C

		# 0x2E (.) IS allowed in the thisdir an updir entries, which should be
		# the first two entries in a non-root dir

		# must be unique within a directory
		("DIR_Name",         c_ubyte * 11),

		("DIR_Attr",         c_ubyte), # 0xC0 bits are reserved, set to 0
		("DIR_NTRes",        c_ubyte), # Reserved by Win NT, set to 0
		("DIR_CrtTimeTenth", c_ubyte), # / 100 and add to create time - yes despite 'Tenth' in the name
		("DIR_CrtTime",      c_uint16),
		("DIR_CrtDate",      c_uint16),
		("DIR_LstAccDate",   c_uint16),

		# << 16 and | with first cluster. should be 0 on FAT12/16
		# must be 0 when ATTR_VOLUME_ID set
		("DIR_FstClusHI",    c_uint16),
		("DIR_WrtTime",      c_uint16),
		("DIR_WrtDate",      c_uint16),

		# must be 0 when ATTR_VOLUME_ID set
		# if this is a .. entry and the parent is root, must be 0 
		# (along with DIR_FstClusHI)
		("DIR_FstClusLO",    c_uint16),

		# must be 0 when ATTR_DIRECTORY set
		("DIR_FileSize",     c_uint32)
	]


_LAST_LONG_ENTRY = 0x40
_LONG_ENTRY_ORD_MASK = 0x3F

class _FATLongDirEntry(LittleEndianStructure):
	_pack_ = 1
	_fields_ = [
		("LDIR_Ord",         c_ubyte),      # ORed with LAST_LONG_ENTRY
		("LDIR_Name1",       c_ubyte * 10), # UCS2 chars 1-5 of this segment
		("LDIR_Attr",        c_ubyte),      # Must be ATTR_LONG_NAME
		("LDIR_Type",        c_ubyte),      # Must be zero. Non-zero for future expansion (which is safe to say never happened)
		("LDIR_Chksum",      c_ubyte),      # Check byte
		("LDIR_Name2",       c_ubyte * 12), # UCS2 chars 6-11 of this segment
		("LDIR_FstClusLO",   c_uint16),     # Must be 0 for non LFN-aware disk utils
		("LDIR_Name3",       c_ubyte * 4)   # UCS2 chars 12-13 of this segment
	]


class FATDirEntry(Union):
	_anonymous_ = ("short", "long")
	_fields_ = [
		("short", _FATShortDirEntry),
		("long",  _FATLongDirEntry)
	]

	def _name_parts(self):
		name = bytearray(self.DIR_Name)
		if name[0] == _INITIAL_0XE5_PLACEHOLDER:
			name[0] = 0xE5

		return str(name[:8]).rstrip(), str(name[8:]).rstrip()

	def short_name(self):
		prefix, suffix = self._name_parts()

		if suffix:
			return prefix + "." + suffix
		return prefix

	def short_name_with_encoding(self, encoding="cp1252"):
		prefix, suffix = self._name_parts()
		uprefix = prefix.decode(encoding, "replace")
		usuffix = suffix.decode(encoding, "replace")

		if usuffix:
			return uprefix + "." + usuffix
		return uprefix

	def short_name_checksum(self):
		return short_name_checksum(self.DIR_Name)

	def is_free_entry(self):
		return self.DIR_Name[0] == _FREE_MARKER

	def is_last_in_dir(self):
		return self.DIR_Name[0] == _LAST_MARKER

	def is_long_name_segment(self):
		return (self.DIR_Attr & ATTR_LONG_NAME_MASK) == ATTR_LONG_NAME

	def is_final_long_name_segment(self):
		return (self.LDIR_Ord & _LAST_LONG_ENTRY) != 0

	def long_name_ordinal(self):
		return self.LDIR_Ord & _LONG_ENTRY_ORD_MASK

	def is_read_only(self):
		return self.DIR_Attr & ATTR_READ_ONLY != 0

	def is_hidden(self):
		return self.DIR_Attr & ATTR_HIDDEN != 0

	def is_system(self):
		return self.DIR_Attr & ATTR_SYSTEM != 0

	def is_volume_id(self):
		return self.DIR_Attr & ATTR_VOLUME_ID != 0

	def is_directory(self):
		return self.DIR_Attr & ATTR_DIRECTORY != 0

	def is_archive(self):
		return self.DIR_Attr & ATTR_ARCHIVE != 0

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

	def start_cluster(self):
		return (
			(self.DIR_FstClusHI << 16) |
			self.DIR_FstClusLO
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

	def write_time(self, timezone=None):
		return fat_time_to_unix(
			self.short_entry.DIR_WrtDate,
			self.short_entry.DIR_WrtTime,
			0, timezone
		)

	def iter_long_name_bytes(self):
		for field in (self.LDIR_Name1, self.LDIR_Name2, self.LDIR_Name3):
			for b in field:
				yield b

	def long_name_segment(self):
		return bytearray(self.iter_long_name_bytes()).decode("utf_16_le")

	def type_string(self):
		if self.is_free_entry():
			return "non-terminal free entry"
		elif self.is_last_in_dir():
			return "terminal free entry"
		elif self.is_long_name_segment():
			return "long filename segment"
		elif self.is_volume_id():
			return "volume id"
		elif self.is_directory():
			return "directory"
		else:
			return "file"


class FATAggregateDirEntry(object):
	def __init__(self, short_entry, long_entries=None):
		self.short_entry = short_entry
		self.long_entries = list(long_entries or [ ])
		if len(self.long_entries) > 0:
			self.long_name = assemble_long_entries(self.long_entries)
		else:
			self.long_name = None

	def name(self):
		if self.long_name is None:
			return self.short_entry.short_name()
		return self.long_name

	def __str__(self):
		return "{0!r} [{1}] {2}".format(
			self.name(),
			self.short_entry.attr_string(),
			self.short_entry.DIR_FileSize
		)


def _can_append_long_entry(e, f):
	"""True if f is a FATDirEntry that can follow e. For f to follow e, f and e
	must have the same checksum, and f's ordinal must be one less than e"""
	return (
		f.LDIR_Chksum == e.LDIR_Chksum and
		f.long_name_ordinal() + 1 == e.long_name_ordinal()
	)


def _long_entry_set_belongs_to_short_entry(long_entries, short_entry):
	"""True if a list of long entries is associated with the short_entry.
	The last member of long_entries must be numbered 1, and its checksum value
	must match the calculated checksum of short_entry's name. Only the last
	checksum in long_entries is checked. It's assumed that long_entries is
	accumulated with the use of _can_append_long_entry"""
	return (
		len(long_entries) > 0 and
		long_entries[-1].long_name_ordinal() == 1 and
		long_entries[-1].LDIR_Chksum == short_entry.short_name_checksum()
	)


def assemble_long_entries(long_entries):
	name_bytes = bytearray()
	for e in reversed(long_entries):
		name_bytes.extend(e.iter_long_name_bytes())

	# append a 16-bit null in case the last entry segment is filled exactly
	name_bytes.extend((0, 0))

	name = name_bytes.decode("utf_16_le", "replace")
	return name[:name.find("\0")]


def read_dir(stream):
	long_entries = [ ]
	while True:
		bytes = stream.read(sizeof(FATDirEntry))
		if len(bytes) == 0:
			# this is unexpected if we're not intentionally reading beyond end
			break

		entry = FATDirEntry.from_buffer_copy(bytes)
		if entry.is_last_in_dir():
			break
		elif entry.is_free_entry():
			continue
		elif entry.is_long_name_segment():
			if len(long_entries) == 0:
				long_entries.append(entry)
			elif entry.is_final_long_name_segment():
				# begins a new entry
				long_entries = [ entry ]
			elif _can_append_long_entry(long_entries[-1], entry):
				long_entries.append(entry)
			else:
				# it's not the last in a new sequence, it's not part of
				# this one. what is it? dunno
				long_entries = [ ]
		else:
			# we should have hit long entry 1 (they're 1-based to prevent 0s
			# in the first byte)
			if _long_entry_set_belongs_to_short_entry(long_entries, entry):
				yield FATAggregateDirEntry(entry, long_entries)
			else:
				yield FATAggregateDirEntry(entry)

			long_entries = [ ]
