import collections
import math
import struct


from utils.NamedStruct import NamedStruct

from msfat import TYPE_FAT12, TYPE_FAT16, TYPE_FAT32
from msfat.chkdsk import chkdsk


class MediaError(Exception):
	pass


class SeekError(MediaError):
	pass


class AllocationError(MediaError):
	pass


_FAT32_ENTRY_MASK = 0x0FFFFFFF
_FAT12_EOC = 0xFF8
_FAT12_BAD = 0xFF7
_MIN_CLUSTER_NUM = 2

class BiosParameterBlock(NamedStruct):
	endian = "little"
	fields = [
		("3s",  "BS_jmpBoot"),     # \xeb.\x90|\xe9..
		("8s",  "BS_OEMName"),     # informational only. "MSWIN4.1" recommended
		("H",   "BPB_BytsPerSec"), # 2^n where 9 <= n <= 12
		("B",   "BPB_SecPerClus"), # 2^n where 0 <= n <= 7, BPB_BytsPerSec * BPB_SecPerClus <= 32*1024
		("H",   "BPB_RsvdSecCnt"), # > 0, FAT12 and FAT16 must be 1, FAT32 often 32
		("B",   "BPB_NumFATs"),    # Should be 2

		# This field * 32 must be an even multiple of BPB_BytsPerSec
		# i.e. Root entry count must not partially fill a sector
		# (entries are 32 bytes each)
		# Must be 0 on FAT32
		# FAT16 recommended to be 512
		("H",   "BPB_RootEntCnt"),

		# If 0, then see BOB_TotSec32. Otherwise use this value and 
		# BPB_TotSec32 must be 0. Must be 0 on FAT32.
		# Can be less than the total # of sectors on disk. Must never be greater
		("H",   "BPB_TotSec16"),

		# 0xF0, 0xF8-0xFF. Should equal FAT[0]. 0xF0 for removable media,
		# 0xF8 for non-removable
		("B",   "BPB_Media"),

		("H",   "BPB_FATSz16"), # must be 0 on FAT32, in which case see BPB_FATSz32
		("H",   "BPB_SecPerTrk"), # check against MediaGeometry
		("H",   "BPB_NumHeads"),  # check against MediaGeometry
		("I",   "BPB_HiddSec"),   # 0 on non-partitioned disks, like floppies
		("I",   "BPB_TotSec32")
	]


class BiosParameterBlock16(NamedStruct): # also used for FAT12
	endian = "little"
	fields = [
		("B",   "BS_DrvNum"),  # 0x00 for floppy, 0x80 for hard

		# Used by WinNT, other software should set to 0 when creating
		("B",   "BS_Reserved1"),

		("B",   "BS_BootSig"), # 0x29 means the following 3 fields are present
		("I",   "BS_VolID"),
		("11s", "BS_VolLab"), # should match volume dir entry in \. "NO NAME    " if not set

		# not actually used in FAT type determination, but should be one of
		# "FAT12   ", "FAT16   ", "FAT     "
		("8s",  "BS_FilSysType")
	]


class BiosParameterBlock32(NamedStruct):
	endian = "little"
	fields = [
		("I",   "BPB_FATSz32"),
		("H",   "BPB_ExtFlags"), # See docs, but nothing to validate probably
		("H",   "BPB_FSVer"),    # Version 0 seems to be the highest defined
		("I",   "BPB_RootClus"), # Should be 2, but not required
		("H",   "BPB_FSInfo"),
		("H",   "BPB_BkBootSec"), # Should be 6
		("12s", "BPB_Reserved"), # Should be all \0

		# Following are same as in BiosParameterBlock16, just different offsets
		("B",   "BS_DrvNum"),
		("B",   "BS_Reserved1"),
		("B",   "BS_BootSig"),
		("I",   "BS_VolID"),
		("11s", "BS_VolLab"),

		# Should be "FAT32   " but as in BiosParameterBlock16, not actually
		# used in type determination
		("8s",  "BS_FilSysType")
	]


_VolumeInfo = collections.namedtuple(
	"_VolumeInfo", [
		"fat_type",
		"fat_type_id",             # BS_FilSysType
		"oem_name",                # BS_OEMName
		"bs_volume_id",            # BS_VolID
		"bs_volume_name",          # BS_VolLab
		"bytes_per_sector",        # BPB_BytsPerSec
		"sectors_per_track",       # BPB_SecPerTrk
		"head_count",              # BPB_NumHeads
		"sector_count",            # self._total_sector_count
		"single_fat_sector_count", # self._fat_sector_count
		"fat_count",               # BPB_NumFATs
		"fat0_sector_start",       # ??
		"root_dir_sector_start",   # self._root_dir_sector_start
		"root_dir_sector_count",   # self._root_dir_sector_count
		"root_entry_count",        # BPB_RootEntCnt
		"data_sector_start",       # self._data_sector_start
		"data_sector_count",       # self._data_sector_count
		"sectors_per_cluster",     # BPB_SecPerClus
		"cluster_count"            # self._cluster_count
	]
)

# Also, Sector[0][510] must == 0x55 and [0][511] must == 0xAA

# FATSize = BPB_FATSz16 != 0 ? BPB_FATSz16 : BPB_FATSz32

# FirstDataSector is first sector of cluster 2, first legal cluster
# FirstDataSector = BPB_RsvdSecCnt + (BPB_NumFATs * FATSize) + RootDirSectorCount

# FirstSectorOfCluster(N) = ((N - 2) * BPB_SecPerClus) + FirstDataSector


ATTR_READ_ONLY =      0x01
ATTR_HIDDEN =         0x02
ATTR_SYSTEM =         0x04
ATTR_VOLUME_ID =      0x08
ATTR_DIRECTORY =      0x10
ATTR_ARCHIVE =        0x20
ATTR_LONG_NAME =      ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID
ATTR_LONG_NAME_MASK = ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID | ATTR_DIRECTORY | ATTR_ARCHIVE
ATTR_RESERVED_MASK =  0xC0

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
		# rotate right and add byte
		s = ((s & 1) << 7) | ((s & 0xFE) >> 1) + ord(ch)
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

def _assemble_long_entries(long_entries):
	if long_entries is None:
		return None

	count = 0

	# max length of an LFN is 255. each entry can store 13 characters, so use
	# a buffer of 255 rounded up to the next multiple of 13
	buf = bytearray(260)
	for e in long_entries:
		order = e.LDIR_Ord & _LONG_ENTRY_ORD_MASK
		base = order * 13
		buf[base : base + 5] = e.LDIR_Name1
		buf[base + 5 : base + 11] = e.LDIR_Name2
		buf[base + 11 : base + 13] = e.LDIR_Name3
		count += 1

	if count == 0:
		return None

	# if there were any missing entries, that block of 13 chars will be
	# \0s in the middle of the string
	return buf.decode("utf_16_le").rstrip("\0")

class FATDirEntry(object):
	def __init__(self, short_entry, long_entries=None):
		self.short_entry = short_entry
		self.long_entry = _assemble_long_entries(long_entries)

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
		return self.short_entry.DIR_Attr & ATTR_READ_ONLY

	def is_hidden(self):
		return self.short_entry.DIR_Attr & ATTR_HIDDEN

	def is_system(self):
		return self.short_entry.DIR_Attr & ATTR_SYSTEM

	def is_volume_id(self):
		return self.short_entry.DIR_Attr & ATTR_VOLUME_ID

	def is_directory(self):
		return self.short_entry.DIR_Attr & ATTR_DIRECTORY

	def is_archive(self):
		return self.short_entry.DIR_Attr & ATTR_ARCHIVE

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


class _BaseStream(object):
	def read(self, count):
		bufs = [ ]
		while count > 0:
			chunk = self._read_chunk(count)
			bufs.append(chunk)
			if len(chunk) == 0:
				break
			count -= len(chunk)
		return "".join(bufs)


class _SectorRunStream(_BaseStream):
	def __init__(self, vol, sector, count):
		self._vol = vol
		self._cur_sector = sector
		self._end_sector = sector + count

		self._buf = None
		self._buf_ptr = 0
		self._buf_left = 0

		self._load_cur_sector()

	def _read_chunk(self, count):
		if self._buf_left == 0 and self._cur_sector < self._end_sector:
			self._cur_sector += 1
			self._load_cur_sector()

		if self._cur_sector == self._end_sector:
			return ""

		actual_count = min(count, self._buf_left)

		ret = self._buf[self._buf_ptr : self._buf_ptr + actual_count]

		self._buf_ptr += actual_count
		self._buf_left -= actual_count

		return ret

	def _load_cur_sector(self):
		self._buf = self._vol._read_sector(self._cur_sector)
		self._buf_ptr = 0
		self._buf_left = len(self._buf)


class _ClusterChainStream(_BaseStream):
	def __init__(self, vol, cluster, bytes=-1, ignore_bad_clusters=False):
		self.ignore_bad_clusters = ignore_bad_clusters

		self._vol = vol
		self._cur_cluster = -1
		self._next_cluster = cluster
		self._is_last = False
		self._bytes_left = bytes
		self._seen = set()

		self._buf = None
		self._buf_ptr = 0
		self._buf_left = 0

	def _read_chunk(self, count):
		if count == 0 or self._bytes_left == 0:
			return ""

		if self._buf_left == 0:
			# hit the end of the last cluster on a stream with unknown size
			# end here
			if self._bytes_left < 0 and self._is_last:
				return ""
			else:
				self._load_next_cluster()

		actual_count = min(count, self._buf_left)

		if self._bytes_left >= 0:
			actual_count = min(actual_count, self._bytes_left)
			self._bytes_left -= actual_count

		ret = self._buf[self._buf_ptr : self._buf_ptr + actual_count]

		self._buf_ptr += actual_count
		self._buf_left -= actual_count

		return ret

	def _load_next_cluster(self):
		if self._is_last:
			raise AllocationError("Premature end of chain")

		new_cur = self._next_cluster
		new_next = self._get_fat_entry(new_cur)

		if self._vol._is_bad(new_next):
			if self.ignore_bad_clusters:
				# there's nothing to link to, so this will still raise a PEOC
				# unless the file is expected to end here
				self._is_last = True
			else:
				raise AllocationError("Chain entered bad sector")

		if self._vol._is_eoc(new_next):
			self._is_last = True

		if new_cur in self._seen:
			raise AllocationError("Cyclical chain")
		self._seen.add(new_cur)

		self._buf = self._vol._read_cluster(new_cur)
		self._buf_ptr = 0
		self._buf_left = len(self._buf)

		self._cur_cluster = new_cur
		self._next_cluster = new_next


class FATVolume(object):
	def __init__(self, stream, geometry):
		self._stream = stream
		self._geometry = geometry
		self._bpb = None
		self._bpb16 = None
		self._bpb32 = None

		# mirror the value we want to use in here. maybe take it from geometry,
		# maybe use what we read from the boot sector.
		self._bytes_per_sector = 0

		# some way of changing this
		self.active_fat_index = 0

		self._root_dir_sector_count = -1
		self._fat_sector_count = -1
		self._total_sector_count = -1
		self._data_sector_start = -1
		self._data_sector_count = -1
		self._cluster_count = -1
		self.fat_type = None

		self._fat_buffer = None
		self._fat_buffer_sector = -1

		self._init_bpb()
		self._init_calcs()
		self._determine_fat_type()


	def get_info(self):
		b = self._bpb
		bx = self.fat_type == TYPE_FAT32 and self._bpb32 or self._bpb16

		return _VolumeInfo(
			self.fat_type,
			bx.BS_FilSysType,
			b.BS_OEMName,
			bx.BS_VolID,
			bx.BS_VolLab,
			b.BPB_BytsPerSec,
			b.BPB_SecPerTrk,
			b.BPB_NumHeads,
			self._total_sector_count,
			self._fat_sector_count,
			b.BPB_NumFATs,
			b.BPB_RsvdSecCnt,
			self._root_dir_sector_start,
			self._root_dir_sector_count,
			b.BPB_RootEntCnt,
			self._data_sector_start,
			self._data_sector_count,
			b.BPB_SecPerClus,
			self._cluster_count
		)


	def chkdsk(self):
		for m in chkdsk(self):
			yield m


	def _open_root_dir(self):
		if self.fat_type == TYPE_FAT32:
			return self._open_cluster_chain(self._bpb32.BPB_RootClus)
		else:
			return self._open_sector_run(self._root_dir_sector_start, self._root_dir_sector_count)


	def _open_sector_run(self, first_sector, count):
		return _SectorRunStream(self, first_sector, count)


	def _open_cluster_chain(self, first_cluster, expected_bytes=-1):
		return _ClusterChainStream(self, first_cluster, expected_bytes)


	def _seek_sector(self, sector, byte=0):
		if 0 <= sector < self._geometry.total_sector_count():
			self._stream.seek(sector * self._geometry.sector_size + byte)
		else:
			raise SeekError("Invalid sector number", sector)

	def _seek_cluster(self, cluster):
		if cluster < _MIN_CLUSTER_NUM:
			raise SeekError("Invalid cluster number", cluster)
		self._seek_sector(self._cluster_sector_start(cluster))

	def _read(self, byte_count):
		return self._stream.read(byte_count)

	def _read_sector(self, sector):
		self._seek_sector(sector)
		return self._read(self._bytes_per_sector)

	def _read_cluster(self, cluster):
		self._seek_cluster(cluster)
		return self._read(self._bytes_per_sector * self._bpb.BPB_SecPerClus)


	def _init_bpb(self):
		self._seek_sector(0)

		self._bpb = BiosParameterBlock.from_stream(self._stream)

		bpbx_union = self._read(max(
			BiosParameterBlock16.size(), BiosParameterBlock32.size()))

		self._bpb16 = BiosParameterBlock16(bpbx_union[:BiosParameterBlock16.size()])
		self._bpb32 = BiosParameterBlock32(bpbx_union[:BiosParameterBlock32.size()])

	def _init_calcs(self):
		# you could use self._bpb.BPB_BytsPerSec
		# self._bytes_per_sector = self._bpb.BPB_BytsPerSec
		self._bytes_per_sector = self._geometry.sector_size

		# you could use BPB_TotSec16 / BPB_TotSec32
		# self._total_sector_count = self._calc_total_sector_count()
		self._total_sector_count = self._geometry.total_sector_count()

		self._fat_sector_count = self._calc_fat_sector_count()
		self._root_dir_sector_start = self._calc_root_dir_sector_start()
		self._root_dir_sector_count = self._calc_root_dir_sector_count()
		self._data_sector_start = self._calc_data_sector_start()
		self._data_sector_count = self._calc_data_sector_count()

		self._cluster_count = 0
		if self._bpb.BPB_SecPerClus > 0:
			self._cluster_count = self._data_sector_count / self._bpb.BPB_SecPerClus
		self._max_cluster_num = self._cluster_count + 1


	def _calc_total_sector_count(self):
		if self._bpb.BPB_TotSec16 != 0:
			return self._bpb.BPB_TotSec16
		return self._bpb.BPB_TotSec32

	def _calc_fat_sector_start(self):
		return self._bpb.BPB_RsvdSecCnt + self._fat_sector_count * self.active_fat_index

	def _calc_fat_sector_count(self):
		if self._bpb.BPB_FATSz16 != 0:
			return self._bpb.BPB_FATSz16
		return self._bpb32.BPB_FATSz32

	def _calc_root_dir_sector_start(self):
		b = self._bpb
		return (b.BPB_RsvdSecCnt + self._fat_sector_count * b.BPB_NumFATs)

	def _calc_root_dir_sector_count(self):
		b = self._bpb
		# RootDirSectorCount = 
		#   ((BPB_RootEntCnt * 32) + (BPB_BytsPerSec - 1)) / BPB_BytsPerSec
		if b.BPB_RootEntCnt == 0:
			return 0

		# adding bytes_per_sector - 1 has the effect of performing a ceil
		# when using integer division. don't need to ceil it twice
		bytes = (b.BPB_RootEntCnt * 32) + (self._bytes_per_sector - 1)
		return bytes / self._bytes_per_sector

	def _calc_data_sector_start(self):
		return self._root_dir_sector_start + self._root_dir_sector_count

	def _calc_data_sector_count(self):
		return self._total_sector_count - self._calc_data_sector_start()

	def _cluster_sector_start(self, n):
		return (n - 2) * self._bpb.BPB_SecPerClus + self._data_sector_start

	def _get_fat_offset(self, clustern):
		if self.fat_type == TYPE_FAT32:
			offset = clustern * 4
		elif self.fat_type == TYPE_FAT16:
			offset = clustern * 2
		else:
			offset = clustern + (clustern >> 1) # integer mul by 1.5, rounding down

		return divmod(offset, self._bytes_per_sector)

	def _get_fat_address(self, clustern):
		sec_offset, byte_offset = self._get_fat_offset(clustern)
		return (sec_offset + self._calc_fat_sector_start(), byte_offset)

	def _get_fat_entry(self, clustern):
		sec_num, sec_offset = self._get_fat_address(clustern)
		self._load_fat(sec_num)

		if self.fat_type == TYPE_FAT32:
			entry_bytes = self._fat_buffer[sec_offset : sec_offset + 4]
			return struct.unpack("I", entry_bytes)[0] & _FAT32_ENTRY_MASK

		entry_bytes = self._fat_buffer[sec_offset : sec_offset + 2]
		entry = struct.unpack("H", entry_bytes)[0]
		if self.fat_type == TYPE_FAT16:
			return entry

		# FAT12 case
		if clustern & 1:
			# odd-numbered clusters are stored in the high 12 bits of the 16 bit value
			return entry >> 4

		# even-numbered clusters are stored in the low 12
		return entry & 0x0FFF

	def _is_eoc(self, entry):
		return entry >= self._fat_eoc

	def _is_bad(self, entry):
		return entry == self._fat_bad

	def _load_fat(self, sectorn):
		if sectorn == self._fat_buffer_sector:
			return
		self._fat_buffer_sector = sectorn
		self._seek_sector(sectorn)
		self._fat_buffer = self._read(self._bytes_per_sector * 2)

	def _determine_fat_type(self):
		if self._cluster_count < 4085:
			self.fat_type = TYPE_FAT12
			extrabits = 0

		elif self._cluster_count < 65525:
			self.fat_type = TYPE_FAT16
			extrabits = 0xF000

		else:
			self.fat_type = TYPE_FAT32
			extrabits = 0xFFFF000

		self._fat_eoc = _FAT12_EOC | extrabits
		self._fat_bad = _FAT12_BAD | extrabits