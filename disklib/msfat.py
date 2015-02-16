import math
import re


from utils.NamedStruct import NamedStruct


_COMMON_JMPBOOT = re.compile(r"^(?:\xEB.\x90|\xE9..)$")
_VALID_BYTES_PER_SECTOR = tuple(1 << n for n in xrange(9, 13))
_VALID_SECTORS_PER_CLUSTER = tuple(1 << n for n in xrange(0, 8))
_VALID_MEDIA_BYTE = (0xF0,) + tuple(xrange(0xF8, 0x100))
_VALID_DRIVE_NUM = (0x00, 0x80)
_FAT_TYPE_CLUSTER_COUNT_CUTOVERS = (4085, 65525)
_FAT_SIG = "\x55\xAA"

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


# Also, Sector[0][510] must == 0x55 and [0][511] must == 0xAA

# FATSize = BPB_FATSz16 != 0 ? BPB_FATSz16 : BPB_FATSz32

# FirstDataSector is first sector of cluster 2, first legal cluster
# FirstDataSector = BPB_RsvdSecCnt + (BPB_NumFATs * FATSize) + RootDirSectorCount

# FirstSectorOfCluster(N) = ((N - 2) * BPB_SecPerClus) + FirstDataSector

def _hexdump(string):
	return " ".join("{0:02X}".format(ord(c)) for c in string)


# Log levels match values of equivalent severity in python logging module
# Short names privately...
_INVALID = 40
_UNCOMMON = 30
_INFO = 20

# ...long names publicly
CHKDSK_LOG_INVALID = _INVALID
CHKDSK_LOG_UNCOMMON = _UNCOMMON
CHKDSK_LOG_INFO = _INFO


class FATVolume(object):
	FAT12 = "FAT12"
	FAT16 = "FAT16"
	FAT32 = "FAT32"


	def __init__(self, stream, geometry):
		self._stream = stream
		self._geometry = geometry
		self._bpb = None
		self._bpb16 = None
		self._bpb32 = None

		# mirror the value we want to use in here. maybe take it from geometry,
		# maybe use what we read from the boot sector.
		self._bytes_per_sector = 0

		self._root_dir_sector_count = -1
		self._fat_sector_count = -1
		self._total_sector_count = -1
		self._first_data_sector = -1
		self._data_sector_count = -1
		self._cluster_count = -1
		self.fat_type = None

		self._read_bpb()


	def chkdsk(self):
		b = self._bpb
		b16 = self._bpb16
		b32 = self._bpb32

		if _COMMON_JMPBOOT.match(b.BS_jmpBoot) is None:
			yield (_UNCOMMON, "Uncommon BS_jmpBoot: {0}".format(_hexdump(b.BS_jmpBoot)))

		yield (_INFO, "BS_OEMName: {0!r}".format(b.BS_OEMName))

		if b.BPB_BytsPerSec not in _VALID_BYTES_PER_SECTOR:
			yield (_INVALID, "Invalid BPB_BytsPerSec: 0x{0:04X}".format(b.BPB_BytsPerSec))

		if b.BPB_SecPerClus not in _VALID_SECTORS_PER_CLUSTER:
			yield (_INVALID, "Invalid BPB_SecPerClus: 0x{0:02X}".format(b.BPB_SecPerClus))

		if b.BPB_NumFATs != 2:
			yield (_UNCOMMON, "Uncommon BPB_NumFATs: 0x{0:02X}".format(b.BPB_NumFATs))

		if b.BPB_BytsPerSec > 0 and (b.BPB_RootEntCnt * 32) % b.BPB_BytsPerSec != 0:
			yield (_INVALID, "Invalid BPB_RootEntCnt: 0x{0:04X}".format(b.BPB_RootEntCnt))

		if b.BPB_TotSec16 == 0 and b.BPB_TotSec32 == 0:
			yield (_INVALID, "Invalid sector count: Both BPB_TotSec16 and BPB_TotSec32 are zero")

		if self._total_sector_count != self._geometry.total_sector_count():
			expect = self._geometry.total_sector_count()
			reported = self._total_sector_count
			sign, level = (reported > expect) and ('>', _INVALID) or ('<', _UNCOMMON)
			yield (level, "Reported sector count {1} Geometry sector count (0x{0:08X} {1} 0x{2:08X})".format(reported, sign, expect))

		for cutover_count in _FAT_TYPE_CLUSTER_COUNT_CUTOVERS:
			diff = cutover_count - self._cluster_count
			if -16 < diff < 16:
				yield (_UNCOMMON, "Cluster count {0} is close to cutover value {1}".format(self._cluster_count, cutover_count))
				break

		if b.BPB_Media not in _VALID_MEDIA_BYTE:
			yield (_INVALID, "Invalid BPB_Media: 0x{0:02X}".format(b.BPB_Media))
		# TODO: should equal the first byte of FAT

		if b.BPB_FATSz16 == 0 and b32.BPB_FATSz32 == 0:
			yield (_INVALID, "Invalid FAT size: Both BPB_FATSz16 and BPB_FATSz32 are zero")

		if b.BPB_SecPerTrk != self._geometry.sectors:
			yield (_UNCOMMON, "Sector per track mismatch (read=0x{0:04X}, geometry=0x{1:04X})".format(b.BPB_SecPerTrk, self._geometry.sectors))
		if b.BPB_NumHeads != self._geometry.heads:
			yield (_UNCOMMON, "Head count mismatch (read=0x{0:04X}, geometry=0x{1:04X})".format(b.BPB_NumHeads, self._geometry.heads))

		if self.fat_type == FATVolume.FAT32:
			diag_iter = self._chkdsk32()
		else:
			diag_iter = self._chkdsk16()

		for message in diag_iter:
			yield message

		self._seek_sector(0, 510)
		sig = self._read(2)
		if sig != _FAT_SIG:
			yield (_INVALID, "No signature at byte 0x1FE: {0} (should be {1})".format(_hexdump(sig), _hexdump(_FAT_SIG)))


	def _chkdsk16(self):
		b = self._bpb
		b16 = self._bpb16

		if b.BPB_RsvdSecCnt != 1:
			yield (_INVALID, "Invalid BPB_RsvdSecCnt for {0}: 0x{1:04X}".format(self.fat_type, b.BPB_RsvdSecCnt))

		if b.BPB_RootEntCnt not in (0x0E0, 0x200):
			yield (_UNCOMMON, "Uncommon BPB_RootEntCnt for {0}: 0x{1:04X}".format(self.fat_type, b.BPB_RootEntCnt))

		if b.BPB_FATSz16 == 0:
			yield (_INVALID, "Invalid FAT size for {0}: 0x{1:04X}".format(self.fat_type, b.BPB_FATSz16))

		if b16.BS_DrvNum == 0x00:
			if b.BPB_Media != 0xF0:
				yield (_UNCOMMON, "BS_DrvNum is floppy but BPB_Media is not removable")
			if b.BPB_HiddSec != 0:
				yield (_INVALID, "Invalid BPB_HiddSec for non-partitioned media: 0x{0:04X}".format(b.BPB_HiddSec))
		elif b16.BS_DrvNum == 0x80 and b.BPB_Media == 0xF0:
			yield (_UNCOMMON, "BS_DrvNum is fixed but BPB_Media is removable")

		for message in self._chkdsk_bpbx(b16):
			yield message


	def _chkdsk32(self):
		b = self._bpb
		b32 = self._bpb32

		if b.BPB_RsvdSecCnt != 32:
			yield (_UNCOMMON, "Uncommon BPB_RsvdSecCnt for {0}: 0x{1:04X}".format(self.fat_type, b.BPB_RsvdSecCnt))

		if b.BPB_RootEntCnt != 0:
			yield (_INVALID, "Invalid BPB_RootEntCnt for {0}: 0x{1:04X}".format(self.fat_type, b.BPB_RootEntCnt))

		if b.BPB_FATSz16 != 0:
			yield (_INVALID, "BPB_FATSz16 must be zero for {0}: 0x{1:04X}".format(self.fat_type, b.BPB_FATSz16))

		if b32.BPB_FATSz32 == 0:
			yield (_INVALID, "Invalid BPB_FATSz32 for {0}: 0x{1:08X}".format(self.fat_type, b32.BPB_FATSz32))

		if (b32.BPB_ExtFlags & 0b1111111101110000) != 0:
			yield (_UNCOMMON, "Reserved bits in BPB_ExtFlags are set: 0x{0:04X} ({0:016b})".format(b32.BPB_ExtFlags))

		if b32.BPB_FSVer != 0:
			yield (_INVALID, "Unsupported BPB_FSVer: 0x{0:04X}".format(b32.BPB_FSVer))

		if b32.BPB_RootClus != 2:
			yield (_UNCOMMON, "Uncommon BPB_RootClus: 0x{0:08X}".format(b32.BPB_RootClus))

		if b32.BPB_FSInfo != 1:
			yield (_UNCOMMON, "Uncommon BPB_FSInfo: 0x{0:08X}".format(b32.BPB_FSInfo))

		if b32.BPB_BkBootSec != 6:
			yield (_UNCOMMON, "Uncommon BPB_BkBootSec: 0x{0:08X}".format(b32.BPB_BkBootSec))

		if b32.BPB_Reserved != '\0' * 12:
			yield (_UNCOMMON, "Non-zero bytes in BPB_Reserved: {0!r}".format(_hexdump(b32.BPB_Reserved)))

		for message in self._chkdsk_bpbx(b32):
			yield message


	def _chkdsk_bpbx(self, bx):
		if bx.BS_DrvNum not in _VALID_DRIVE_NUM:
			yield (_INVALID, "Invalid BS_DrvNum: 0x{0:02X}".format(bx.BS_DrvNum))

		if bx.BS_Reserved1 != 0:
			yield (_UNCOMMON, "Nonzero BS_Reserved1: 0x{0:02X}".format(bx.BS_Reserved1))

		_bs_level = _UNCOMMON
		if bx.BS_BootSig != 0x29:
			yield (_INFO, "BS_VolID, BS_VolLab, BS_FilSysType not present")
			_bs_level = _INFO

		# TODO: check bx.BS_VolLab against what the root dir thinks it is

		fstype_ok = False
		if self.fat_type == FATVolume.FAT32:
			fstype_ok = bx.BS_FilSysType == "FAT32   "
		elif bx.BS_FilSysType == "FAT     ":
			fstype_ok = True
		elif self.fat_type == FATVolume.FAT16:
			fstype_ok = bx.BS_FilSysType == "FAT16   "
		else:
			fstype_ok = bx.BS_FilSysType == "FAT12   "

		if not fstype_ok:
			yield (_bs_level, "BS_FilSysType doesn't match determined filesystem type of {0}: {1!r}".format(self.fat_type, bx.BS_FilSysType))


	def _seek_sector(self, sector, byte=0):
		self._stream.seek(sector * self._geometry.sector_size + byte)

	def _read(self, byte_count):
		return self._stream.read(byte_count)

	def _read_bpb(self):
		self._seek_sector(0)

		self._bpb = BiosParameterBlock.from_stream(self._stream)

		# TODO: at the moment we're using the value from the boot sector
		# but we should probably take this from self._geometry instead if
		# we'll be dealing with bad boot sectors
		self._bytes_per_sector = self._bpb.BPB_BytsPerSec

		bpbx_union = self._read(max(
			BiosParameterBlock16.size(), BiosParameterBlock32.size()))

		self._bpb16 = BiosParameterBlock16(bpbx_union[:BiosParameterBlock16.size()])
		self._bpb32 = BiosParameterBlock32(bpbx_union[:BiosParameterBlock32.size()])

		self._root_dir_sector_count = self._calc_root_dir_sector_count()
		self._fat_sector_count = self._calc_fat_sector_count()

		# may want to use geometry here too
		self._total_sector_count = self._calc_total_sector_count()

		self._first_data_sector = self._calc_first_data_sector()
		self._data_sector_count = self._calc_data_sector_count()

		self._cluster_count = 0
		if self._bpb.BPB_SecPerClus > 0:
			self._cluster_count = self._data_sector_count / self._bpb.BPB_SecPerClus

		self.fat_type = self._determine_fat_type()

	def _calc_root_dir_sector_count(self):
		b = self._bpb
		# RootDirSectorCount = ceil(
		#   ((BPB_RootEntCnt * 32) + (BPB_BytsPerSec - 1)) / BPB_BytsPerSec
		# )
		if b.BPB_RootEntCnt == 0:
			return 0

		bytes = (b.BPB_RootEntCnt * 32) + (self._bytes_per_sector - 1)
		return int(math.ceil(float(bytes) / self._bytes_per_sector))

	def _calc_fat_sector_count(self):
		if self._bpb.BPB_FATSz16 != 0:
			return self._bpb.BPB_FATSz16
		return self._bpb32.BPB_FATSz32

	def _calc_total_sector_count(self):
		if self._bpb.BPB_TotSec16 != 0:
			return self._bpb.BPB_TotSec16
		return self._bpb.BPB_TotSec32

	def _calc_first_data_sector(self):
		b = self._bpb
		return (
			b.BPB_RsvdSecCnt + b.BPB_NumFATs * self._fat_sector_count +
			self._root_dir_sector_count
		)

	def _calc_data_sector_count(self):
		return self._total_sector_count - self._calc_first_data_sector()

	def _first_sector_of_cluster(self, n):
		return (n - 2) * self._bpb.BPB_SecPerClus + self._first_data_sector

	def _determine_fat_type(self):
		if self._cluster_count < 4085:
			return FATVolume.FAT12
		elif self._cluster_count < 65525:
			return FATVolume.FAT16
		return FATVolume.FAT32
