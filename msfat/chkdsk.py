from ctypes import sizeof
import calendar
import operator
import re
import string


from msfat import TYPE_FAT12, TYPE_FAT16, TYPE_FAT32, \
	ATTR_VOLUME_ID, ATTR_VALID_MASK, ATTR_RESERVED_MASK, \
	MediaError, _inline_hexdump, _bytes_to_str

from msfat.dir import FATDirEntry, assemble_long_entries, is_valid_short_name, \
	is_valid_long_name, is_long_name_correctly_padded, THISDIR_NAME, \
	UPDIR_NAME, unpack_fat_date, unpack_fat_time


# Log levels match values of equivalent severity in python logging module
# Short names privately...
_INVALID = 40
_UNCOMMON = 30
_INFO = 20

# ...long names publicly
CHKDSK_LOG_INVALID = _INVALID
CHKDSK_LOG_UNCOMMON = _UNCOMMON
CHKDSK_LOG_INFO = _INFO


# need to add 2 as the formatter counts the 0x prefix as part of the width
_FMT_U32 = "#010x"
_FMT_U16 = "#06x"
_FMT_U8 =  "#04x"


_MAX_CLUSTER_BYTES = 0x8000

_MEDIA_BYTE_REMOVABLE = 0xF0
_VALID_MEDIA_BYTE = (_MEDIA_BYTE_REMOVABLE,) + tuple(xrange(0xF8, 0x100))

_DRIVE_NUM_REMOVABLE = 0x00
_DRIVE_NUM_FIXED = 0x80
_VALID_DRIVE_NUM = (_DRIVE_NUM_REMOVABLE, _DRIVE_NUM_FIXED)

_FAT_TYPE_CLUSTER_COUNT_CUTOVER_VALUES = (4085, 65525)
_VALID_BYTES_PER_SECTOR = tuple(1 << n for n in xrange(9, 13))
_VALID_SECTORS_PER_CLUSTER = tuple(1 << n for n in xrange(0, 8))

_FAT32_BPB_EXTFLAGS_RESERVED_BITS = 0b1111111101110000

# fat32 can't have clusters whose number >= the fat32 bad cluster marker.
# the max cluster number is 0x0FFFFFF6. when compensating for the lowest
# cluster num being 2, the max COUNT is 0x0FFFFFF5
_FAT32_MAX_ALLOWED_CLUSTER_COUNT = 0x0FFFFFF5

_EXT_BOOTSIG = 0x29

_FAT_SIG_OFFSET = 510
_FAT_SIG = "\x55\xAA"

_NULL_DIR_ENTRY = '\0' * sizeof(FATDirEntry)

_TYPES_TO_XBSTYPE = {
	TYPE_FAT32: ("FAT32   ",),
	TYPE_FAT16: ("FAT16   ", "FAT     "),
	TYPE_FAT12: ("FAT12   ", "FAT     ")
}


def chkdsk(volume, user_log_func):
	_ChkDsk(volume, user_log_func).run()


def _is_common_jmpboot(bytes):
	return (bytes[0] == 0xEB and bytes[2] == 0x90) or bytes[0] == 0xE9


class _ChkDskFormatter(string.Formatter):
	def convert_field(self, value, conversion):
		if conversion == 'h':
			return _inline_hexdump(value)
		elif conversion == 'b':
			return repr(_bytes_to_str(value))
		else:
			return string.Formatter.convert_field(self, value, conversion)


class _ChkDskLogger(object):
	def __init__(self, user_log_func, **kwargs):
		self._user_log_func = user_log_func
		self._default_format_dict = kwargs
		self._formatter = _ChkDskFormatter()

		self.leveled_log_funcs = (self.info, self.uncommon, self.invalid)

	def log(self, level, template, *args, **kwargs):
		# slow but whatever
		if kwargs:
			format_dict = dict(self._default_format_dict, **kwargs)
		else:
			format_dict = self._default_format_dict

		message = self._formatter.vformat(template, args, format_dict)
		self._user_log_func(level, re.sub("\s+", " ", message.strip()))

	def info(self, template, *args, **kwargs):
		self.log(_INFO, template, *args, **kwargs)

	def uncommon(self, template, *args, **kwargs):
		self.log(_UNCOMMON, template, *args, **kwargs)

	def invalid(self, template, *args, **kwargs):
		self.log(_INVALID, template, *args, **kwargs)


class _NamedValue(object):
	def __init__(self, name, value, format=""):
		self.name = name
		self.value = value
		self.format = format

	def __str__(self):
		# TODO: i dunno
		return unicode(self).encode("ascii", "replace")

	def __unicode__(self):
		return format(self.value, self.format)

	def __format__(self, format_spec):
		return format(self.value, format_spec or self.format)


def _check_contains(query_set, named_value, log_func):
	if named_value.value not in query_set:
		log_func("Invalid {nv.name} ({nv})", nv=named_value)


def _check_binary_cmp(bin_bool_func, opposite_string):
	def check_func(named_value_a, named_value_b, log_func):
		if not bin_bool_func(named_value_a.value, named_value_b.value):
			log_func("{a.name} ({a}) {opposite_string} {b.name} ({b})",
				a=named_value_a, b=named_value_b,
				opposite_string=opposite_string)
			return False
		return True
	return check_func

_check_eq = _check_binary_cmp(operator.eq, "not equal to")
_check_lt = _check_binary_cmp(operator.lt, "greater than or equal to")
_check_le = _check_binary_cmp(operator.le, "greater than")
_check_gt = _check_binary_cmp(operator.gt, "less than or equal to")
_check_ge = _check_binary_cmp(operator.ge, "less than")


def _check_eq_nonzero_const(got_named_value, expected_value, unequal_log_func, zero_log_func):
	if got_named_value.value == 0:
		zero_log_func("{gv.name} is zero", gv=got_named_value)
	elif got_named_value.value != expected_value:
		unequal_log_func(
			"{gv.name} ({gv}) should be {ev}",
			gv=got_named_value, ev=expected_value
		)


class _ChkDsk(object):
	def __init__(self, volume, user_log_func):
		self.volume = volume
		self.geometry = volume._geometry
		self.bpb = volume._bpb
		self.bpb16 = volume._bpb.fat16
		self.bpb32 = volume._bpb.fat32
		self.bpbx = volume.fat_type == TYPE_FAT32 and self.bpb32 or self.bpb16

		self.log = _ChkDskLogger(
			user_log_func,
			volume=  self.volume,
			geometry=self.geometry,
			bpb=     self.bpb,
			bpb16=   self.bpb16,
			bpb32=   self.bpb32,
			bpbx=    self.bpbx
		)


	def run(self):
		self._check_common()
		if self.volume.fat_type == TYPE_FAT32:
			self._check_bpb32()
		else:
			self._check_bpb16()
		self._check_bpbx()
		self._check_sig()
		self._check_fat_size()
		self._check_fats()


	def _check_common(self):
		if not _is_common_jmpboot(self.bpb.BS_jmpBoot):
			self.log.uncommon("Uncommon BS_jmpBoot: {bpb.BS_jmpBoot!h}")
		
		self.log.info("BS_OEMName: {bpb.BS_OEMName!b}")

		_check_contains(
			_VALID_BYTES_PER_SECTOR,
			_NamedValue("BPB_BytsPerSec", self.bpb.BPB_BytsPerSec, _FMT_U16),
			self.log.invalid
		)

		_check_eq(
			_NamedValue("BPB_BytsPerSec", self.bpb.BPB_BytsPerSec, _FMT_U16),
			_NamedValue("geometry.sector_size", self.geometry.sector_size, _FMT_U16),
			self.log.invalid
		)

		_check_contains(
			_VALID_SECTORS_PER_CLUSTER,
			_NamedValue("BPB_SecPerClus", self.bpb.BPB_SecPerClus, _FMT_U8),
			self.log.invalid
		)

		if self.bpb.BPB_BytsPerSec * self.bpb.BPB_SecPerClus > _MAX_CLUSTER_BYTES:
			self.log.invalid("Calculated bytes per cluster exceeds {0}", _MAX_CLUSTER_BYTES)

		_check_eq_nonzero_const(
			_NamedValue("BPB_NumFATs", self.bpb.BPB_NumFATs, _FMT_U8),
			2, self.log.uncommon, self.log.invalid
		)

		if self.bpb.BPB_BytsPerSec > 0 and (self.bpb.BPB_RootEntCnt * 32) % self.bpb.BPB_BytsPerSec != 0:
			self.log.invalid("BPB_RootEntCnt of {bpb.BPB_RootEntCnt:#06x} does not fill sectors evenly")

		if self.volume._root_dir_sector_count > self.volume._total_sector_count:
			self.log.invalid("""BPB_RootEntCnt of {bpb.BPB_RootEntCnt:#06x}
				exceeds volume sector count
				({volume._root_dir_sector_count:#010x} sectors >
				{volume._total_sector_count:#010x} sectors)""")

		if self.bpb.BPB_TotSec16 == 0 and self.bpb.BPB_TotSec32 == 0:
			self.log.invalid("Invalid sector count: Both BPB_TotSec16 and BPB_TotSec32 are zero")

		if self.volume._total_sector_count != self.geometry.total_sector_count():
			geom_value = self.geometry.total_sector_count()
			bpb_value = self.volume._total_sector_count
			sign, log_func = (bpb_value > geom_val) and ('>', self.log.invalid) or ('<', self.log.uncommon)
			log_func("""BPB sector count {sign} Geometry sector count
				({bpb_value:#010x} {sign} {geom_value:#010x})""",
				sign=sign, bpb_value=bpb_value, geom_value=geom_value
			)

		for cutover_value in _FAT_TYPE_CLUSTER_COUNT_CUTOVER_VALUES:
			diff = cutover_value - self.volume._cluster_count
			if -16 < diff < 16:
				self.log.uncommon("Cluster count {volume._cluster_count} is close to cutover value {cv}", cv=cutover_value)
				break

		_check_contains(
			_VALID_MEDIA_BYTE,
			_NamedValue("BPB_Media", self.bpb.BPB_Media, _FMT_U8),
			self.log.invalid
		)

		if self.bpb.BPB_FATSz16 == 0 and self.bpb32.BPB_FATSz32 == 0:
			self.log.invalid("Invalid FAT size: Both BPB_FATSz16 and BPB_FATSz32 are zero")

		named_total_sectors = _NamedValue("volume sector count", self.volume._total_sector_count, _FMT_U32)

		if _check_le(
			_NamedValue("Single FAT sector count", self.volume._fat_sector_count, _FMT_U32),
			named_total_sectors,
			self.log.invalid
		):
			_check_le(
				_NamedValue("Total FAT sector count", self.bpb.BPB_NumFATs * self.volume._fat_sector_count, _FMT_U32),
				named_total_sectors,
				self.log.invalid
			)

		_check_le(
			_NamedValue("BPB_RsvdSecCnt", self.bpb.BPB_RsvdSecCnt, _FMT_U16),
			named_total_sectors,
			self.log.invalid
		)

		_check_lt(
			_NamedValue("Data start sector", self.volume._data_sector_start, _FMT_U32),
			named_total_sectors,
			self.log.invalid
		)

		_check_eq(
			_NamedValue("BPB_SecPerTrk", self.bpb.BPB_SecPerTrk, _FMT_U16),
			_NamedValue("Geometry sector count", self.geometry.sectors, _FMT_U16),
			self.log.uncommon
		)

		_check_eq(
			_NamedValue("BPB_NumHeads", self.bpb.BPB_NumHeads, _FMT_U16),
			_NamedValue("Geometry head count", self.geometry.heads, _FMT_U16),
			self.log.uncommon
		)

		if self.bpb.BPB_HiddSec != 0:
			if self.bpb.BPB_Media == _MEDIA_BYTE_REMOVABLE:
				self.log.invalid("""BPB_HiddSec must be zero on non-partitioned
					media ({bpb.BPB_HiddSec:#010x})""")


	def _check_bpb16(self):
		if self.bpb.BPB_RsvdSecCnt != 1:
			self.log.invalid("Invalid BPB_RsvdSecCnt for {volume.fat_type}: {bpb.BPB_RsvdSecCnt:#06x}")

		if self.bpb.BPB_RootEntCnt == 0:
			self.log.invalid("Zero BPB_RootEntCnt is invalid for {volume.fat_type} volumes")

		if self.bpb.BPB_FATSz16 == 0:
			self.log.invalid("Zero BPB_FATSz16 is invalid for {volume.fat_type} volumes")

		if self.bpb16.BS_DrvNum == _DRIVE_NUM_REMOVABLE:
			if self.bpb.BPB_Media != _MEDIA_BYTE_REMOVABLE:
				self.log.uncommon("""BS_DrvNum is floppy ({bpb16.BS_DrvNum:#04x})
					but BPB_Media is not removable (got {bpb.BPB_Media:#04x},
					should be {expected:#04x})""", expected=_MEDIA_BYTE_REMOVABLE)

		elif self.bpb16.BS_DrvNum == _DRIVE_NUM_FIXED and self.bpb.BPB_Media == _MEDIA_BYTE_REMOVABLE:
			self.log.uncommon("""BS_DrvNum is fixed ({bpb16.BS_DrvNum:#04x})
				but BPB_Media is removable (\{bpb.BPB_Media:#04x})""")


	def _check_bpb32(self):
		_check_eq_nonzero_const(
			_NamedValue("BPB_RsvdSecCnt", self.bpb.BPB_RsvdSecCnt, _FMT_U16),
			32, self.log.uncommon, self.log.invalid
		)

		if self.bpb.BPB_RootEntCnt != 0:
			self.log.invalid("""Non-zero BPB_RootEntCnt is invalid for
				{volume.fat_type} volumes (got {bpb.BPB_RootEntCnt:#06x})""")

		if self.bpb.BPB_FATSz16 != 0:
			self.log.invalid("""Non-zero BPB_FATSz16 is invalid for
				{volume.fat_type} volumes (got {bpb.BPB_FATSz16:#06x})""")

		if self.bpb.BPB_FATSz32 == 0:
			self.log.invalid("Zero BPB_FATSz32 is invalid for {volume.fat_type} volumes")

		if (sefl.bpb32.BPB_ExtFlags & _FAT32_BPB_EXTFLAGS_RESERVED_BITS) != 0:
			self.log.uncommon("""Reserved bits in BPB_ExtFlags are set:
				{bpb32.BPB_ExtFlags:#06x} ({bpb32.BPB_ExtFlags:#016b})""")

		if self.bpb32.BPB_FSVer == 0:
			self.log.invalid("Unsupported BPB_FSVer: {bpb32.BPB_FSVer:#06x}")

		_check_eq_nonzero_const(
			_NamedValue("BPB_RootClus", self.bpb32.BPB_RootClus, _FMT_U32),
			2, self.log.uncommon, self.log.invalid
		)

		_check_eq_nonzero_const(
			_NamedValue("BPB_FSInfo", self.bpb32.BPB_FSInfo, _FMT_U32),
			1, self.log.uncommon, self.log.invalid
		)

		_check_eq_nonzero_const(
			_NamedValue("BPB_BkBootSec", self.bpb32.BPB_BkBootSec, _FMT_U32),
			6, self.log.uncommon, self.log.invalid
		)

		if _bytes_to_str(self.bpb32.BPB_Reserved) != '\0' * 12:
			self.log.uncommon("Non-zero bytes in BPB_Reserved {bpb32.BPB_Reserved!h}")

		if self.volume._cluster_count > _FAT32_MAX_ALLOWED_CLUSTER_COUNT:
			self.log.invalid("""Cluster count exceeds maximum allowed for
				{volume.fat_type} volumes: {volumes._cluster_count:#010x} >
				{maximum:#010x}""",
				maximum=_FAT32_MAX_ALLOWED_CLUSTER_COUNT)


	def _check_bpbx(self):
		_check_contains(
			_VALID_DRIVE_NUM,
			_NamedValue("BS_DrvNum", self.bpbx.BS_DrvNum, _FMT_U8),
			self.log.invalid
		)

		if self.bpbx.BS_Reserved1 != 0:
			self.log.uncommon("Nonzero BS_Reserved1: {bpbx.BS_Reserved1:#04x}")

		xbs_log_func = self.log.uncommon
		if self.bpbx.BS_BootSig != _EXT_BOOTSIG:
			self.log.info("BS_VolID, BS_VolLab, BS_FilSysType not present")
			xbs_log_func = self.log.info

		# TODO: check self.bpbx.BS_VolLab against what the root dir thinks it is
		self.log.info("BS_VolID is {bpbx.BS_VolID:#010x}")
		self.log.info("BS_VolLab is {bpbx.BS_VolLab!b}")

		fstype_str = _bytes_to_str(self.bpbx.BS_FilSysType)
		if fstype_str not in _TYPES_TO_XBSTYPE[self.volume.fat_type]:
			xbs_log_func("""BS_FilSysType doesn't match determined filesystem
				type of {volume.fat_type}: {bpbx.BS_FilSysType!b}""")


	def _check_sig(self):
		self.volume._seek_sector(0, _FAT_SIG_OFFSET)
		sig = self.volume._read(2)
		if sig != _FAT_SIG:
			self.log.invalid("""No signature at byte {offset:#06x}:
				{got!h} (should be {expect!h})""",
				offset=_FAT_SIG_OFFSET, got=sig, expect=_FAT_SIG)


	def _check_fat_size(self):
		# checking it this way is an easier way of accounting for the chance
		# of the last FAT12 entry running into the next sector. i don't know
		# if this ever happens
		max_fat_sector, max_fat_byte = self.volume._get_fat_offset(self.volume._max_cluster_num + 1)
		required_sectors = max_fat_sector
		if max_fat_byte != 0:
			required_sectors += 1

		if self.volume._cluster_count > 0 and self.volume._fat_sector_count > required_sectors:
			self.log.uncommon("""FAT size ({volume._fat_sector_count:#010x}
				sectors) is larger than necessary. The minimum required for
				{volume._cluster_count:#010x} clusters is
				{required_sectors:#010x} sectors.""",
				required_sectors=required_sectors
			)


	def _check_fats(self):
		prev_active_fat = self.volume.active_fat_index
		
		for fat_index in xrange(self.bpb.BPB_NumFATs):
			self.volume.active_fat_index = fat_index
			if self.volume._calc_fat_sector_start() >= self.geometry.total_sector_count():
				self.log.invalid("""Canceling FAT check at FAT[{stop_index}]: First
					sector of this FAT exceeds volume sector count""",
					stop_index=fat_index)
				break

			try:
				self._check_lowfat()
				self._check_highfat()

			except MediaError as me:
				self.log.invalid("Error while checking FAT[{index}]: {exc!s}",
					index=fat_index, exc=me)

		self.volume.active_fat_index = prev_active_fat


	def _check_lowfat(self):
		expect_fat0 = 0x0F00 | self.bpb.BPB_Media

		fat1_check_mask = 0x0FFF
		fat1_clean = 0
		fat_value_type = _FMT_U8

		if self.volume.fat_type == TYPE_FAT32:
			fat1_check_mask = 0x03FFFFFF
			fat1_clean =      0x08000000
			fat1_harderror =  0x04000000
			fat_value_type = _FMT_U32

		elif self.volume.fat_type == TYPE_FAT16:
			fat1_check_mask = 0x3FFF
			fat1_clean =      0x8000
			fat1_harderror =  0x4000
			fat_value_type = _FMT_U16

		actual_fat0 = self.volume._get_fat_entry(0)
		_check_eq(
			_NamedValue("FAT[{0}][0]".format(self.volume.active_fat_index), actual_fat0, fat_value_type),
			_NamedValue("expected value", expect_fat0, fat_value_type),
			self.log.invalid
		)

		actual_fat1 = self.volume._get_fat_entry(1)
		_check_ge(
			_NamedValue(
				"FAT[{0}][1] low bits".format(self.volume.active_fat_index),
				actual_fat1 & fat1_check_mask,
				fat_value_type
			),
			_NamedValue(
				"{0} EOC".format(self.volume.fat_type),
				self.volume._fat_eoc & fat1_check_mask,
				fat_value_type
			),
			self.log.invalid
		)

		if fat1_clean:
			if (actual_fat1 & fat1_clean) == 0:
				self.log.info("FAT[{volume.active_fat_index}] reports volume is marked as dirty")
			if (actual_fat1 & fat1_harderror) == 0:
				self.log.info("FAT[{volume.active_fat_index}] reports volume encountered hard errors at last mount")


	def _check_highfat(self):
		nonzeroes = 0

		start_sector, start_byte = self.volume._get_fat_address(self.volume._max_cluster_num + 1)

		# this is the first invalid, not the last valid
		# so feeding it to xrange is correct
		end_sector = self.volume._calc_fat_sector_start() + self.volume._fat_sector_count

		for current_sector in xrange(start_sector, end_sector):
			sec = self.volume._read_sector(current_sector)
			for b in xrange(start_byte, self.volume._bytes_per_sector):
				if sec[b] != '\0':
					nonzeroes += 1

			start_byte = 0

		if nonzeroes > 0:
			self.log.info("FAT[{volume.active_fat_index}] has non-zero data in its unused area")
