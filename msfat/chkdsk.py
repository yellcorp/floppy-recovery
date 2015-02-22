from msfat import TYPE_FAT12, TYPE_FAT16, TYPE_FAT32, \
	_inline_hexdump, _bytes_to_str


# Log levels match values of equivalent severity in python logging module
# Short names privately...
_INVALID = 40
_UNCOMMON = 30
_INFO = 20

# ...long names publicly
CHKDSK_LOG_INVALID = _INVALID
CHKDSK_LOG_UNCOMMON = _UNCOMMON
CHKDSK_LOG_INFO = _INFO


_VALID_MEDIA_BYTE = (0xF0,) + tuple(xrange(0xF8, 0x100))
_VALID_DRIVE_NUM = (0x00, 0x80)
_FAT_TYPE_CLUSTER_COUNT_CUTOVERS = (4085, 65525)
_VALID_BYTES_PER_SECTOR = tuple(1 << n for n in xrange(9, 13))
_VALID_SECTORS_PER_CLUSTER = tuple(1 << n for n in xrange(0, 8))
_FAT_SIG = "\x55\xAA"

# fat32 can't have clusters whose number >= the fat32 bad cluster marker.
# the max cluster number is 0x0FFFFFF6. when compensating for the lowest
# cluster num being 2, the max COUNT is 0x0FFFFFF5
_FAT32_MAX_ALLOWED_CLUSTER_COUNT = 0x0FFFFFF5


def _is_common_jmpboot(bytes):
	return (bytes[0] == 0xEB and bytes[2] == 0x90) or bytes[0] == 0xE9


def chkdsk(volume):
	v = volume
	b = v._bpb
	b16 = b.fat16
	b32 = b.fat32

	if not _is_common_jmpboot(b.BS_jmpBoot):
		yield (_UNCOMMON, "Uncommon BS_jmpBoot: {0}".format(_inline_hexdump(b.BS_jmpBoot)))

	yield (_INFO, "BS_OEMName: {0!r}".format(_bytes_to_str(b.BS_OEMName)))

	if b.BPB_BytsPerSec not in _VALID_BYTES_PER_SECTOR:
		yield (_INVALID, "Invalid BPB_BytsPerSec: 0x{0:04X}".format(b.BPB_BytsPerSec))

	if b.BPB_BytsPerSec != v._geometry.sector_size:
		yield (_INVALID, "Bytes per sector mismatch (read=0x{0:04X}, geometry=0x{1:04X})".format(b.BPB_BytsPerSec, v._geometry.sector_size))

	if b.BPB_SecPerClus not in _VALID_SECTORS_PER_CLUSTER:
		yield (_INVALID, "Invalid BPB_SecPerClus: 0x{0:02X}".format(b.BPB_SecPerClus))

	if b.BPB_NumFATs == 0:
		yield (_INVALID, "Invalid BPB_NumFATs: 0x{0:02X}".format(b.BPB_NumFATs))
	elif b.BPB_NumFATs != 2:
		yield (_UNCOMMON, "Uncommon BPB_NumFATs: 0x{0:02X}".format(b.BPB_NumFATs))

	if b.BPB_BytsPerSec > 0 and (b.BPB_RootEntCnt * 32) % b.BPB_BytsPerSec != 0:
		yield (_INVALID, "BPB_RootEntCnt of 0x{0:04X} does not fill sectors evenly".format(b.BPB_RootEntCnt))

	if v._root_dir_sector_count > v._total_sector_count:
		yield (_INVALID, "BPB_RootEntCnt of 0x{0:04X} exceeds volume sector count ({0:04X} sectors > {1:04X} sectors)".format(v._root_dir_sector_count, v._total_sector_count))

	if b.BPB_TotSec16 == 0 and b.BPB_TotSec32 == 0:
		yield (_INVALID, "Invalid sector count: Both BPB_TotSec16 and BPB_TotSec32 are zero")

	if v._total_sector_count != v._geometry.total_sector_count():
		expect = v._geometry.total_sector_count()
		reported = v._total_sector_count
		sign, level = (reported > expect) and ('>', _INVALID) or ('<', _UNCOMMON)
		yield (level, "Reported sector count {1} Geometry sector count (0x{0:08X} {1} 0x{2:08X})".format(reported, sign, expect))

	for cutover_count in _FAT_TYPE_CLUSTER_COUNT_CUTOVERS:
		diff = cutover_count - v._cluster_count
		if -16 < diff < 16:
			yield (_UNCOMMON, "Cluster count {0} is close to cutover value {1}".format(v._cluster_count, cutover_count))
			break

	if b.BPB_Media not in _VALID_MEDIA_BYTE:
		yield (_INVALID, "Invalid BPB_Media: 0x{0:02X}".format(b.BPB_Media))

	if b.BPB_FATSz16 == 0 and b32.BPB_FATSz32 == 0:
		yield (_INVALID, "Invalid FAT size: Both BPB_FATSz16 and BPB_FATSz32 are zero")

	if v._fat_sector_count > v._total_sector_count:
		yield (_INVALID, "Single FAT sector count exceeds volume sector count ({0:04X} > {1:04X})".format(v._fat_sector_count, v._total_sector_count))
	elif b.BPB_NumFATs * v._fat_sector_count > v._total_sector_count:
		yield (
			_INVALID,
			"{0} copies of FAT exceeds volume sector count ({1:04X} > {2:04X})".format(
				b.BPB_NumFATs,
				b.BPB_NumFATs * v._fat_sector_count,
				v._total_sector_count
			)
		)

	if b.BPB_RsvdSecCnt > v._total_sector_count:
		yield (_INVALID, "BPB_RsvdSecCnt exceeds volume sector count ({0:04X} > {1:04X})".format(b.BPB_RsvdSecCnt, v._total_sector_count))

	if v._data_sector_start >= v._total_sector_count:
		yield (_INVALID, "Data area begins beyond volume capacity ({0:04X} >= {1:04X})".format(v._data_sector_start, v._total_sector_count))

	if b.BPB_SecPerTrk != v._geometry.sectors:
		yield (_UNCOMMON, "Sector per track mismatch (read=0x{0:04X}, geometry=0x{1:04X})".format(b.BPB_SecPerTrk, v._geometry.sectors))
	if b.BPB_NumHeads != v._geometry.heads:
		yield (_UNCOMMON, "Head count mismatch (read=0x{0:04X}, geometry=0x{1:04X})".format(b.BPB_NumHeads, v._geometry.heads))

	if v.fat_type == TYPE_FAT32:
		diag_iter = _chkdsk32(v)
	else:
		diag_iter = _chkdsk16(v)

	for message in diag_iter:
		yield message

	v._seek_sector(0, 510)
	sig = v._read(2)
	if sig != _FAT_SIG:
		yield (_INVALID, "No signature at byte 0x1FE: {0} (should be {1})".format(_inline_hexdump(sig), _inline_hexdump(_FAT_SIG)))

	# checking it this way is an easier way of accounting for the chance
	# of the last FAT12 entry running into the next sector. i don't know
	# if this ever happens
	max_fat_sector, max_fat_byte = v._get_fat_offset(v._max_cluster_num + 1)
	required_sectors = max_fat_sector
	if max_fat_byte != 0:
		required_sectors += 1

	if v._cluster_count > 0: # Don't do this check for garbaged cluster counts
		if v._fat_sector_count > required_sectors:
			yield (
				_UNCOMMON,
				"FAT(s) occupy more sectors ({0}) than necessary. The minimum required for {1} clusters is {2}.".format(
					v._fat_sector_count,
					v._cluster_count,
					required_sectors
				)
			)

	for message in _chkdsk_fat(v):
		yield message


def _chkdsk16(v):
	b = v._bpb
	b16 = b.fat16

	if b.BPB_RsvdSecCnt != 1:
		yield (_INVALID, "Invalid BPB_RsvdSecCnt for {0}: 0x{1:04X}".format(v.fat_type, b.BPB_RsvdSecCnt))

	if b.BPB_RootEntCnt == 0:
		yield (_INVALID, "Invalid BPB_RootEntCnt for {0}: 0x{1:04X}".format(v.fat_type, b.BPB_RootEntCnt))
	elif b.BPB_RootEntCnt not in (0x0E0, 0x200):
		yield (_UNCOMMON, "Uncommon BPB_RootEntCnt for {0}: 0x{1:04X}".format(v.fat_type, b.BPB_RootEntCnt))

	if b.BPB_FATSz16 == 0:
		yield (_INVALID, "Invalid FAT size for {0}: 0x{1:04X}".format(v.fat_type, b.BPB_FATSz16))

	if b16.BS_DrvNum == 0x00:
		if b.BPB_Media != 0xF0:
			yield (_UNCOMMON, "BS_DrvNum is floppy but BPB_Media is not removable")
		if b.BPB_HiddSec != 0:
			yield (_INVALID, "Invalid BPB_HiddSec for non-partitioned media: 0x{0:04X}".format(b.BPB_HiddSec))
	elif b16.BS_DrvNum == 0x80 and b.BPB_Media == 0xF0:
		yield (_UNCOMMON, "BS_DrvNum is fixed but BPB_Media is removable")

	for message in _chkdsk_bpbx_common(v, b16):
		yield message


def _chkdsk32(v):
	b = v._bpb
	b32 = b.fat32

	if b.BPB_RsvdSecCnt == 0:
		yield (_INVALID, "Invalid BPB_RsvdSecCnt for {0}: 0x{1:04X}".format(v.fat_type, b.BPB_RsvdSecCnt))
	if b.BPB_RsvdSecCnt != 32:
		yield (_UNCOMMON, "Uncommon BPB_RsvdSecCnt for {0}: 0x{1:04X}".format(v.fat_type, b.BPB_RsvdSecCnt))

	if b.BPB_RootEntCnt != 0:
		yield (_INVALID, "Invalid BPB_RootEntCnt for {0}: 0x{1:04X}".format(v.fat_type, b.BPB_RootEntCnt))

	if b.BPB_FATSz16 != 0:
		yield (_INVALID, "BPB_FATSz16 must be zero for {0}: 0x{1:04X}".format(v.fat_type, b.BPB_FATSz16))

	if b32.BPB_FATSz32 == 0:
		yield (_INVALID, "Invalid BPB_FATSz32 for {0}: 0x{1:08X}".format(v.fat_type, b32.BPB_FATSz32))

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
		yield (_UNCOMMON, "Non-zero bytes in BPB_Reserved: {0}".format(_inline_hexdump(b32.BPB_Reserved)))

	if v._cluster_count > _FAT32_MAX_ALLOWED_CLUSTER_COUNT:
		yield (_INVALID, "Cluster count exceeds maximum allowed for {0}: 0x{1:08X} > 0x{2:08X}".format(v.fat_type, v._cluster_count, _FAT32_MAX_ALLOWED_CLUSTER_COUNT))

	for message in _chkdsk_bpbx_common(v, b32):
		yield message


_TYPES_TO_BSTYPE = {
	TYPE_FAT32: ("FAT32   ",),
	TYPE_FAT16: ("FAT16   ", "FAT     "),
	TYPE_FAT12: ("FAT12   ", "FAT     ")
}

def _chkdsk_bpbx_common(v, bx):
	if bx.BS_DrvNum not in _VALID_DRIVE_NUM:
		yield (_INVALID, "Invalid BS_DrvNum: 0x{0:02X}".format(bx.BS_DrvNum))

	if bx.BS_Reserved1 != 0:
		yield (_UNCOMMON, "Nonzero BS_Reserved1: 0x{0:02X}".format(bx.BS_Reserved1))

	_bs_level = _UNCOMMON
	if bx.BS_BootSig != 0x29:
		yield (_INFO, "BS_VolID, BS_VolLab, BS_FilSysType not present")
		_bs_level = _INFO

	# TODO: check bx.BS_VolLab against what the root dir thinks it is
	yield (_INFO, "BS_VolID is 0x{0:08X}".format(bx.BS_VolID))
	yield (_INFO, "BS_VolLab is {0!r}".format(_bytes_to_str(bx.BS_VolLab)))

	fstype_str = _bytes_to_str(bx.BS_FilSysType)
	if fstype_str not in _TYPES_TO_BSTYPE[v.fat_type]:
		yield (_bs_level, "BS_FilSysType doesn't match determined filesystem type of {0}: {1!r}".format(v.fat_type, fstype_str))


def _chkdsk_fat(v):
	b = v._bpb
	prev_active_fat = v.active_fat_index
	
	for fat_index in xrange(b.BPB_NumFATs):
		v.active_fat_index = fat_index
		if v._calc_fat_sector_start() >= v._geometry.total_sector_count():
			yield (_INVALID, "Canceling FAT check at FAT[{0}]: First sector of this FAT exceeds volume sector count".format(fat_index))
			break

		try:
			for message in _chkdsk_lowfat(v):
				yield message

			for message in _chkdsk_highfat(v):
				yield message

		except MediaError as me:
			yield (_INVALID, "Error while checking FAT[{0}]: {1!s}".format(fat_index, me))

	v.active_fat_index = prev_active_fat


def _chkdsk_lowfat(v):
	b = v._bpb
	expect_fat0 = 0x0F00 | b.BPB_Media

	fat1_check_mask = 0x0FFF
	fat1_clean = 0

	if v.fat_type == TYPE_FAT32:
		fat1_check_mask = 0x03FFFFFF
		fat1_clean =      0x08000000
		fat1_harderror =  0x04000000

	elif v.fat_type == TYPE_FAT16:
		fat1_check_mask = 0x3FFF
		fat1_clean =      0x8000
		fat1_harderror =  0x4000

	actual_fat0 = v._get_fat_entry(0)
	if actual_fat0 != expect_fat0:
		yield (
			_INVALID,
			"FAT[{0}][0] doesn't match BPB_Media (0x{1:02X}). Expected 0x{2:04X}, got 0x{3:04X}".format(
				v.active_fat_index,
				b.BPB_Media,
				expect_fat0,
				actual_fat0
			)
		)

	actual_fat1 = v._get_fat_entry(1)
	if (actual_fat1 & fat1_check_mask) < (v._fat_eoc & fat1_check_mask):
		yield (
			_INVALID,
			"FAT[{0}][1] low bits don't contain a valid EOC for {1}: Expected >= 0x{2:04X}, got 0x{3:04X}".format(
				v.active_fat_index,
				v.fat_type,
				v._fat_eoc & fat1_check_mask,
				actual_fat1 & fat1_check_mask
			)
		)

	if fat1_clean:
		if (actual_fat1 & fat1_clean) == 0:
			yield (_INFO, "FAT[{0}] reports volume is marked as dirty".format(v.active_fat_index))
		if (actual_fat1 & fat1_harderror) == 0:
			yield (_INFO, "FAT[{0}] reports volume is marked as having hard errors".format(v.active_fat_index))


def _chkdsk_highfat(v):
	nonzeroes = 0

	start_sector, start_byte = v._get_fat_address(v._max_cluster_num + 1)

	# this is the first invalid, not the last valid
	# so feeding it to xrange is correct
	end_sector = v._calc_fat_sector_start() + v._fat_sector_count

	for current_sector in xrange(start_sector, end_sector):
		sec = v._read_sector(current_sector)
		for b in xrange(start_byte, v._bytes_per_sector):
			if sec[b] != '\0':
				nonzeroes += 1

		start_byte = 0

	if nonzeroes > 0:
		yield (_UNCOMMON, "FAT[{0}] has non-zero data in its unused area".format(v.active_fat_index))
