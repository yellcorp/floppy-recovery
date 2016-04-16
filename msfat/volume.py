from ctypes import LittleEndianStructure, Union, sizeof, c_ubyte, c_uint16, c_uint32
import collections
import struct


from msfat import TYPE_FAT12, TYPE_FAT16, TYPE_FAT32, SeekError
from msfat.chkdsk import chkdsk
import msfat.stream


_FAT32_ENTRY_MASK = 0x0FFFFFFF
_FAT12_EOC = 0xFF8
_FAT12_BAD = 0xFF7
_MIN_CLUSTER_NUM = 2

class _BiosParameterBlock16(LittleEndianStructure): # also used for FAT12
    _pack_ = 1
    _fields_ = [
        ("BS_DrvNum",      c_ubyte),      # 0x00 for floppy, 0x80 for hard

        # Used by WinNT, other software should set to 0 when creating
        ("BS_Reserved1",   c_ubyte),

        ("BS_BootSig",     c_ubyte),      # 0x29 means the following 3 fields are present
        ("BS_VolID",       c_uint32),
        ("BS_VolLab",      c_ubyte * 11), # should match volume dir entry in \. "NO NAME    " if not set

        # not actually used in FAT type determination, but should be one of
        # "FAT12   ", "FAT16   ", "FAT     "
        ("BS_FilSysType",  c_ubyte * 8)
    ]


class _BiosParameterBlock32(LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("BPB_FATSz32",    c_uint32),
        ("BPB_ExtFlags",   c_uint16),     # See docs, but nothing to validate probably
        ("BPB_FSVer",      c_uint16),     # Version 0 seems to be the highest defined
        ("BPB_RootClus",   c_uint32),     # Should be 2, but not required
        ("BPB_FSInfo",     c_uint16),
        ("BPB_BkBootSec",  c_uint16),     # Should be 6
        ("BPB_Reserved",   c_ubyte * 12), # Should be all \0

        # Following are same as in BiosParameterBlock16, just different offsets
        ("BS_DrvNum",      c_ubyte),
        ("BS_Reserved1",   c_ubyte),
        ("BS_BootSig",     c_ubyte),
        ("BS_VolID",       c_uint32),
        ("BS_VolLab",      c_ubyte * 11),

        # Should be "FAT32   " but as in BiosParameterBlock16, not actually
        # used in type determination
        ("BS_FilSysType",  c_ubyte * 8)
    ]


class _BiosParameterBlockUnion(Union):
    _fields_ = [
        ("fat16", _BiosParameterBlock16),
        ("fat32", _BiosParameterBlock32)
    ]


class BiosParameterBlock(LittleEndianStructure):
    _pack_ = 1
    _anonymous_ = ("bpbex",)
    _fields_ = [
        ("BS_jmpBoot",     c_ubyte * 3),  # \xeb.\x90|\xe9..
        ("BS_OEMName",     c_ubyte * 8),  # informational only. "MSWIN4.1" recommended
        ("BPB_BytsPerSec", c_uint16),     # 2^n where 9 <= n <= 12
        ("BPB_SecPerClus", c_ubyte),      # 2^n where 0 <= n <= 7, BPB_BytsPerSec * BPB_SecPerClus <= 32*1024
        ("BPB_RsvdSecCnt", c_uint16),     # > 0, FAT12 and FAT16 must be 1, FAT32 often 32
        ("BPB_NumFATs",    c_ubyte),      # Should be 2

        # This field * 32 must be an even multiple of BPB_BytsPerSec
        # i.e. Root entry count must not partially fill a sector
        # (entries are 32 bytes each)
        # Must be 0 on FAT32
        # FAT16 recommended to be 512
        ("BPB_RootEntCnt", c_uint16),

        # If 0, then see BOB_TotSec32. Otherwise use this value and
        # BPB_TotSec32 must be 0. Must be 0 on FAT32.
        # Can be less than the total # of sectors on disk. Must never be greater
        ("BPB_TotSec16",   c_uint16),

        # 0xF0, 0xF8-0xFF. Should equal FAT[0]. 0xF0 for removable media,
        # 0xF8 for non-removable
        ("BPB_Media",      c_ubyte),

        ("BPB_FATSz16",    c_uint16),     # must be 0 on FAT32, in which case see BPB_FATSz32
        ("BPB_SecPerTrk",  c_uint16),     # check against MediaGeometry
        ("BPB_NumHeads",   c_uint16),     # check against MediaGeometry
        ("BPB_HiddSec",    c_uint32),     # 0 on non-partitioned disks, like floppies
        ("BPB_TotSec32",   c_uint32),
        ("bpbex",          _BiosParameterBlockUnion)
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


class FATVolume(object):
    def __init__(self, stream, geometry):
        self._stream = stream
        self._geometry = geometry
        self._bpb = None

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
        bx = self.fat_type == TYPE_FAT32 and b.fat32 or b.fat16

        return _VolumeInfo(
            self.fat_type,
            bytes(bx.BS_FilSysType),
            bytes(b.BS_OEMName),
            bx.BS_VolID,
            bytes(bx.BS_VolLab),
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


    def chkdsk(self, user_log_func):
        chkdsk(self, user_log_func)


    def _open_root_dir(self):
        if self.fat_type == TYPE_FAT32:
            return self._open_cluster_chain(self._bpb.fat32.BPB_RootClus)
        else:
            return self._open_sector_run(self._root_dir_sector_start, self._root_dir_sector_count)


    def _open_sector_run(self, first_sector, count):
        return msfat.stream.SectorRunStream(self, first_sector, count)


    def _open_cluster_chain(self, first_cluster, expected_bytes=-1):
        return msfat.stream.ClusterChainStream(self, first_cluster, expected_bytes)


    def _seek_sector(self, sector, byte=0):
        if 0 <= sector < self._geometry.total_sector_count():
            self._stream.seek(sector * self._geometry.sector_size + byte)
        else:
            raise SeekError("Invalid sector number", sector)

    def _is_valid_cluster_num(self, cluster):
        return _MIN_CLUSTER_NUM <= cluster <= self._max_cluster_num

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

        bpbbuf = self._read(sizeof(BiosParameterBlock))
        self._bpb = BiosParameterBlock.from_buffer_copy(bpbbuf)

    def _init_calcs(self):
        # you could use self._bpb.BPB_BytsPerSec
        # self._bytes_per_sector = self._bpb.BPB_BytsPerSec
        self._bytes_per_sector = self._geometry.sector_size
        self._bytes_per_cluster = self._bytes_per_sector * self._bpb.BPB_SecPerClus

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
        return self._bpb.fat32.BPB_FATSz32

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
        byte_count = (b.BPB_RootEntCnt * 32) + (self._bytes_per_sector - 1)
        return byte_count // self._bytes_per_sector

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
