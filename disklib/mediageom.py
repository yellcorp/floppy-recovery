import disklib


class DiskGeometry(object):
	floppy_dimensions = [
		# 8"
		(77, 1, 26,  128),
		(77, 2, 26,  128),
		(77, 1,  8, 1024),
		(77, 2,  8, 1024),

		# 5.25"
		(40, 1,  8,  512),
		(40, 2,  8,  512),
		(40, 1,  9,  512),
		(40, 2,  9,  512), # 360K
		(80, 2, 15,  512), # 1.2MB

		# 3.5"
		(80, 1,  8,  512),
		(80, 1,  9,  512),
		(80, 2,  8,  512),
		(80, 2,  9,  512), # 720K
		(80, 2, 18,  512), # 1.44MB
		(80, 2, 36,  512), # 2.88MB

		# 3.5" Microsoft
		(80, 2, 21,  512),
		(82, 2, 21,  512)
	]

	floppy_dimensions_by_size = dict(
		(disklib.product(dim), dim) for dim in floppy_dimensions
	)

	def __init__(self, cylinders, heads, sectors, sector_size):
		self.cylinders = cylinders
		self.heads = heads
		self.sectors = sectors
		self.sector_size = sector_size

	def __repr__(self):
		return "{0}({1!r}, {2!r}, {3!r}, {4!r})".format(
			self.__class__.__name__,
			self.cylinders,
			self.heads,
			self.sectors,
			self.sector_size
		)

	def __str__(self):
		return repr(self)

	def __unicode__(self):
		return repr(self)

	def total_sector_count(self):
		return self.cylinders * self.heads * self.sectors

	def total_bytes(self):
		return self.total_sector_count() * self.sector_size

	# sectors are 1-based, apparently??
	def lba_to_chs(self, sector_num):
		(x, sector) = divmod(sector_num, self.sectors)
		(cylinder, head) = divmod(x, self.heads)
		return (cylinder, head, sector + 1)

	def chs_to_lba(self, cylinder, head=None, sector=None):
		# first argument can be a tuple
		if head is None:
			cylinder, head, sector = cylinder
		return (cylinder * self.heads + head) * self.sectors + (sector - 1)

	def lba_to_byte(self, sector_num):
		return sector_num * self.sector_size

	def chs_to_byte(self, cylinder, head=None, sector=None):
		return self.lba_to_byte(self.chs_to_lba(cylinder, head, sector))

	@classmethod
	def from_image_size(cls, byte_count):
		return cls(*cls.floppy_dimensions_by_size[byte_count])


if __name__ == '__main__':
	fd = DiskGeometry.from_image_size(1474560)
	print fd
	print fd.total_bytes()
	print fd.lba_to_chs(2879)
