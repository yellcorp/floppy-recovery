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


class SectorRunStream(_BaseStream):
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


class ClusterChainStream(_BaseStream):
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
