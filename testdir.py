#!/usr/bin/env python3

import sys

import disklib.mediageom
import disklib.validity
import msfat.dir
import msfat.volume


def main():
	prog_errs = [ ]

	for path in sys.argv[1:]:
		print(path)

		try:
			validity = disklib.validity.read_validity_for_file(path)
			with open(path, "rb") as stream:
				geometry = disklib.mediageom.DiskGeometry.from_image_size(validity.domain)
				volume = msfat.volume.FATVolume(stream, geometry)

				for k, v in volume.get_info()._asdict().items():
					if isinstance(v, int):
						sv = "{:#010x}".format(v)
					else:
						sv = repr(v)
					print("{0:24} {1}".format(k, sv))

				for entry in msfat.dir.read_dir(volume._open_root_dir()):
					print(str(entry))

		except Exception as e:
			prog_errs.append((path, e))

		print()

	if prog_errs:
		print("Program errors ({}):".format(len(prog_errs)))
		for path, e in prog_errs:
			print("{0}: {1!s}".format(path, e))


if __name__ == '__main__':
	main()
