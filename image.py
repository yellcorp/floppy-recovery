#!/usr/local/bin/python


import argparse
import itertools
import os

import PIL.Image

import disklib
import disklib.validity


def get_arg_parser():
	p = argparse.ArgumentParser("Renders the bytes of a disk file as a graphic.")

	p.add_argument(
		"width",
		help="""The width of the generated graphic. Can be expressed as an
			integer or a product of integers using '*' to represent
			multiplication.""",
		metavar="WIDTHEXPR"
	)

	p.add_argument(
		"paths",
		nargs="+",
		help="""Files to convert to graphics. Output files will be named
			{path}.{width}.{format}"""
	)

	p.add_argument(
		"-f", "--force",
		action="store_true",
		help="""Overwrite existing graphic files"""
	)

	return p


FORMAT = "png"


def parse_product(width_expr):
	return disklib.product(map(int, width_expr.split("*")))


def error_map(b):
	return (b / 2 + 128, b, int(b * 0.25), 255)


def gray_map(b):
	return (b, b, b, 255)


def append_pixels(in_stream, count, out_bytearray, byte_to_pixel_function, void_pixel):
	if count == 0:
		return

	bytes_read = 0
	while bytes_read < count:
		b = in_stream.read(count - bytes_read)
		if len(b) == 0:
			out_bytearray.extend(
				itertools.chain(
					*itertools.repeat(void_pixel, count - bytes_read))
				)
			return
		else:
			out_bytearray.extend(
				itertools.chain(
					*(byte_to_pixel_function(ord(ch)) for ch in b)
				)
			)
			bytes_read += len(b)


def render_graphic(in_path, width, out_path):
	ranges = disklib.validity.read_validity_for_file(in_path)
	graphic_buffer = bytearray()

	print(in_path)
	with open(in_path, "rb") as in_stream:
		for is_good, start, end in ranges.iterall():
			if is_good:
				pixel_func = gray_map
				void = (0, 0, 0, 0)
			else:
				pixel_func = error_map
				void = (255, 0, 0, 64)

			append_pixels(in_stream, end - start, graphic_buffer, pixel_func, void)

	height, remainder = divmod(ranges.domain, width)

	if remainder != 0:
		graphic_buffer.extend(
			itertools.chain(
				*itertools.repeat((0, 0, 0, 0), width - remainder)
			)
		)
		height += 1

	graphic = PIL.Image.frombuffer(
		# frombuffer args
		'RGBA', (width, height), graphic_buffer,
		# decoder args
		'raw', 'RGBA', 0, 1
	)
	graphic.save(out_path)


def main():
	config = get_arg_parser().parse_args()

	width = parse_product(config.width)

	for in_path in config.paths:
		out_path = "{path}.{width}.{format}".format(
			path=in_path, width=width, format=FORMAT)
		if config.force or not os.path.exists(out_path):
			render_graphic(in_path, width, out_path)


if __name__ == '__main__':
	main()
