import functools
import operator


CAPACITY_1_44MB = 1474560
CAPACITY_2_88MB = 2949120
CAPACITY_720K = 737280

CAPACITY_1_2MB = 1228800
CAPACITY_360K = 368640


def product(iterable):
	return functools.reduce(operator.mul, iterable, 1)
