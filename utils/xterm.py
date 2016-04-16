ANSI_RESET = "\x1b[0m"


def rgb(r, g, b):
    """Returns a xterm256 color index that represents the specified RGB color.
    Each argument should be an integer in the range [0, 5]."""

    if r < 0 or r > 5 or g < 0 or g > 5 or b < 0 or b > 5:
        raise ValueError("Value out of range")

    return 16 + r * 36 + g * 6 + b


def gray(graylevel):
    """Returns a xterm256 color index that represents the specified gray level.
    The argument should be an integer in the range [0, 25]."""
    if graylevel < 0 or graylevel > 25:
        raise ValueError("Value out of range")

    if graylevel == 0:
        return 0
    elif graylevel == 25:
        return 231
    return 231 + graylevel


def sequence(fore=None, back=None):
    if fore is None and back is None:
        return ""
    codes = [ ]
    if fore is not None:
        codes.extend((38, 5, fore))
    if back is not None:
        codes.extend((48, 5, back))
    return "\x1b[{}m".format(";".join(str(c) for c in codes))


def wrap(text, fore=None, back=None):
    if fore is None and back is None:
        return str(text)
    return "".join([
        sequence(fore, back),
        str(text),
        ANSI_RESET])


def ignore(text, fore=None, back=None):
    return str(text)


def wrap_for_stream(stream):
    try:
        if stream.isatty():
            return wrap
    except AttributeError:
        pass
    return ignore
