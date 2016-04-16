#!/usr/bin/env python3

# This is awful. What it does is scan the specified root paths, recursively,
# for zip files (checking magic number, not extension), and unzips those which
# contain only a single file. The file's name inside the zip is ignored, except
# for the extension, which is combined with the extension-less name of the zip.
# The original zip is then moved to {root}/__unzipped/{zip_path}

# This is done so unzips preserve renames done to the zip files after the
# disk imaging program has written them.

# usage: $0 ROOTDIR+

import calendar
import itertools
import os
import shutil
import sys
import zipfile


UNZIPPED_DIRNAME = "__unzipped"


def strip_exts(s):
    # yes, this is wrong and stupid and you should use os.path.splitext, but
    # this covers the mess i made of naming conventions
    bits = s.split(".")
    if len(bits) == 1:
        return s

    if bits[0] == "":
        prefix = bits[0:2]
        domain = bits[2:]

    else:
        prefix = bits[0:1]
        domain = bits[1:]

    truncated = itertools.dropwhile(lambda s: 2 <= len(s) <= 3, reversed(domain))
    return ".".join(itertools.chain(prefix, reversed(list(truncated))))


def unzip_image(zip_path, move_to_on_success=None):
    with zipfile.ZipFile(zip_path, "r") as archive:
        members = archive.infolist()
        if len(members) != 1:
            print("Contains multiple files: {0}".format(zip_path), file=sys.stderr)
            return

        base_name = strip_exts(zip_path)
        member = members[0]
        _, member_ext = os.path.splitext(member.filename)
        out_name = base_name + member_ext.lower()

        print("{0} >> {1}".format(member.filename, out_name))

        with open(out_name, "wb") as out_stream:
            zstream = archive.open(member, "r")
            try:
                out_stream.write(zstream.read())
            finally:
                zstream.close()

        volume_mtime = os.path.getmtime(zip_path)
        member_mtime = calendar.timegm(member.date_time)
        earliest = min(volume_mtime, member_mtime)
        os.utime(out_name, (earliest, earliest))

    if move_to_on_success:
        root = os.path.dirname(move_to_on_success)
        relpath = os.path.relpath(zip_path, root)
        move_dest = os.path.join(move_to_on_success, relpath)

        print("{0} -> {1}".format(zip_path, move_dest))

        move_parent = os.path.dirname(move_dest)
        try:
            os.makedirs(move_parent)
        except EnvironmentError:
            if os.path.isdir(move_parent):
                pass
            else:
                raise
        shutil.move(zip_path, move_dest)


def main():
    for root in sys.argv[1:]:
        success_path = os.path.join(root, UNZIPPED_DIRNAME)
        for path, dirnames, filenames in os.walk(root):

            try:
                dirnames.pop(dirnames.index(UNZIPPED_DIRNAME))
            except ValueError:
                pass

            for filename in filenames:
                filepath = os.path.join(path, filename)
                if zipfile.is_zipfile(filepath):
                    unzip_image(filepath, success_path)


if __name__ == '__main__':
    main()
