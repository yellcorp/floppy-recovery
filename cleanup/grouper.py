#!/usr/bin/env python3

import collections
import os
import re
import shutil
import sys


DIR_TO_METHOD = {
    "1 winimage bytecc": 1,
    "2 winimage iomega": 2,
    "3 winimage iomega auto": 3,
    "4 fau-dd iomega": 4,
    "5 ddrescue iomega": 5
}


class PassFileDescriptor(object):
    _PASS_PATTERN = re.compile(r"^(?P<source_name>.+)-pass(?P<pass_num>\d+)$")

    def __init__(self, path, method_num):
        self.path = path
        self.method_num = method_num
        self.source_name = None
        self.pass_num = None
        self.ext = None
        self._infer_from_path()

    def _infer_from_path(self):
        bare_name, self.ext = os.path.splitext(os.path.basename(self.path))
        match = PassFileDescriptor._PASS_PATTERN.match(bare_name)
        if match:
            self.source_name = match.group("source_name")
            self.pass_num = int(match.group("pass_num"))
        else:
            self.source_name = bare_name
            self.pass_num = 1


def path_to_method_num(path):
    for part in path.split("/"):
        if part in DIR_TO_METHOD:
            return DIR_TO_METHOD[part]
    return None


def copy(src, dest):
    print("{0} -> {1}".format(src, dest))
    try:
        shutil.copy2(src, dest)
    except EnvironmentError as e:
        if os.path.exists(src):
            raise e


def copy_ima_and_log(src, dest):
    for suffix in ("", ".log"):
        copy(src + suffix, dest + suffix)


def main():
    in_root = sys.argv[1]
    out_root = sys.argv[2]

    passes_by_name = collections.defaultdict(list)

    for path, dirs, files in os.walk(in_root):
        method_num = path_to_method_num(path)
        if method_num is None:
            print("{0}: Unknown method".format(path), file=sys.stderr)
            continue

        for f in files:
            if os.path.splitext(f)[1].lower() == ".ima":
                desc = PassFileDescriptor(os.path.join(path, f), method_num)
                passes_by_name[desc.source_name].append(desc)

    for desc_set in passes_by_name.values():
        ordered = sorted(desc_set, key=lambda d: (d.method_num, d.pass_num, d.path))
        for new_pass_num, desc in enumerate(ordered):
            copy_ima_and_log(
                desc.path,
                os.path.join(
                    out_root,
                    "{source}.p{passn}.m{methodn}{ext}".format(
                        source=desc.source_name,
                        passn=new_pass_num + 1,
                        methodn=desc.method_num,
                        ext=desc.ext
                    )
                )
            )


if __name__ == '__main__':
    main()
