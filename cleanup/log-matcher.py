#!/usr/bin/env python3


# Cleans up logs. Pairs .txt or .log files with their corresponding image files
# Deletes log files without a matching image file
# Names log and image files consistently

# usage: $0 ROOTDIR+

import argparse
import os
import sys


def get_arg_parser():
    p = argparse.ArgumentParser(
        description="""Cleans up logs. Pairs .txt or .log files with their
            corresponding image files, and deletes log files without a matching
            image file, and names log and image files consistently"""
    )

    p.add_argument(
        "-c", "--commit",
        action="store_true",
        help="Proceed with changes"
    )

    p.add_argument(
        "paths",
        nargs="+",
        help="Directories to search recursively",
        metavar="PATH"
    )

    return p


class EchoAgent(object):
    def rm(self, path):
        print("rm {0!r}".format(path))

    def mv(self, src, dest):
        print("mv {0!r} {1!r}".format(src, dest))


class ActuallyDoItAgent(object):
    def rm(self, path):
        os.remove(path)

    def mv(self, src, dest):
        old_src = None
        src_name = os.path.basename(src)
        dest_name = os.path.basename(dest)

        if src_name.lower() == dest_name.lower():
            old_src = src
            src += "__" # yes, awful garbage, it suits my needs
            os.rename(old_src, src)

        if os.path.exists(dest): # race condition, but i don't care
            print("Target exists: {0}".format(dest), file=sys.stderr)
            if old_src is not None:
                os.rename(src, old_src)
            return

        os.rename(src, dest)


class Aggregator(list):
    def __init__(self, *args, **kwargs):
        super(Aggregator, self).__init__(*args, **kwargs)
        self._cache = dict()


    def __getattr__(self, name):
        if name in self._cache:
            return self._cache[name]

        def agfunc(*args, **kwargs):
            return [ getattr(member, name)(*args, **kwargs) for member in self ]

        self._cache[name] = agfunc
        return agfunc


def lowercase_ext(path):
    b, e = os.path.splitext(path)
    return b + e.lower()


def main():
    config = get_arg_parser().parse_args()

    agents = Aggregator([ EchoAgent() ])

    if config.commit:
        agents.append(ActuallyDoItAgent())

    for root in config.paths:
        for path, dirnames, filenames in os.walk(root):
            icase_map = dict((n.lower(), n) for n in filenames)
            for iname in icase_map.keys():
                barename, ext = os.path.splitext(iname)
                if ext not in (".txt", ".log"):
                    continue

                # some logs are named imagename.imageext.logext
                # others are just named imagename.logext
                # this next line makes either a one or two-member set
                # depending on whether there's another extension that can be
                # stripped
                try_prefixes = set((barename, os.path.splitext(barename)[0]))
                try_suffixes = ("", ".imz", ".ima")

                try_names = set(p + s for p in try_prefixes for s in try_suffixes)
                matched_names = [ n for n in try_names if n in icase_map ]

                log_name = icase_map[iname]

                if len(matched_names) == 0:
                    agents.rm(os.path.join(path, log_name))

                elif len(matched_names) == 1:
                    owner_name = icase_map[matched_names[0]]
                    new_owner_name = lowercase_ext(owner_name)
                    new_log_name = new_owner_name + ".log"

                    if owner_name != new_owner_name:
                        agents.mv(
                            os.path.join(path, owner_name),
                            os.path.join(path, new_owner_name)
                        )

                    if log_name != new_log_name:
                        agents.mv(
                            os.path.join(path, log_name),
                            os.path.join(path, new_log_name)
                        )

    if not config.commit:
        print("Specify -c/--commit to proceed.")


if __name__ == '__main__':
    main()
