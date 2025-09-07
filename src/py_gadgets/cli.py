"""
Unified CLI wrapper that forwards args to individual tools.
Usage:
  pygadgets quickscope -- <args...>
  pygadgets bigfiles   -- <args...>
  pygadgets dupes      -- <args...>
"""
import argparse
import sys

from py_gadgets.tools import quickscope, bigfiles, dupes


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pygadgets",
        description="APonder.dev Python gadgets (unified launcher)"
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_passthrough(name: str, help_text: str):
        sp = sub.add_parser(name, help=help_text)
        sp.add_argument("args", nargs=argparse.REMAINDER, help="Arguments passed to the tool (use -- before them)")
        return sp

    add_passthrough("quickscope", "Async TCP port scanner")
    add_passthrough("bigfiles", "Find largest files under a path")
    add_passthrough("dupes", "Find duplicate files via SHA-256 hashing")

    return p


def main(argv=None) -> int:
    parser = build_parser()
    ns = parser.parse_args(argv)

    # Strip a leading "--" if present (common UX pattern)
    fwd = ns.args
    if fwd and fwd[0] == "--":
        fwd = fwd[1:]

    if ns.cmd == "quickscope":
        return quickscope.main(fwd)
    if ns.cmd == "bigfiles":
        return bigfiles.main(fwd)
    if ns.cmd == "dupes":
        return dupes.main(fwd)

    parser.print_help()
    return 2
