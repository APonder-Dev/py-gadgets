import argparse
import hashlib
from pathlib import Path
from collections import defaultdict


def file_hash(path, chunk=1024*1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Find duplicate files by SHA-256 (size prefilter)")
    p.add_argument("-p","--path", default=".", help="Root path to scan")
    p.add_argument("--min-bytes", type=int, default=1, help="Only consider files ≥ this size")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.path)

    by_size = defaultdict(list)
    for p in root.rglob("*"):
        if p.is_file():
            try:
                sz = p.stat().st_size
                if sz >= args.min_bytes:
                    by_size[sz].append(p)
            except Exception:
                pass

    dup_groups = defaultdict(list)
    for sz, group in by_size.items():
        if len(group) < 2:
            continue
        for p in group:
            try:
                h = file_hash(p)
                dup_groups[h].append(p)
            except Exception:
                pass

    had = False
    for h, paths in dup_groups.items():
        if len(paths) > 1:
            had = True
            print(f"\n# hash={h}")
            for p in paths:
                print(p)
    if not had:
        print("No duplicates found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
