import argparse
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Find largest files under a path")
    p.add_argument("-p","--path", default=".", help="Root path to scan")
    p.add_argument("-n","--top", type=int, default=20, help="Show top N files")
    p.add_argument("-m","--min-mb", type=int, default=50, help="Minimum size (MB)")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    root = Path(args.path)
    min_bytes = args.min_mb * 1024 * 1024
    files = []
    for p in root.rglob("*"):
        if p.is_file():
            try:
                sz = p.stat().st_size
                if sz >= min_bytes:
                    files.append((sz, p))
            except Exception:
                pass
    files.sort(reverse=True)
    for sz, p in files[:args.top]:
        print(f"{sz/1_048_576:9.1f} MB  {p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
