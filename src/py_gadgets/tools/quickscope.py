#!/usr/bin/env python3
# quickscope.py — Async TCP port scanner with IPv4/IPv6, CSV/NDJSON, and nicer UX
import argparse, asyncio, ipaddress, json, socket, sys, os
from typing import List, Tuple, Dict, Iterable, Set, Optional
from contextlib import suppress

COMMON_PORTS = [21,22,23,25,53,80,110,123,135,139,143,161,389,443,445,465,514,587,631,636,8080,8443,25565]


def parse_ports(s: str) -> List[int]:
    if s.lower() == "common": return COMMON_PORTS
    out: Set[int] = set()
    for part in s.split(","):
        part = part.strip()
        if not part: continue
        if "-" in part:
            a,b = part.split("-",1)
            a,b = int(a), int(b)
            if a>b: a,b = b,a
            out.update(range(a, b+1))
        else:
            out.add(int(part))
    return sorted(p for p in out if 1 <= p <= 65535)


def parse_exclude(s: Optional[str]) -> Set[int]:
    return set(parse_ports(s)) if s else set()


async def resolve_target(t: str) -> List[str]:
    # Accept IPv4/IPv6 literals and hostnames; return a list of IPs (v4/v6)
    try:
        ipaddress.ip_address(t)
        return [t]
    except ValueError:
        pass
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(t, None, type=socket.SOCK_STREAM)
    ips = []
    for fam, _, _, _, sockaddr in infos:
        ip = sockaddr[0]
        if fam in (socket.AF_INET, socket.AF_INET6):
            ips.append(ip)
    seen=set(); out=[]
    for ip in ips:
        if ip not in seen: seen.add(ip); out.append(ip)
    return out


def expand_targets(targets: Iterable[str]) -> List[str]:
    out: List[str] = []
    for t in targets:
        t = t.strip()
        if not t: continue
        if "/" in t:
            net = ipaddress.ip_network(t, strict=False)
            out.extend([str(ip) for ip in net.hosts()])
        else:
            out.append(t)
    # Order-preserving de-dup of tokens (IPs or names/CIDR-expanded IPs)
    seen=set(); final=[]
    for tok in out:
        if tok not in seen: seen.add(tok); final.append(tok)
    return final


async def probe(ip: str, port: int, timeout: float, do_banner: bool) -> Tuple[bool, str]:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        banner = ""
        if do_banner:
            with suppress(Exception):
                writer.write(b"\r\n"); await writer.drain()
                data = await asyncio.wait_for(reader.read(128), timeout=min(0.6, timeout))
                banner = data.decode(errors="ignore").strip()
        writer.close()
        with suppress(Exception): await writer.wait_closed()
        return True, banner
    except Exception:
        return False, ""


async def run_scan(ips: List[str], ports: List[int], timeout: float, max_concurrency: int,
                   do_banner: bool, progress: bool, open_only: bool, exclude: Set[int]) -> Dict[str, List[Dict]]:
    sem = asyncio.Semaphore(max_concurrency)
    results: Dict[str, List[Dict]] = {ip: [] for ip in ips}

    ports = [p for p in ports if p not in exclude]
    total = len(ips) * len(ports)
    done = 0

    async def task(ip: str, port: int):
        nonlocal done
        async with sem:
            ok, banner = await probe(ip, port, timeout, do_banner)
            if ok or not open_only:
                results[ip].append({"port": port, "state": "open" if ok else "closed", "banner": banner if ok else ""})
        done += 1
        if progress and total:
            if done % 50 == 0 or done == total:
                pct = (done / total) * 100
                print(f"\r[+] Progress: {done}/{total} ({pct:0.1f}%)", end="", file=sys.stderr)

    tasks = [asyncio.create_task(task(ip, p)) for ip in ips for p in ports]
    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        for t in tasks: t.cancel()
        raise
    finally:
        if progress:
            print("\r[+] Progress: done".ljust(40), file=sys.stderr)
    return {ip: v for ip, v in results.items() if (v and (not open_only or any(e["state"]=="open" for e in v)))}


async def materialize_ips(maybe_names: List[str]) -> List[str]:
    ips: List[str] = []
    for tok in maybe_names:
        try:
            ipaddress.ip_address(tok)
            ips.append(tok)
        except ValueError:
            resolved = await resolve_target(tok)
            ips.extend(resolved)
    seen=set(); out=[]
    for ip in ips:
        if ip not in seen: seen.add(ip); out.append(ip)
    return out


def print_pretty(results: Dict[str, List[Dict]], open_only: bool):
    if not results:
        print("No results." if not open_only else "No open ports found.")
        return
    for ip, entries in results.items():
        entries = sorted(entries, key=lambda e: e["port"])
        if open_only:
            entries = [e for e in entries if e["state"]=="open"]
            if not entries: continue
        print(f"\n{ip}")
        for e in entries:
            if e["state"] == "open":
                banner = f"  ← {e['banner']}" if e["banner"] else ""
                print(f"  {e['port']}/tcp open{banner}")
            else:
                print(f"  {e['port']}/tcp closed")


def print_csv(results: Dict[str, List[Dict]], open_only: bool, header: bool):
    if header:
        print("ip,port,protocol,state,banner")
    for ip, entries in results.items():
        for e in sorted(entries, key=lambda x: x["port"]):
            if open_only and e["state"]!="open": continue
            b = e["banner"].replace('"','""')
            print(f'{ip},{e["port"]},tcp,{e["state"]},"{b}"')


def print_ndjson(results: Dict[str, List[Dict]], open_only: bool):
    for ip, entries in results.items():
        for e in sorted(entries, key=lambda x: x["port"]):
            if open_only and e["state"]!="open": continue
            obj = {"ip": ip, "port": e["port"], "protocol": "tcp", "state": e["state"], "banner": e["banner"]}
            print(json.dumps(obj, separators=(",",":")))


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="QuickScope: async TCP subnet/host port scanner")
    ap.add_argument("targets", nargs="+", help="IPs/hostnames or CIDRs (IPv4/IPv6), e.g. 192.168.1.0/24 example.com")
    ap.add_argument("-p","--ports", default="common", help="Ports: 'common' or '22,80,443' or '1-1024'")
    ap.add_argument("-x","--exclude", default=None, help="Exclude ports/ranges (e.g., '135-139,445')")
    ap.add_argument("-t","--timeout", type=float, default=1.2, help="Socket timeout (s)")
    ap.add_argument("-c","--concurrency", type=int, default=1024, help="Max concurrent connections")
    ap.add_argument("--json", action="store_true", help="Output JSON (object keyed by IP)")
    ap.add_argument("--csv", action="store_true", help="Output CSV")
    ap.add_argument("--ndjson", action="store_true", help="Output newline-delimited JSON")
    ap.add_argument("--csv-header", action="store_true", help="Include header row in CSV")
    ap.add_argument("--no-banner", action="store_true", help="Disable banner grab (faster/quieter)")
    ap.add_argument("--progress", action="store_true", help="Show stderr progress")
    ap.add_argument("--all", dest="open_only", action="store_false", help="Show closed ports too")
    ap.set_defaults(open_only=True)
    return ap


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    with suppress(Exception):
        if os.name == "nt":
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    try:
        tokens = expand_targets(args.targets)
        ports = parse_ports(args.ports)
        if not ports: raise ValueError("no valid ports")
        exclude = parse_exclude(args.exclude)
    except Exception as e:
        print(f"[!] Invalid input: {e}", file=sys.stderr); return 2

    try:
        ips = asyncio.run(materialize_ips(tokens))
        if not ips:
            print("[!] No resolvable targets.", file=sys.stderr); return 2

        results = asyncio.run(
            run_scan(
                ips=ips, ports=ports, timeout=args.timeout, max_concurrency=args.concurrency,
                do_banner=not args.no_banner, progress=args.progress, open_only=args.open_only, exclude=exclude
            )
        )
    except KeyboardInterrupt:
        print("\n[!] Aborted.", file=sys.stderr); return 130

    if args.json:
        print(json.dumps(results, indent=2, sort_keys=True))
    elif args.csv:
        print_csv(results, open_only=args.open_only, header=args.csv_header)
    elif args.ndjson:
        print_ndjson(results, open_only=args.open_only)
    else:
        print_pretty(results, open_only=args.open_only)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
