#!/usr/bin/env python3
# quickscope.py
import argparse, asyncio, ipaddress, json, socket, sys
from typing import List, Tuple, Dict

COMMON_PORTS = [21,22,23,25,53,80,110,123,135,139,143,161,389,443,445,465,514,587,631,636,8080,8443,25565]

async def probe(ip: str, port: int, timeout: float) -> Tuple[bool, str]:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        # Try a tiny banner read without sending anything intrusive
        banner = ""
        try:
            writer.write(b"\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(128), timeout=0.4)
            banner = data.decode(errors="ignore").strip()
        except Exception:
            pass
        writer.close()
        try: await writer.wait_closed()
        except Exception: pass
        return True, banner
    except Exception:
        return False, ""

def expand_targets(targets: List[str]) -> List[str]:
    out = []
    for t in targets:
        t = t.strip()
        if "/" in t:
            out.extend([str(ip) for ip in ipaddress.ip_network(t, strict=False).hosts()])
        else:
            out.append(t)
    # de-dupe preserve order
    seen = set(); final=[]
    for ip in out:
        if ip not in seen:
            seen.add(ip); final.append(ip)
    return final

async def run_scan(ips: List[str], ports: List[int], timeout: float, max_concurrency: int) -> Dict[str, List[Dict]]:
    sem = asyncio.Semaphore(max_concurrency)
    results: Dict[str, List[Dict]] = {ip: [] for ip in ips}

    async def task(ip: str, port: int):
        async with sem:
            ok, banner = await probe(ip, port, timeout)
            if ok:
                results[ip].append({"port": port, "banner": banner})

    tasks = [asyncio.create_task(task(ip, p)) for ip in ips for p in ports]
    await asyncio.gather(*tasks)
    # Trim empties
    return {ip: v for ip, v in results.items() if v}

def parse_ports(s: str) -> List[int]:
    if s.lower() == "common":
        return COMMON_PORTS
    out = set()
    for part in s.split(","):
        part = part.strip()
        if "-" in part:
            a,b = part.split("-",1)
            out.update(range(int(a), int(b)+1))
        else:
            out.add(int(part))
    return sorted(out)

def main():
    ap = argparse.ArgumentParser(description="QuickScope: async subnet + port scanner")
    ap.add_argument("targets", nargs="+", help="CIDR(s) or IP(s), e.g. 192.168.1.0/24 10.0.0.5")
    ap.add_argument("-p","--ports", default="common", help="Ports: 'common' or '22,80,443' or '1-1024'")
    ap.add_argument("-t","--timeout", type=float, default=1.2, help="Socket timeout (s)")
    ap.add_argument("-c","--concurrency", type=int, default=1024, help="Max concurrent connections")
    ap.add_argument("--json", action="store_true", help="Output JSON")
    args = ap.parse_args()

    try:
        ips = expand_targets(args.targets)
    except ValueError as e:
        print(f"[!] Invalid target: {e}", file=sys.stderr); sys.exit(2)
    ports = parse_ports(args.ports)

    try:
        results = asyncio.run(run_scan(ips, ports, args.timeout, args.concurrency))
    except KeyboardInterrupt:
        print("\n[!] Aborted.", file=sys.stderr); sys.exit(130)

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        if not results:
            print("No open ports found.")
            return
        for ip, entries in results.items():
            print(f"\n{ip}")
            for e in sorted(entries, key=lambda x: x["port"]):
                banner = f"  ← {e['banner']}" if e["banner"] else ""
                print(f"  {e['port']}/tcp open{banner}")

if __name__ == "__main__":
    # Make Ctrl+C snappier on Windows
    try:
        import asyncio, os
        if os.name == "nt":
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    except Exception:
        pass
    main()
