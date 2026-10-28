#!/usr/bin/env python3
import argparse
import datetime
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time


def unavailable(error):
    return {"available": False, "error": str(error)}


def fields(path):
    result = {}
    for line in Path(path).read_text().splitlines():
        key, _, value = line.partition(":")
        words = value.split()
        if words and words[0].isdigit():
            result[key] = int(words[0]) * (1024 if len(words) > 1 and words[1] == "kB" else 1)
    return result


def process_stat(pid):
    text = Path(f"/proc/{pid}/stat").read_text()
    rest = text[text.rindex(")") + 2:].split()
    return {"ppid": int(rest[1]), "start_ticks": int(rest[19]), "cpu_ticks": int(rest[11]) + int(rest[12])}


def process_tree(root, start_ticks):
    stats = {}
    for path in Path("/proc").iterdir():
        if path.name.isdigit():
            try:
                stats[int(path.name)] = process_stat(int(path.name))
            except (OSError, ValueError):
                pass
    if root not in stats or stats[root]["start_ticks"] != start_ticks:
        return []
    members = {root}
    while True:
        children = {pid for pid, stat in stats.items() if stat["ppid"] in members}
        expanded = members | children
        if expanded == members:
            break
        members = expanded
    return [(pid, stats[pid]) for pid in sorted(members)]


def process_sample(pid, stat):
    result = {"pid": pid, **stat}
    root = Path(f"/proc/{pid}")
    try:
        result["command"] = (root / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace").strip()
        status = fields(root / "status")
        result["status"] = {k: status[k] for k in ["VmRSS", "VmSize", "VmHWM", "Threads", "FDSize"] if k in status}
    except OSError as error:
        result["status"] = unavailable(error)
    try:
        match = re.search(r"Max open files\s+(\S+)\s+(\S+)", (root / "limits").read_text())
        result["rlimit_nofile"] = {key: int(value) if value.isdigit() else value for key, value in zip(["soft", "hard"], match.groups())}
    except (OSError, AttributeError) as error:
        result["rlimit_nofile"] = unavailable(error)
    try:
        rollup = fields(root / "smaps_rollup")
        result["memory_bytes"] = {k: rollup[k] for k in ["Rss", "Pss", "Private_Clean", "Private_Dirty", "Private_Hugetlb", "Shared_Clean", "Shared_Dirty", "Swap", "SwapPss"] if k in rollup}
        result["memory_bytes"]["private_total"] = sum(rollup.get(k, 0) for k in ["Private_Clean", "Private_Dirty", "Private_Hugetlb"])
    except OSError as error:
        result["memory_bytes"] = unavailable(error)
    try:
        descriptors = {"total": 0, "sockets": 0, "eventpoll": 0, "epoll_watches": 0, "raced_or_denied": 0}
        with os.scandir(root / "fd") as entries:
            for entry in entries:
                descriptors["total"] += 1
                try:
                    target = os.readlink(entry.path)
                    descriptors["sockets"] += target.startswith("socket:")
                    if target == "anon_inode:[eventpoll]":
                        descriptors["eventpoll"] += 1
                        with (root / "fdinfo" / entry.name).open() as info:
                            descriptors["epoll_watches"] += sum(line.startswith("tfd:") for line in info)
                except OSError:
                    descriptors["raced_or_denied"] += 1
        result["fds"] = descriptors
    except OSError as error:
        result["fds"] = unavailable(error)
    return result


def sockstat(path):
    values = {}
    for line in Path(path).read_text().splitlines():
        words = line.replace(":", "").split()
        values[words[0]] = {words[i]: int(words[i + 1]) for i in range(1, len(words) - 1, 2)}
    return values


def network_counters(path):
    lines = Path(path).read_text().splitlines()
    result = {}
    for i in range(0, len(lines) - 1, 2):
        names, values = lines[i].split(), lines[i + 1].split()
        selected = {name: int(value) for name, value in zip(names[1:], values[1:]) if name in ["CurrEstab", "RetransSegs", "ListenOverflows", "ListenDrops", "TCPTimeouts", "TCPSynRetrans", "TCPMemoryPressures", "TCPAbortOnMemory"]}
        if selected:
            result[names[0].rstrip(":")] = selected
    return result


def slab_counters():
    result = {}
    with Path("/proc/slabinfo").open() as source:
        for line in source:
            words = line.split()
            if not words or not words[0].startswith(("TCP", "tw_sock", "request_sock", "sock_inode", "skbuff", "eventpoll", "filp")):
                continue
            active, total, size, per_slab, pages = map(int, words[1:6])
            value = {"active_objects": active, "total_objects": total, "object_bytes": size, "object_capacity_bytes": total * size}
            if "slabdata" in words:
                total_slabs = int(words[words.index("slabdata") + 2])
                value["allocated_slab_pages_bytes"] = total_slabs * pages * os.sysconf("SC_PAGE_SIZE")
            result[words[0]] = value
    return result


def sysfs_slab_counters():
    result = {}
    for name in ["TCP", "sock_inode_cache", "eventpoll_epi", "eventpoll_pwq", "filp"]:
        root = Path("/sys/kernel/slab") / name
        result[name] = {key: (root / key).read_text().strip() for key in ["objects", "object_size", "slabs"]}
    return result


def socket_buffers(ports):
    categories = dict.fromkeys(["r", "t", "f", "w", "o", "bl"], 0)
    maxima = dict(categories)
    limits = dict.fromkeys(["rb", "tb"], 0)
    endpoints = 0
    drops = 0
    incomplete = False
    socket_lines = 0
    selector = "( " + " or ".join(f"sport = :{port}" for port in ports) + " )"
    command = ["ss", "-Htnm", "state", "established", selector]
    try:
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as process:
            for line in process.stdout:
                match = re.search(r"skmem:\(([^)]*)\)", line)
                if match is None:
                    socket_lines += bool(line.strip())
                    continue
                values = dict((key, int(value)) for key, value in re.findall(r"([a-z]+)([0-9]+)", match.group(1)))
                if not all(key in values for key in [*categories, *limits]):
                    incomplete = True
                    continue
                endpoints += 1
                for key in categories:
                    categories[key] += values[key]
                    maxima[key] = max(maxima[key], values[key])
                for key in limits:
                    limits[key] += values[key]
                drops += values.get("d", 0)
            error = process.stderr.read().strip()
            if process.wait() != 0:
                return unavailable(error or "ss failed")
            if incomplete:
                return unavailable("ss omitted socket allocation categories or limits")
            if socket_lines and not endpoints:
                return unavailable("ss returned endpoints without parseable skmem records")
    except OSError as error:
        return unavailable(error)
    return {
        "available": True, "source_ports": ports, "state": "established", "endpoints": endpoints,
        "allocation_categories_bytes": categories, "allocation_category_max_bytes": maxima,
        "buffer_limit_sums_bytes_not_allocation": limits, "socket_drop_counter_sum": drops,
        "scope": "Server-side endpoint socket diagnostics in this network namespace, selected by source port; not an atomic snapshot. r=receive allocation,t=transmit allocation,f=forward allocation,w=queued transmit,o=option memory,bl=backlog. Categories can overlap, especially r/t/w; do not sum them. rb/tb are buffer limits, not memory allocated. TCP socket objects, file objects and epoll slabs are not included.",
    }


def system_sample():
    result = {}
    probes = {
        "sockstat": lambda: sockstat("/proc/net/sockstat"),
        "sockstat6": lambda: sockstat("/proc/net/sockstat6"),
        "tcp": lambda: network_counters("/proc/net/snmp"),
        "tcp_ext": lambda: network_counters("/proc/net/netstat"),
        "slabinfo": slab_counters,
        "slab_sysfs": sysfs_slab_counters,
        "memory_bytes": lambda: {k: v for k, v in fields("/proc/meminfo").items() if k in ["MemAvailable", "Slab", "SReclaimable", "SUnreclaim", "KernelStack", "PageTables"]},
        "file_nr": lambda: dict(zip(["allocated", "unused", "maximum"], map(int, Path("/proc/sys/fs/file-nr").read_text().split()))),
        "file_max": lambda: int(Path("/proc/sys/fs/file-max").read_text()),
        "epoll_max_user_watches": lambda: int(Path("/proc/sys/fs/epoll/max_user_watches").read_text()),
        "conntrack": lambda: {key: int(Path("/proc/sys/net/netfilter/nf_conntrack_" + key).read_text()) for key in ["count", "max"]},
    }
    for name, probe in probes.items():
        try:
            result[name] = probe()
        except (OSError, ValueError) as error:
            result[name] = unavailable(error)
    return result


def flatten(value, prefix=""):
    result = {}
    for key, item in value.items():
        name = prefix + key
        if isinstance(item, dict):
            result.update(flatten(item, name + "."))
        elif isinstance(item, int) and not isinstance(item, bool):
            result[name] = item
    return result


def aggregate(processes, section, keys):
    totals = {}
    for key in keys:
        values = [p.get(section, {}).get(key) for p in processes]
        totals[key] = sum(values) if values and all(isinstance(v, int) for v in values) else None
    return totals


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, required=True, help="foreground server or launcher PID; descendants included")
    parser.add_argument("--out", required=True, help="append JSONL here")
    parser.add_argument("--interval", type=float, default=10)
    parser.add_argument("--duration", type=float, default=0, help="0 samples until interrupted or root exits")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--ports", help="comma-separated server source ports for established ss -tnm sampling")
    args = parser.parse_args()
    try:
        ports = sorted(set(int(port) for port in args.ports.split(","))) if args.ports else []
        if any(port < 1 or port > 65535 for port in ports):
            raise ValueError()
    except ValueError:
        parser.error("ports must be comma-separated integers from 1 through 65535")
    if args.interval <= 0 or args.duration < 0:
        parser.error("interval must be positive and duration nonnegative")
    try:
        root_start = process_stat(args.pid)["start_ticks"]
    except OSError as error:
        parser.error(str(error))
    stopped = False
    def stop(*_):
        nonlocal stopped
        stopped = True
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    begin = time.monotonic()
    baseline = None
    with open(args.out, "a", buffering=1) as output:
        while not stopped:
            capture_start = time.monotonic()
            processes = [process_sample(pid, stat) for pid, stat in process_tree(args.pid, root_start)]
            system = system_sample()
            sockets = socket_buffers(ports) if ports else {"available": False, "reason": "source-port sampling not requested"}
            numeric = flatten(system)
            if baseline is None:
                baseline = numeric
            record = {
                "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "elapsed_s": capture_start - begin,
                "capture_duration_s": time.monotonic() - capture_start,
                "root_pid": args.pid,
                "root_alive": bool(processes),
                "processes": processes,
                "tree_memory_bytes": aggregate(processes, "memory_bytes", ["Rss", "Pss", "private_total", "Swap", "SwapPss"]),
                "tree_fds": aggregate(processes, "fds", ["total", "sockets", "eventpoll", "epoll_watches", "raced_or_denied"]),
                "system": system,
                "server_socket_buffers": sockets,
                "system_delta_from_first_sample": {k: v - baseline[k] for k, v in numeric.items() if k in baseline},
                "measurement_scope": "Process-tree sums: RSS can double-count shared mappings; PSS apportions them. Kernel counters are shared-host/network-namespace observations, not attributable server memory. sockstat TCP mem is in pages. FD scans and epoll reads add sampling overhead; samples are not atomic.",
                "page_size_bytes": os.sysconf("SC_PAGE_SIZE"),
                "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"),
            }
            output.write(json.dumps(record, separators=(",", ":")) + "\n")
            print(f"elapsed={record['elapsed_s']:.1f}s processes={len(processes)} pss={record['tree_memory_bytes']['Pss']} fds={record['tree_fds']['total']}", flush=True)
            if args.once or not processes or (args.duration and time.monotonic() - begin >= args.duration):
                break
            until = capture_start + args.interval
            while not stopped and time.monotonic() < until:
                time.sleep(min(0.2, until - time.monotonic()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
