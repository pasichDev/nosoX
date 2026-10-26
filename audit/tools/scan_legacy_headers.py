#!/usr/bin/env python3
"""Read-only local archive inventory/header diagnostic; NOT a consensus replay.

Usage: python3 audit/tools/scan_legacy_headers.py /path/to/BLOCKS
No wallet files, DB directory contents, or network services are accessed.
"""
import argparse
import collections
import json
import os
import struct
import time
import hashlib
from pathlib import Path


def scan(path, max_height=None):
    started = time.monotonic()
    blocks = {}
    # A local diagnostic, with a finite inventory and no symlink traversal.
    with os.scandir(path) as entries:
        for entry in entries:
            if not entry.name.endswith(".blk") or not entry.name[:-4].isascii() or not entry.name[:-4].isdigit():
                continue
            if not entry.is_file(follow_symlinks=False):
                raise ValueError("numeric archive entry is not a regular file")
            height = int(entry.name[:-4])
            if height > 1000000 or len(blocks) >= 1000001 or height in blocks:
                raise ValueError("archive inventory bound or duplicate numeric height")
            blocks[height] = entry
    if not blocks:
        raise ValueError("no numeric .blk files")
    heights = sorted(blocks)
    missing = [h for h in range(heights[0], heights[-1] + 1) if h not in blocks]
    selected = [h for h in heights if max_height is None or h <= max_height]
    result = dict(archive_files=len(heights), archive_range=[heights[0], heights[-1]],
                  missing=missing, archive_bytes=sum(e.stat(follow_symlinks=False).st_size for e in blocks.values()),
                  scanned_files=len(selected), scanned_range=[selected[0], selected[-1]] if selected else [],
                  header_number_mismatch=[], truncated=[], negative_reward=[], negative_fee=[],
                  negative_order_count=[], header_reward_sum=0, header_fee_sum=0,
                  orders=0, files_with_untyped_trail=0, untyped_trail_bytes=0,
                  reward_counts=collections.Counter())
    for height in selected:
        entry = blocks[height]
        fd = os.open(entry.path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as source:
            header = source.read(368)
        if len(header) != 368:
            result["truncated"].append(height)
            continue
        number = struct.unpack_from("<q", header)[0]
        orders = struct.unpack_from("<i", header, 32)[0]
        fee, reward = struct.unpack_from("<qq", header, 352)
        if number != height:
            result["header_number_mismatch"].append([height, number])
        if reward < 0:
            result["negative_reward"].append([height, reward])
        if fee < 0:
            result["negative_fee"].append([height, fee])
        if orders < 0:
            result["negative_order_count"].append([height, orders])
        else:
            trail = entry.stat(follow_symlinks=False).st_size - 368 - orders * 562
            if trail < 0:
                result["truncated"].append(height)
            if trail > 0:
                result["files_with_untyped_trail"] += 1
                result["untyped_trail_bytes"] += trail
        result["header_reward_sum"] += reward
        result["header_fee_sum"] += fee
        result["orders"] += orders
        result["reward_counts"][reward] += 1
    result["elapsed_seconds"] = round(time.monotonic() - started, 3)
    result["script_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    result["limitations"] = ["header inventory only; no transaction signature or MD5 link verification",
                             "no economic replay, snapshot reconciliation or archive provenance authentication",
                             "local files assumed stable during diagnostic; PoS/MN tails remain untyped"]
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive")
    parser.add_argument("--max-height", type=int, help="bound header reads; inventory remains complete")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = json.dumps(scan(args.archive, args.max_height), indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(result)
    else:
        print(result, end="")
