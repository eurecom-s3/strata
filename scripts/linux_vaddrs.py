#!/usr/bin/env python3

import pandas
from prettytable import PrettyTable
import argparse
from pandare import Panda

# Print statistics about writes in different regions of Linux kernel address space

parser = argparse.ArgumentParser()
parser.add_argument("--kallsyms", help="kallsysm file", type=str, default="")
parser.add_argument("--panda-args", help="vm arguments to extract region symbols value", type=str, default="")
parser.add_argument("--panda-replay", help="snapshot name", type=str, default="")
parser.add_argument("vaddr_stats", help="vaddr_stats h5 file", type=str)
args = parser.parse_args()

page_offset_base = 0
vmalloc_base = 0
vmemmap_base = 0

regions = [
        [0xffff800000000000, 0xffff87ffffffffff, "Guard hole"],
        [0xffff880000000000, 0xffff887fffffffff, "LDT Remap"],
        [0xffff888000000000, 0xffffc87fffffffff, "Direct mappings"],
        [0xffffc88000000000, 0xffffc8ffffffffff, "Unused"],
        [0xffffc90000000000, 0xffffe8ffffffffff, "Vmalloc/ioremap"],
        [0xffffe90000000000, 0xffffe9ffffffffff, "Unused"],
        [0xffffea0000000000, 0xffffeaffffffffff, "Virtual memory map"],
        [0xffffeb0000000000, 0xffffebffffffffff, "Unused"],
        [0xffffec0000000000, 0xfffffbffffffffff, "KASAN shadow"],
        [0xfffffc0000000000, 0xfffffdffffffffff, "Unused"],
        [0xfffffe0000000000, 0xfffffe7fffffffff, "cpu_entry area"],
        [0xfffffe8000000000, 0xfffffeffffffffff, "Unused"],
        [0xffffff0000000000, 0xffffff7fffffffff, "ESP fixup"],
        [0xffffff8000000000, 0xffffffeeffffffff, "Unused"],
        [0xffffffef00000000, 0xfffffffeffffffff, "EFI region"],
        [0xffffffff00000000, 0xffffffff7fffffff, "Unused"],
        [0xffffffff80000000, 0xffffffff9fffffff, "Kernel text"],
        [0xffffffffa0000000, 0xfffffffffeffffff, "Module mapping space"],
        [0xffffffffff000000, 0xffffffffff5fffff, "Kernel internal fixmap"],
        [0xffffffffff600000, 0xffffffffff600fff, "Legacy vsyscall"],
        [0xffffffffffe00000, 0xffffffffffffffff, "Unused"]
        ]

if args.kallsyms:
    with open(args.kallsyms, "r") as f:
        kallsyms = {}
        for symb in f:
            s = symb.split()
            kallsyms[" ".join(s[2:])] = int(s[0], 16)

    panda = Panda(arch="x86_64", mem="4096", extra_args=args.panda_args, os="linux")
    @panda.cb_after_loadvm
    def get_base_state(cpu):
        global page_offset_base
        global vmalloc_base
        global vmemmap_base

        page_offset_base = int.from_bytes(panda.virtual_memory_read(cpu, kallsyms["page_offset_base"], 8), "little")
        vmalloc_base = int.from_bytes(panda.virtual_memory_read(cpu, kallsyms["vmalloc_base"], 8), "little")
        vmemmap_base = int.from_bytes(panda.virtual_memory_read(cpu, kallsyms["vmemmap_base"], 8), "little")

        panda.end_analysis()
    panda.run_replay(args.panda_replay)

    regions = [
        [page_offset_base, vmalloc_base, "Direct mappings"],
        [vmalloc_base, vmalloc_base + 0x1FFFFFFFFFFF, "Vmalloc/ioremap"],
        [vmemmap_base, vmemmap_base + 0xFFFFFFFFFF, "Virtual memory map"],
        [kallsyms["_stext"],  kallsyms["_stext"] + 0x1FFFFFFF, "Kernel text"]
    ]

    regions.sort()
    # for s, e, t in regions:
    #     print(hex(s), hex(e), t)

vaddrs = pandas.read_hdf(args.vaddr_stats, "data")
tot_addrs = len(vaddrs)
ssum = vaddrs.sum(axis=0)
tot_writes = ssum["write_count"]
tot_zeroes = ssum["zero_count"]
tot_ptrs = ssum["ptr_count"]
table = PrettyTable()
table.field_names = ["Region", "Addresses", "Writes", "Zeores", "Pointers"]
table.align["Region"] = "l"

print()
for start, end, name in regions:
    filter = (start<=vaddrs["vaddr"]) & (vaddrs["vaddr"]<end)
    addrs = len(vaddrs[filter])
    ssum = vaddrs[filter].sum(axis=0)
    writes = ssum["write_count"]
    zeroes = ssum["zero_count"]
    ptrs = ssum["ptr_count"]
    if not addrs and not writes and not zeroes and not ptrs:
        continue
    table.add_row([
        name,
        f"{addrs} ( {addrs/tot_addrs*100: .2f}% )",
        f"{writes} ( {writes/tot_writes*100: .2f}% )",
        f"{zeroes} ( {zeroes/tot_zeroes*100: .2f}% )",
        f"{ptrs} ( {ptrs/tot_ptrs*100: .2f}% )"
        ])

print(table)
