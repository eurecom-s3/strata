#!/usr/bin/env python3
import argparse
from collections import defaultdict
from copy import deepcopy
from pickle import dump
from struct import iter_unpack

from pandare import Panda
from dataclasses import dataclass

# PANDA Python plugin to collect information about pointers and memory pages on
# a Generic OS

@dataclass
class PageTiming:
    start_time: int
    end_time: int

class Page:
    def __init__(self, ppage: int):
        self.ppage =  ppage
        self.pointers = {}
        self.dump_version = None

parser = argparse.ArgumentParser()
parser.add_argument('--mem', "-m", type=str, default=2048, help='Panda mem in MB')
parser.add_argument('--extra-args', "-e", default="", type=str, help='Panda extra command line')
parser.add_argument('--prompt', "-p", type=str, default=r"root@ubuntu:~#", help='Prompt shown on serial port')
parser.add_argument('--debug', "-d", action='store_true', default=False, help="Debug output")
parser.add_argument('record', type=str, help='Record name')
parser.add_argument("mem_regions", type=argparse.FileType('r'), help='mtree file')
parser.add_argument("total_instrs", type=argparse.FileType('r'), help='total instruction file')
parser.add_argument("output", type=str, help='output dir file')
args = parser.parse_args()

debug = args.debug

ppage_timing = PageTiming(0,0)
timestamp = 0
pages = {}
pages_timestamps = []
total_writes = defaultdict(int)       # Writes per page
vaddrs = defaultdict(int)

# Parse memory regions (taken from QEMU info mtree -f file)
iomem = []
total_pages = 0
for line in args.mem_regions:
    s = line.strip().split()
    if not len(s):
        continue
    if "pc.ram" not in s[-1] and "pc.ram" not in s[-2]:
        continue
    start, end = s[0].split("-")
    start = int(start, 16)
    end = int(end, 16) + 1
    total_pages += (end - start) // 0x1000
    for p in range(start, end, 0x1000):
        pages[p] = Page(p)
    iomem.append((start, end))
args.mem_regions.close()
page_in_dump = iomem[0][0]

# print(iomem)

total_instrs = int(args.total_instrs.readline().rstrip('\n'), 10)
args.total_instrs.close()
# print(total_instrs)

instr_per_page = total_instrs // total_pages
for idx, page in enumerate(pages.keys()):
    pages_timestamps.append((page, PageTiming(instr_per_page * idx, instr_per_page * (idx + 1))))
current_page_index = 0

panda = Panda(arch="x86_64", mem=str(args.mem), extra_args=args.extra_args,expect_prompt=args.prompt.encode(),serial_kwargs={"unansi": False}, os="linux")

# Stats on memory fragmentation
@panda.cb_after_loadvm
def fragmentation(cpu):
    pgd = cpu.env_ptr.cr[3] >> 12 << 12
    ppages = set()
    ppages_huge = set()
    try:
        table_l0 = panda.physical_memory_read(pgd, 0x1000)
    except Exception as ex:
        print(f"ERROR: explore_radix_tree Failing reading physical page {ex}")
        return

    # LEVEL 0
    for idx_l0, entry_l0 in enumerate(iter_unpack("<Q", table_l0)):
        entry_l0 = entry_l0[0]
        if not (entry_l0 & 0x1):
            continue

        vaddr = idx_l0 << 39
        if vaddr < 0x800000000000:
            continue

        vaddr_l0 = vaddr | 0xffff800000000000
        table_addr_l1 = (entry_l0 >> 12 << 12) & 0x3fffffffff000
        try:
            table_l1 = panda.physical_memory_read(table_addr_l1, 0x1000)
        except Exception as ex:
            print(f"ERROR: explore_radix_tree Failing reading physical page {hex(table_addr_l1)} {ex}")
            continue

        # LEVEL 1
        for idx_l1, entry_l1 in enumerate(iter_unpack("<Q", table_l1)):
            entry_l1 = entry_l1[0]
            if not (entry_l1 & 0x1):
                continue

            if ((entry_l1 >> 7) & 0x1):
                vaddr_l1 = vaddr_l0 | (idx_l1 << 39)
                page_addr = (entry_l1 >> 30 << 30) & 0x3fffffffff000
                for p in range(page_addr, page_addr + 0x40000000, 0x1000):
                    ppages_huge.add(p)
                continue

            table_addr_l2 = (entry_l1 >> 12 << 12) & 0x3fffffffff000
            vaddr_l1 = vaddr_l0 | (idx_l1 << 30)
            try:
                table_l2 = panda.physical_memory_read(table_addr_l2, 0x1000)
            except Exception as ex:
                print(f"ERROR: explore_radix_tree Failing reading physical page {hex(table_addr_l2)} {ex}")
                continue
            # LEVEL 2
            for idx_l2, entry_l2 in enumerate(iter_unpack("<Q", table_l2)):
                entry_l2 = entry_l2[0]
                if not (entry_l2 & 0x1):
                    continue

                if ((entry_l2 >> 7) & 0x1):
                    vaddr_l2 = vaddr_l1 | (idx_l2 << 30)
                    page_addr = (entry_l2 >> 21 << 21) & 0x3fffffffff000
                    for p in range(page_addr, page_addr + 0x200000, 0x1000):
                        ppages_huge.add(p)
                    continue

                table_addr_l3 = (entry_l2 >> 12 << 12) & 0x3fffffffff000
                vaddr_l2 = vaddr_l1 | (idx_l2 << 20)
                try:
                    table_l3 = panda.physical_memory_read(table_addr_l3, 0x1000)
                except Exception as ex:
                    print(f"ERROR: explore_radix_tree Failing reading physical page {hex(table_addr_l3)} {ex}")
                    continue

                 # LEVEL 3
                for idx_l3, entry_l3 in enumerate(iter_unpack("<Q", table_l3)):
                    entry_l3 = entry_l3[0]
                    if not (entry_l3 & 0x1):
                        continue

                    page_addr = (entry_l3 >> 12 << 12) & 0x3fffffffff000
                    vaddr_l3 = vaddr_l2 | (idx_l3 << 12)
                    ppages.add(page_addr)

    with open(args.output + "/kernel_pages", "wb") as f:
        dump({"ppages": ppages, "ppages_huge": ppages_huge}, f)

def virt_to_phys(addr):
    # Convert virtual address to physical one
    try:
        phy = panda.virt_to_phys(panda.get_cpu(), addr)
        if phy == 0xffffffffffffffff:
            phy = -1
        return phy
    except Exception as ex:
        print(f"ERROR translating hex{addr}")
        raise

@panda.cb_virt_mem_after_write
def write_event(cpu, pc, address, size, buf):
    global pages_timestamps
    global page_in_dump
    global pages
    global timestamp
    global total_writes
    global current_page_index
    global vaddrs

    # Not a kernel address (and not in kernel mode)
    if address < 0xffff800000000000:
        return

    # Update counter of writes in kernel mode (only on RAM pages)
    paddr = virt_to_phys(address)
    if paddr == -1:
        return
    ppage = paddr >> 12 << 12
    for start, end in iomem:
        if start <= ppage < end:
            total_writes[ppage] += 1
            break

    # Emulate dump
    current_instr = panda.rr_get_guest_instr_count()

    if current_page_index < len(pages_timestamps) and current_instr >= pages_timestamps[current_page_index][1].end_time:
        dump_page = pages_timestamps[current_page_index][0]

        page_content = panda.physical_memory_read(dump_page, 0x1000)
        pages[dump_page].dump_version = hash(page_content)

        # Explore the page looking for pointers
        pointers = {}

        for value in iter_unpack("<Q", page_content):
            if value[0] < 0xffff800000000000: # Not a kernel address (canonical form)
                continue

            phy_addr = virt_to_phys(value[0])
            if phy_addr == -1:
                continue
            dest_ppage = phy_addr >> 12 << 12

            vaddrs[value[0]] += 1
            if dest_ppage in pointers:
                pointers[dest_ppage][0] += 1
            else:
                dest_page_hash = hash(panda.physical_memory_read(dest_ppage, 0x1000))
                pointers[dest_ppage] = [1, dest_page_hash]

        pages[dump_page].pointers = pointers
        current_page_index += 1

        if debug:
            print(f"Page {hex(dump_page)} dumped ({current_page_index / total_pages * 100} %) pointers {len(pointers) if len(pointers) else 'NONE'}")

panda.enable_memcb()
panda.enable_precise_pc()
panda.run_replay(args.record)

results = {"pages": pages, "timestamps": pages_timestamps, "total_writes": total_writes}
with open(args.output + "/results_pointers", "wb") as f:
    dump(results, f)