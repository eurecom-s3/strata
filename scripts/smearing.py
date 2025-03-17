#!/usr/bin/env python3
import argparse
from collections import defaultdict
from copy import deepcopy
import fcntl
from functools import partial
from pickle import dump
from typing import Dict, List, Union

from pandare import Panda
from volatility.framework.objects import utility
from structs import *

# This PANDA plugin analyze smearing in page tables 

ADDR_MASK = 0xFFFFFFF000

parser = argparse.ArgumentParser()
parser.add_argument('--mem', "-m", type=str, default=2048, help='Panda mem in MB')
parser.add_argument('--extra-args', "-e", default="", type=str, help='Panda extra command line')
parser.add_argument('--prompt', "-p", type=str, default=r"root@ubuntu:~#", help='Prompt shown on serial port')
parser.add_argument('--debug', "-d", action='store_true', default=False, help="Debug output")
parser.add_argument('record', type=str, help='Record name')
parser.add_argument("kallsyms", type=argparse.FileType('r'), help='kallsyms file')
parser.add_argument("iomem", type=argparse.FileType('r'), help='iomem file')
parser.add_argument("output", type=argparse.FileType('wb'), help='output file')
args = parser.parse_args()

debug = args.debug

in_dump = False
ppage_timing = PageTiming(0,0)
ppage_in_dump = -1
timestamp = 0
ppages_timestamps = defaultdict(PageTiming)

volatility = None
vmemmap_base = 0

page_tables = {}
page_tables_dead = []
pages_timestamp = {}

# Parse kallsyms
kallsyms = {}
for symb in args.kallsyms:
    s = symb.split()
    try:
        kallsyms[" ".join(s[2:])] = int(s[0], 16)
    except:
        continue
args.kallsyms.close()

# Parse iomem
iomem = []
for line in args.iomem:
    s = line.split()
    if s[-1] != "RAM":
        continue
    start, end = s[0].split("-")
    start = int(start, 16)
    end = int(end, 16) + 1
    iomem.append((start, end))
args.iomem.close()

lime_addr_start = kallsyms["lime_vaddr_start [lime]"]
lime_addr_end = kallsyms["lime_vaddr_end [lime]"]
lime_page_timestamp = kallsyms["lime_page_timestamp [lime]"]

hd_events = defaultdict(int)
net_events = defaultdict(int)

panda = Panda(arch="x86_64", mem=str(args.mem), extra_args=args.extra_args,expect_prompt=args.prompt.encode(),serial_kwargs={"unansi": False}, os="linux")

def canonical_address(addr):
    return addr | 0xffff000000000000

def get_kernel_user_pgd(pgd):
    return [pgd & 0xFFFFFFFFFFFFEFFF, pgd | 0x1000]

def page_to_phy(addr):
    # Convert a virtual address of a struct page to the physical address of the
    # real page

    ppn = (addr - vmemmap_base)//64
    return ppn << 12

def phys_to_page(phy_addr):
    # Convert a physical page address to the virtual address of the struct page associated
    ppn = phy_addr >> 12
    return vmemmap_base + ppn * 64

def virt_to_phys(addr):
    # Convert virtual address to physical one
    try:
        return panda.virt_to_phys(panda.get_cpu(), canonical_address(addr))
    except Exception as ex:
        print(f"ERROR translating hex{addr}")
        raise


def pte_free_tlb(debug, cpu, tb, h):
    global page_tables
    global page_tables_dead

    args = panda.arch.get_args(cpu, 2)
    pte_page = args[1]
    pte_phy = page_to_phy(pte_page)

    PageTable.decrease_ref_counter(pte_phy, timestamp, page_tables, page_tables_dead, debug)
    PageTable.free_pt(pte_phy, timestamp, page_tables, page_tables_dead)

    if debug:
        print(f"Remove PTE (pte_free_tlb()) {hex(pte_phy)}")

def pmd_free_tlb(debug, cpu, tb, h):
    global page_tables
    global page_tables_dead

    args = panda.arch.get_args(cpu, 2)
    pmd_page = args[1]
    pmd_phy = virt_to_phys(pmd_page)

    PageTable.decrease_ref_counter(pmd_phy, timestamp, page_tables, page_tables_dead, debug)
    PageTable.free_pt(pmd_phy, timestamp, page_tables, page_tables_dead)

    if debug:
        print(f"Remove PMD (pmd_free_tlb()) {hex(pmd_phy)}")

def pud_free_tlb(debug, cpu, tb, h):
    global page_tables
    global page_tables_dead

    args = panda.arch.get_args(cpu, 2)
    pud_page = args[1]
    pud_phy = virt_to_phys(pud_page)

    PageTable.decrease_ref_counter(pud_phy, timestamp, page_tables, page_tables_dead, debug)
    PageTable.free_pt(pud_phy, timestamp, page_tables, page_tables_dead)

    if debug:
        print(f"Remove PUD (pud_free_tlb()) {hex(pud_phy)}")

def pud_free_pmd_page(debug, cpu, tb, h):
    global page_tables
    global page_tables_dead

    args = panda.arch.get_args(cpu, 2)
    pud_page = args[0]
    pud_phy = virt_to_phys(pud_page)

    PageTable.decrease_ref_counter(pud_phy, timestamp, page_tables, page_tables_dead, debug)
    PageTable.free_pt(pud_phy, timestamp, page_tables, page_tables_dead)

    if debug:
        print(f"Remove PUD (pud_free_pmd_page()) {hex(pud_phy)}")


def manage_pgd(alloc_pt, debug, cpu, tb, h):
    global page_tables
    global page_tables_dead

    args = panda.arch.get_args(cpu, 2)
    mm = args[0]
    pgd_virt = args[1]
    pgd_phy = virt_to_phys(pgd_virt)

    if pgd_phy > iomem[-1][-1]:
        frameinfo = getframeinfo(currentframe())
        print(f"ERROR Line {frameinfo.lineno}  Address out of physical space {hex(pgd_phy)} > {hex(iomem[-1][-1])}")
        if debug:
            print(panda.callstack_callers(20, panda.get_cpu()))

    if alloc_pt:
        for pgd_phy in get_kernel_user_pgd(pgd_phy):

            # PGD already exists (?)
            if pgd_phy in page_tables:
                if debug:
                    print(f"ERROR Strange... PGD already exists?! {hex(pgd_phy)}")
                page_tables[pgd_phy].levels.add(0)
                return

            # Explore
            PageTable.new(pgd_phy, 0, timestamp, page_tables, debug)

             # Save also the process name
            if mm != 0:
                mm_struct = volatility.object("mm_struct", mm)
                if mm_struct.owner != 0:
                    page_tables[pgd_phy].proc = utility.array_to_string(mm_struct.owner.comm)

    else:
        # Remove both PGD (KPTI)
        for pgd_phy in get_kernel_user_pgd(pgd_phy):
            if debug:
                print(f"Remove PGD {hex(pgd_phy)}")

            PageTable.decrease_ref_counter(pgd_phy, timestamp, page_tables, page_tables_dead, debug)
            PageTable.free_pt(pgd_phy, timestamp, page_tables, page_tables_dead)

def free_pages(debug, cpu, tb, h):
    # Free a Page Table
    global page_tables
    global page_tables_dead

    args = panda.arch.get_args(cpu, 2)
    page = args[0]
    order = args[1]

    phy_page_start = page_to_phy(page) # virt_to_phys(page) #

    # print(hex(page), hex(phy_page_start), hex(phy_page_start + (1 << order) * 0x1000))
    for phy_page in range(phy_page_start, phy_page_start + (1 << order) * 0x1000, 0x1000):

        if phy_page not in page_tables:
            return

        PageTable.decrease_ref_counter(phy_page, timestamp, page_tables, page_tables_dead, debug)
        PageTable.free_pt(phy_page, timestamp, page_tables, page_tables_dead)

        if debug:
            print(f"Remove (free_pages()) {hex(phy_page)}")


@panda.cb_after_loadvm
def get_base_state(cpu):
    global volatility
    global page_tables
    global vmemmap_base

    # Workaround print blocking
    fcntl.fcntl(1, fcntl.F_SETFL, 0)

    # Init PageTable class
    PageTable.init(panda, iomem)

    print("Initializing Volatility 3...")
    volatility = panda.get_volatility_symbols(debug=False)
    vmemmap_base = panda.virtual_memory_read(panda.get_cpu(), canonical_address(volatility.get_symbol("vmemmap_base").address), 8, 'int')
    print("Collect page tables...")
    # Find PGD and explore them
    procs = volatility.object_from_symbol("init_task").tasks.to_list("vmlinux1!task_struct", "tasks")
    for proc in procs:

        # Ignore processes without mm_structs
        if not proc.mm:
            continue

        pgd_phy = virt_to_phys(proc.mm.pgd)
        pgd_phys = get_kernel_user_pgd(pgd_phy)

        for pgd_phy in pgd_phys:
            PageTable.new(pgd_phy, 0, 0, page_tables, debug)

            # Add process name
            page_tables[pgd_phy].proc = utility.array_to_string(proc.comm)

    print("Register pgd_ctor() callback...")
    fn_addr = canonical_address(volatility.get_symbol("pgd_ctor").address)
    new_pgd_callback = partial(manage_pgd, True, debug)
    panda.hook(fn_addr, kernel=True)(new_pgd_callback)

    print("Register pgd_dtor() callback...")
    fn_addr = canonical_address(volatility.get_symbol("pgd_free").address)
    new_pgd_callback = partial(manage_pgd, False, debug)
    panda.hook(fn_addr, kernel=True)(new_pgd_callback)

    print("Register ___pte_free_tlb() callback...")
    fn_addr = canonical_address(volatility.get_symbol("___pte_free_tlb").address)
    pte_free_tlb_callback = partial(pte_free_tlb, debug)
    panda.hook(fn_addr, kernel=True)(pte_free_tlb_callback)

    print("Register ___pmd_free_tlb() callback...")
    fn_addr = canonical_address(volatility.get_symbol("___pmd_free_tlb").address)
    pmd_free_tlb_callback = partial(pmd_free_tlb, debug)
    panda.hook(fn_addr, kernel=True)(pmd_free_tlb_callback)

    print("Register ___pud_free_tlb() callback...")
    fn_addr = canonical_address(volatility.get_symbol("___pud_free_tlb").address)
    pud_free_tlb_callback = partial(pud_free_tlb, debug)
    panda.hook(fn_addr, kernel=True)(pud_free_tlb_callback)

    print("Register pud_free_pmd_page() callback...")
    fn_addr = canonical_address(volatility.get_symbol("pud_free_pmd_page").address)
    pud_free_pmd_page_callback = partial(pud_free_pmd_page, debug)
    panda.hook(fn_addr, kernel=True)(pud_free_pmd_page_callback)

    print("Register __free_pages_ok() callback...")
    fn_addr = canonical_address(volatility.get_symbol("__free_pages_ok").address)
    free_pages_callback = partial(free_pages, debug)
    panda.hook(fn_addr, kernel=True)(free_pages_callback)

    print("Register free_unref_page() callback...")
    fn_addr = canonical_address(volatility.get_symbol("free_unref_page").address)
    free_pages_callback = partial(free_pages, debug)
    panda.hook(fn_addr, kernel=True)(free_pages_callback)
    # embed()

    panda.enable_callback('wait_for_lime')

    if debug:
        panda.require("callstack_instr")

    # panda.end_analysis()
    # embed()

@panda.cb_virt_mem_before_write(name='wait_for_lime', enabled=False)
def wait_for_lime(cpu, pc, address, size, buf):
    global lime_page_timestamp
    global lime_addr_start
    global lime_addr_end

    if address in [lime_page_timestamp, lime_addr_start, lime_addr_end]:
        print("LiME loaded")
        lime_page_timestamp = virt_to_phys(lime_page_timestamp)
        lime_addr_start = virt_to_phys(lime_addr_start)
        lime_addr_end = virt_to_phys(lime_addr_end)

        panda.disable_callback('wait_for_lime')


@panda.cb_virt_mem_before_write
def write_event(cpu, pc, address, size, buf):
    global in_dump
    global ppages_timestamps
    global ppage_in_dump
    global page_tables
    global page_tables_dead
    global timestamp
    global pages_timestamp

    address = virt_to_phys(address) # PANDA has another fucking bug... with more than 4GB of RAM return wrong physical addresses, so we cannot use cb_phys_mem_before_write

    table_address = address >> 12 << 12

    # Save timestamp of modification of each single page
    pages_timestamp[table_address] = timestamp

    # Ignore too little writes
    if size != 8:
        return

    if address == lime_page_timestamp:
        timestamp = int.from_bytes(buf[0:8], "little", signed=False)

        # Start the dump of a page
        if in_dump:
            ppage_timing.start_time = timestamp
            return

        # End of a page dump => save ppage timing
        else:
            ppage_timing.end_time = timestamp
            ppages_timestamps[ppage_in_dump] = deepcopy(ppage_timing)
            return

    # Intercept start of page dump
    elif address == lime_addr_start:

        page_in_dump = int.from_bytes(buf[0:8], "little", signed=False)
        ppage_in_dump = virt_to_phys(page_in_dump) >> 12 << 12

        # Init values before page dump start to be ignored
        if ppage_in_dump in [0xffffffffff000, 0xfffffffffffff000]:
            return

        in_dump = True

        if debug:
            print(f"Dumping ppage {hex(ppage_in_dump)}")

        # Save data
        if ppage_in_dump in page_tables:
            page_tables[ppage_in_dump].dumped = True
            page_tables[ppage_in_dump].save(page_tables, page_tables_dead)
        return

    # Intercept end of a page dump, save values at dump time
    elif address == lime_addr_end and ppage_in_dump != -1:

        in_dump = False

        if debug:
            print(f"End dump ppage {hex(ppage_in_dump)}")
        return

    # Is a write on a page table?
    elif table_address in page_tables:

        new_value = int.from_bytes(buf[0:8], "little", signed=False)
        old_value = panda.physical_memory_read(address, 8, "int")

        page_tables[table_address].update_entry(address, old_value, new_value, timestamp, page_tables, page_tables_dead, debug)


panda.enable_memcb()
panda.enable_precise_pc()
panda.run_replay(args.record)

# embed()
PageTable.panda = None
results = {"page_tables": page_tables, "page_tables_dead": page_tables_dead, "timestamps": ppages_timestamps, "pages_timestamp": pages_timestamp, "hd_events": hd_events, "net_events":net_events}
dump(results, args.output)
args.output.close()
