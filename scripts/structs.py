from copy import deepcopy
from struct import iter_unpack
from dataclasses import dataclass
from enum import Enum
from inspect import currentframe, getframeinfo
from typing import Dict, List, Union

ADDR_MASK = 0xFFFFFFF000

@dataclass
class PageTiming:
    start_time: int
    end_time: int

class EntryType(Enum):
    NotPresent = 0
    Table = 1
    Page = 2
    HugePage = 3
    Error = 4

@dataclass
class Versioning:
    present: int
    rw: int
    uk: int
    x: int
    huge: int
    address: int

@dataclass
class PageEntry:
    etype: EntryType
    value: int
    perms: int
    last_modify: int
    dump_value: Union[int, None]
    dump_perms: Union[int, None]
    dump_type: Union[EntryType, None]
    dump_target_version: Versioning

class PageTable:
    panda = None
    counter = 1
    index2address = {}
    iomem = {}

    def __init__(self, index: int, ppage: int, level: int, start_time:int):
        self.index = index
        self.ppage =  ppage
        self.levels = {level}
        self.dumped = False
        self.start_time = start_time
        self.end_time = None
        self.last_modify = start_time
        self.entries = []
        self.ref_counter = 1
        self.proc = ""
        self.dead_version = Versioning(0,0,0,0,0,0)
        self.dump_version = Versioning(0,0,0,0,0,0)

    @classmethod
    def new_index(cls):
        current_counter = cls.counter
        cls.counter += 1
        return current_counter

    @classmethod
    def init(cls, panda, iomem):
        cls.panda = panda
        cls.iomem = iomem

    @classmethod
    def compact_perms(cls, value:int):
        # Format: U/K RWX
        return  (value & 0x4) << 1 | \
                (1 << 3) | \
                (value & 0x2) | \
                (value & 0x8000000000000000) >> 63

    @classmethod
    def new(cls, ppage:int , level:int , start_time:int, page_tables, debug=False):

        if ppage > cls.iomem[-1][-1]:
            frameinfo = getframeinfo(currentframe())
            print(f"ERROR Line {frameinfo.lineno} Address out of physical space (level: {level}) {hex(ppage)} > {hex(cls.iomem[-1][-1])}")
            if debug:
                print(cls.panda.callstack_callers(20, cls.panda.get_cpu()))
            return -1

        # Page already existent
        if ppage in page_tables:
            page_tables[ppage].levels.add(level)
            return page_tables[ppage].index

        # Create and the explore it
        index = cls.new_index()
        pt = PageTable(index, ppage, level, start_time)
        page_tables[ppage] = pt
        cls.index2address[index] = ppage

        # Get the entries
        entries = []
        content = cls.panda.physical_memory_read(ppage, 0x1000)
        for entry_raw in iter_unpack("<Q", content):
            entry_raw = entry_raw[0]

            # NotPresent entry
            if not(entry_raw & 0x1):
                etype = EntryType.NotPresent
                entry = PageEntry(etype, 0, 0, start_time, None, None, None, Versioning(0,0,0,0,0,0))
                entries.append(entry)
                continue

            # PTE
            elif level == 3:
                etype = EntryType.Page
                address = entry_raw & ADDR_MASK
                entry = PageEntry(etype, address, cls.compact_perms(entry_raw), start_time, None, None, None, Versioning(0,0,0,0,0,0))
                entries.append(entry)
                continue

            # Huge Page PUD
            elif level == 1 and entry_raw & 0x80:
                etype = EntryType.HugePage
                address = ((entry_raw & 0xFFC0000000) >> 30 ) << 0x40000000
                entry = PageEntry(etype, address, cls.compact_perms(entry_raw), start_time, None, None, None, Versioning(0,0,0,0,0,0))
                entries.append(entry)
                continue

            # Huge Page PMD
            elif level == 2 and entry_raw & 0x80:
                etype = EntryType.HugePage
                address = ((entry_raw & 0xFFFFF00000) >> 20) << 0x200000
                entry = PageEntry(etype, address, cls.compact_perms(entry_raw), start_time, None, None, None, Versioning(0,0,0,0,0,0))
                entries.append(entry)
                continue

            # Page Table
            else:
                etype = EntryType.Table
                address = entry_raw & ADDR_MASK

                # Check if it must be explored
                if address in page_tables:
                    child_index = page_tables[address].index
                    page_tables[address].increase_ref_counter()
                else:
                    child_index = cls.new(address, level+1, start_time, page_tables, debug)
                    if child_index == -1:
                        etype = EntryType.Error
                entry = PageEntry(etype, child_index, cls.compact_perms(entry_raw), start_time, None, None, None, Versioning(0,0,0,0,0,0))
                entries.append(entry)

        # Save the entries
        page_tables[ppage].entries = entries
        if debug:
            if level == 0:
                t = "PGD"
            elif level == 1:
                t = "PUD"
            elif level == 2:
                t = "PMD"
            else:
                t = "PTE"
            print(f"Add {t} {hex(ppage)}")
        return page_tables[ppage].index

    def get_version(self):
        # Read page
        content = self.panda.physical_memory_read(self.ppage, 0x1000)
        presents = []
        rws = []
        uks = []
        xs = []
        huges = []
        addresses = []
        for value in iter_unpack("<Q", content):
            value = value[0]
            present = value & 0x1
            presents.append(present)

            if present:
                rws.append(value & 0x2)
                uks.append(value & 0x4)
                xs.append(value & 0x8000000000000000)

                if value & 0x80:
                    if self.levels.intersection([0,3]):
                        huges.append(0)
                        addresses.append(value & ADDR_MASK)
                    else:
                        huges.append(1)
                        if 1 in self.levels:
                            addresses.append(((value & 0xFFC0000000) >> 30) << 0x40000000)
                        else:
                            addresses.append(((value & 0xFFFFF00000) >> 20) << 0x200000)
                else:
                    huges.append(0)
                    addresses.append(value & ADDR_MASK)
                
            else:
                rws.append(None)
                uks.append(None)
                xs.append(None)
                huges.append(None)
                addresses.append(None)

        return Versioning(
            hash(tuple(presents)),
            hash(tuple(rws)),
            hash(tuple(uks)),
            hash(tuple(xs)),
            hash(tuple(huges)),
            hash(tuple(addresses))
        )

    def update_entry(self, field_address: int, old_value: int, new_value: int, timestamp:int,  page_tables, page_tables_dead, debug=False):
        # We track changes only on P, RW, US, XD, HUGE, and address field

        changes = new_value ^ old_value
        if changes & 0x800000FFFFFFF187:

            entry_idx = (field_address - self.ppage) // 8
            if not self.dumped:
                self.last_modify = timestamp
                self.entries[entry_idx].last_modify = timestamp
            level = min(self.levels) # We are conservaite in order to not introduce invalid PTs

            if debug:
                print(f"Modify page table {hex(self.ppage)} levels: {self.levels} Entry: {entry_idx} {hex(old_value)}({hex(old_value & ADDR_MASK)}) -> {hex(new_value)}({hex(new_value & ADDR_MASK)})")

            # Decrease the reference counter of the old table
            if self.entries[entry_idx].etype == EntryType.Table:
                try:
                    address = PageTable.index2address[self.entries[entry_idx].value]
                except KeyError:
                    index = self.entries[entry_idx].value
                    for pg_dead in page_tables_dead:
                        if pg_dead.index == index:
                            print(f"WARN Page with index {hex(index)} already dead")
                            break
                    else:
                        print(f"WARN missing page in index2address {hex(self.entries[entry_idx].value)}")
                    return
                PageTable.decrease_ref_counter(address, timestamp, page_tables, page_tables_dead, debug)

            # NotPresent entry
            if not(new_value & 0x1):
                self.entries[entry_idx].etype = EntryType.NotPresent
                self.entries[entry_idx].value = 0
                self.entries[entry_idx].perms = 0

            # PTE
            elif level == 3:
                self.entries[entry_idx].etype = EntryType.Page
                self.entries[entry_idx].value = new_value & ADDR_MASK
                self.entries[entry_idx].perms = PageTable.compact_perms(new_value)

            # Huge Page PUD
            elif level == 1 and new_value & 0x80:
                self.entries[entry_idx].etype = EntryType.HugePage
                self.entries[entry_idx].value = ((new_value & 0xFFC0000000) >> 30) << 0x40000000
                self.entries[entry_idx].perms = PageTable.compact_perms(new_value)

            # Huge Page PMD
            elif level == 2 and new_value & 0x80:
                self.entries[entry_idx].etype = EntryType.HugePage
                self.entries[entry_idx].value = ((new_value & 0xFFFFF00000) >> 20) << 0x200000
                self.entries[entry_idx].perms = PageTable.compact_perms(new_value)

            # Page Table
            else:
                # We have to track changes also if already dump
                self.entries[entry_idx].etype = EntryType.Table
                address = new_value & ADDR_MASK

                # Explore only if not already tracked
                if address in page_tables:
                    index = page_tables[address].index
                    page_tables[address].increase_ref_counter()
                else:
                    index = PageTable.new(address, level + 1, timestamp, page_tables, debug)
                    if index == -1:
                        self.entries[entry_idx].etype = EntryType.Error

                self.entries[entry_idx].value = index
                self.entries[entry_idx].perms = PageTable.compact_perms(new_value)

    def increase_ref_counter(self):
        self.ref_counter += 1

    @classmethod
    def decrease_ref_counter(cls, page:int, timestamp:int, page_tables, page_table_dead, debug=False):
        if page not in page_tables:
            return

        if debug:
            level = min(page_tables[page].levels)
            if level == 0:
                t = "PGD"
            elif level == 1:
                t = "PUD"
            elif level == 2:
                t = "PMD"
            else:
                t = "PTE"
            print(f"Deallocate {t} (levels {page_tables[page].levels}) for ref count {hex(page) }")

        page_tables[page].ref_counter -= 1

        if page_tables[page].ref_counter == 0:
            for idx in range(512):
                if page_tables[page].entries[idx].etype == EntryType.Table:
                    if page_tables[page].entries[idx].value in PageTable.index2address:
                        address = PageTable.index2address[page_tables[page].entries[idx].value]
                        PageTable.decrease_ref_counter(address, timestamp, page_tables, page_table_dead, debug)
            PageTable.free_pt(page, timestamp, page_tables, page_table_dead)

    @classmethod
    def free_pt(cls, phy_addr, timestamp, page_tables, page_tables_dead):
        try:
            table = page_tables.pop(phy_addr)
            table.end_time = timestamp
            table.dead_version = table.get_version()
            page_tables_dead.append(table)
            
        except KeyError:
            pass

    def save(self, page_tables, page_tables_dead):
        self.dump_version = self.get_version()
        for idx in range(512):
            self.entries[idx].dump_value = self.entries[idx].value
            self.entries[idx].dump_perms = self.entries[idx].perms
            self.entries[idx].dump_type = self.entries[idx].etype
            self.entries[idx].dump_perms = self.entries[idx].perms
            if self.entries[idx].etype == EntryType.Table:
                try:
                    child_addr = PageTable.index2address[self.entries[idx].value]
                except KeyError:
                    print(f"ERROR Address of table with index {hex(self.entries[idx].value)} not found")
                    continue
                if child_addr in page_tables:
                    version = page_tables[child_addr].get_version()
                elif child_addr in page_tables_dead:
                    version = page_tables_dead[child_addr].dead_version
                else:
                    print(f"ERROR Table not found {hex(child_addr)}")
                    continue

                self.entries[idx].dump_target_version = version
