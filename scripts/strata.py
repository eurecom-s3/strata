#!/usr/bin/env python3
import argparse
from collections import defaultdict
from functools import partial
import time
from copy import deepcopy
import signal
from pickle import dump
import sys
import fcntl

from IPython import embed
from pandare import Panda
from volatility.framework.objects import utility
from volatility.framework.constants import BANG
from structs_strata import PageTiming, DataStruct, DataStructType, Field, Versioning, StrataPtrArray
from itree import ITree
from inspect import currentframe, getframeinfo

from emu import Emulator

# PANDA Plugin to detect inconsistencies in kernel data structures

def to_canonical_address(addr):
    return addr | 0xffff000000000000

def to_volatility_address(addr):
    return addr & 0xffffffffffff

# Workaround print debug
fcntl.fcntl(1, fcntl.F_SETFL, 0)

parser = argparse.ArgumentParser()
parser.add_argument('--mem', "-m", type=str, default=2048, help='Panda mem in MB')
parser.add_argument('--extra-args', "-e", default="", type=str, help='Panda extra command line')
parser.add_argument('--prompt', "-p", type=str,
                    default=r"root@ubuntu:~#",
                    help='Prompt shown on serial port')
parser.add_argument('--debug', "-d", action='store_true', default=False, help="Debug output")
parser.add_argument('record', type=str, help='Record name')
parser.add_argument("kallsyms", type=argparse.FileType('r'), help='kallsyms file')
parser.add_argument("output", type=argparse.FileType('wb'), help='output file')
args = parser.parse_args()

debug = args.debug

# Parse kallsyms
kallsyms = {}
for symb in args.kallsyms:
    s = symb.split()
    kallsyms[" ".join(s[2:])] = int(s[0], 16)

lime_vaddr_start = kallsyms["lime_vaddr_start [lime]"]
lime_vaddr_end = kallsyms["lime_vaddr_end [lime]"]
lime_page_timestamp = kallsyms["lime_page_timestamp [lime]"]
vmalloc_start = kallsyms["vmalloc_base"]
offset_fields = defaultdict(dict)


poison_addresses = {to_volatility_address(x) for x in (0xdead000000000100, 0xdead000000000122, 0xffffffffffff)}
kmem_cache_alloc_return_offset = 0x1E4
kmem_cache_alloc_node_return_offset = 0x1FF

active_structs_phy = defaultdict(dict) # Maintain active structs using ppage as key (physical page: virt_address: datastruct)
active_structs_virt = {}               # Maintain active structs using virtual address as key (virtual address page: struct)
active_fields = {}
active_extra_fields = {}
dentry_socket = set()

dead_structs = defaultdict(list)    # Dead structures {page: [structs]}
ppages_timestamps = defaultdict(PageTiming) # Maintaint the register of dumped pages {page: PageTiming}
volatility = None                    # Volatility instance

ppage_in_dump = -1                  # Page currently in dump
ppage_timing = PageTiming(0,0)  # Timing of the page in dump
in_dump = False                     # True if it is dumping a page
timestamp = 0                       # Timstamp

stop_addresses = set()              # Addresses that, if reached, stop the exploration
explore_pipeline = {}               # Pipeline containing datastruct to explore (struct_addr, struct_type): struct)
emu = None

mnt_vfsmount_offset = 0
socket_alloc_vfs_inode_offset = 0
sfop = 0
dfop = 0

total_time = time.time()

def is_null_addr(address):
    return address == 0

def is_kernel_addr(address):
    return address >= 0x800000000000

def is_poison_addr(address):
    return address in poison_addresses

def is_addr_valid(address):
    return volatility.context.layers["primary"].is_valid(address) and address >= 0x800000000000 and address != 0 and address not in stop_addresses and address not in poison_addresses

def field_to_offset(offset_fields, field: str):
    # Given a field return the offset

    tot_offset = 0
    fields = field.split(".")
    base_type = volatility.get_type(fields[0])
    base_orig = base_type

    for level in range(len(fields) - 1):
        offset, substruct = base_type.members[fields[level + 1]]
        tot_offset += offset
        base_type = volatility.get_type(substruct.vol.type_name.split(BANG)[-1])
        if base_type.vol.type_name == "array" or not hasattr(base_type.vol, "members"):
            break

    offset_fields[base_orig.vol.type_name][tot_offset] =  ".".join(fields[1:]).split("!")[-1]
    return tot_offset

def explore_fdtable(parent):
    global explore_pipeline

    fdtable = volatility.object("fdtable", parent.address)
    fd = fdtable.fd
    max_fds = int(fdtable.max_fds)

    # Ignore invalid pointers
    if is_null_addr(fd):
        return 0

    if is_poison_addr(fd):
        return -1

    if not is_kernel_addr(fd):
        return -2

    if max_fds > 500000:
        return -3

    # Check if already exists in the pipeline, in that case return its index
    if (fd, "fdtable_ptrarray") in explore_pipeline:
        return explore_pipeline[(fd, "fdtable_ptrarray")].index

    # Check if already exists in active datastructs in that case return its index
    if fd in active_structs_virt:
        return active_structs_virt[fd].index

    # Create new datastruct
    array_size = max_fds * 8

    # Identify all the physical pages containing the struct
    try:
        addr_complete = to_canonical_address(fd)
        ppages = [panda.virt_to_phys(panda.get_cpu(), x) >> 12 << 12 for x in range(addr_complete, addr_complete + array_size, 0x1000)]
    except Exception as ex:
        print(f"ERROR: {getframeinfo(currentframe()).lineno} ARRAY Failed to resolve physical addresses for struct fdtable_ptrarray at address {hex(fd)}", file=sys.stdout)
        return -3

    ops = {x:(False, lambda ptr_addr, addr, first_exp, parent: explore_ptr(addr, "file")) for x in range(0,array_size, 8)}
    struct = StrataPtrArray.new(to_volatility_address(fd), array_size, ops, timestamp, "fdtable_ptrarray", ppages)
    explore_pipeline[(fd, "fdtable_ptrarray")] = struct

    if debug:
        print(f"explore_fdtable (base address {hex(fd)}) Add fdtable_ptrarray at address {hex(fd)}")
    return struct.index

def change_size_fdtable(new_value, parent):
    global explore_pipeline
    global active_fields

    fdtable = volatility.object("fdtable", parent.address)
    fd = fdtable.fd
    max_fds = int(fdtable.max_fds)

    # Ignore invalid pointers
    if is_null_addr(fd):
        return None

    if is_poison_addr(fd):
        return None

    if not is_kernel_addr(fd):
        return None

    if max_fds > 500000:
        return None


    if new_value == max_fds:
        return None

    try:
        fdtable_s = active_structs_virt[fd]
    except Exception as ex:
        ppage = panda.virt_to_phys(panda.get_cpu(), fd) >> 12 << 12

        if dead_structs.get(ppage, None):
            for i in dead_structs[ppage]:
                if i.address == fd and i.struct_type == "fdtable_ptrarray":
                    break
            else:
                print(f"ERROR change_size_fdtable {hex(fd)} {ex}")
        else:
            print(f"ERROR change_size_fdtable {hex(fd)} {ex}")
        return None

    fdtable_s.size = new_value * 8
    if new_value > max_fds:
        for i in range(max_fds * 8, new_value * 8, 8):
            fdtable_s.ops[i] = (False, lambda ptr_addr, addr, first_exp, parent: explore_ptr(addr, "file"))
    else:
        for i in range(new_value * 8, max_fds * 8, 8):
            active_fields.pop(fd + i, None)
            fdtable_s.ops.pop(fd +i, None)
            if not fdtable_s.dumped:
                fdtable_s.fields.pop(fd +i, None)

    if debug:
        print(f"Expand/resize fdtable_array {max_fds * 8}->{new_value * 8}")

def explore_ptr(base_addr, struct_type, offset=0, size=0):
    global explore_pipeline

    # Ignore invalid pointers
    if is_null_addr(base_addr):
        return 0

    if is_poison_addr(base_addr):
        return -1

    if not is_kernel_addr(base_addr):
        return -2

    address = base_addr + offset

    if address in stop_addresses:
        return -3

    if(address < 0):
        print("ERROR: Negative address", hex(base_addr), hex(address), file=sys.stdout)

    # Check if already exists in the pipeline, in that case return its index
    if (address, struct_type) in explore_pipeline:
        return explore_pipeline[(address, struct_type)].index

    # Check if already exists in active datastructs in that case return its index
    if address in active_structs_virt:
        return active_structs_virt[address].index

    # Create new datastruct
    struct_size = DataStruct.datastruct_types[struct_type].size
    if struct_size == 0:
        struct_size = size # Use custom size (arrays)

    # Identify all the physical pages containing the struct
    try:
        addr_complete = to_canonical_address(address)
        ppages = [panda.virt_to_phys(panda.get_cpu(), x) >> 12 << 12 for x in range(addr_complete, addr_complete + struct_size, 0x1000)]
    except Exception as ex:
        print(f"ERROR: {getframeinfo(currentframe()).lineno} Failed to resolve physical addresses for struct {struct_type} at address {hex(address)}", file=sys.stdout)
        return -3
    struct = DataStruct.new(to_volatility_address(address), timestamp, struct_type, ppages)

    explore_pipeline[(address, struct_type)] = struct

    if debug:
        print(f"explore_ptr (base address {hex(base_addr)}) Add struct {struct_type} at address {hex(address)} offset {offset}")
    return struct.index


def explore_open_ptr(address, struct_type, offset1=0, offset2=0):
    base_addr = address
    for offset in [offset1, offset2]:
        address = base_addr + offset

        # Ignore invalid pointers
        if is_null_addr(address):
            return 0

        if is_poison_addr(address):
            return -1

        if not is_kernel_addr(address):
            return -2

        if address in stop_addresses:
            return -3

        if(address < 0):
            print("ERROR: Negative address", hex(base_addr), hex(address), file=sys.stdout)
            continue

        # Check if already exists in the pipeline, in that case return its index
        if (address, struct_type) in explore_pipeline and explore_pipeline[(address, struct_type)].struct_type == struct_type :
            return explore_pipeline[(address, struct_type)].index

        # Check if already exists in active datastructs in that case return its index
        if address in active_structs_virt and active_structs_virt[address].struct_type == struct_type:
            return active_structs_virt[address].index

        # Create if it exist in struct with open heads (?)
        if base_addr in active_fields and active_fields[base_addr].struct_type == struct_type:
            return active_fields[base_addr].index

    return -4

def explore_open_head(head_addr, addr, struct_type, member, member1, first_exploration, forward=True, size=0):
    global explore_pipeline

    # Explore ALL the elements in the list if the struct is unknown otherwise explore only the near one

    # Ignore NULL pointers, stop pointers and bad addresses
    # Ignore invalid pointers
    if is_null_addr(head_addr):
        return 0

    if is_poison_addr(head_addr):
        return -1

    if not is_kernel_addr(head_addr):
        return -2

    if head_addr in stop_addresses:
        return -3

    if not forward:
        head_addr -= 8

    if first_exploration:
        # Get the  list of elements
        list_head = list(volatility.object("list_head", head_addr).to_list("vmlinux1" + BANG + struct_type, member, forward))

        # Self pointer
        if len(list_head) == 0:
            return None

        # Find the index of the first struct to pass it to the parent
        first_elem_addr = list_head[0].vol.offset
        child_idx = DataStruct.next_idx # TODO (?)

        if is_null_addr(first_elem_addr):
            return 0

        if is_poison_addr(first_elem_addr):
            return -1

        if not is_kernel_addr(first_elem_addr):
            return -2

        if first_elem_addr in stop_addresses:
            return -3

        # Check if already exists in the pipeline, in that case return its index
        if (first_elem_addr, struct_type) in explore_pipeline:
            child_idx = explore_pipeline[(first_elem_addr, struct_type)].index

        # Check if already exists in active datastructs in that case return its index
        if first_elem_addr in active_structs_virt:
            child_idx =  active_structs_virt[first_elem_addr].index

        # Explore all the elements
        for elem in list_head:
            address = elem.vol.offset

            if address < 0 or is_null_addr(address) or is_poison_addr(first_elem_addr) or not is_kernel_addr(first_elem_addr) or address in stop_addresses:
                break

            # Check if already exists in the pipeline
            if (address, struct_type) in explore_pipeline:
                continue

            # Check if already exists in active datastructs
            if address in active_structs_virt:
                continue

            # Create new datastruct
            struct_size = DataStruct.datastruct_types[struct_type].size
            if struct_size == 0:
                struct_size = size
            try:
                addr_complete = to_canonical_address(address)
                ppages = [panda.virt_to_phys(panda.get_cpu(), x) >> 12 << 12 for x in range(addr_complete, addr_complete + struct_size, 0x1000)]
            except Exception as ex:
                print(f"ERROR: {getframeinfo(currentframe()).lineno} Failed to resolve physical addresses for struct {struct_type} at address {hex(address)}", file=sys.stdout)
                continue
            struct = DataStruct.new(to_volatility_address(address), timestamp, struct_type, ppages)

            explore_pipeline[(address, struct_type)] = struct

            if debug:
                print(f"explore_open_head (head address {hex(head_addr)}) Add struct {struct_type} at address {hex(address)}")

        # We have to set ref_counters (we can do only now beacuse all the structs exists!)
        if (list_head[-1].vol.offset, struct_type) in explore_pipeline:
            prev_index = explore_pipeline[(list_head[-1].vol.offset, struct_type)].index
        elif list_head[-1].vol.offset in active_structs_virt:
            prev_index = active_structs_virt[list_head[-1].vol.offset].index
        else:
            prev_index = -1

        for elem in list_head:
            address = elem.vol.offset
            # Check if already exists in the pipeline
            if (address, struct_type) in explore_pipeline:
                if prev_index > 0 and prev_index != explore_pipeline[(address, struct_type)].index:
                    explore_pipeline[(address, struct_type)].ref_counter.add(prev_index)
                    prev_index = explore_pipeline[(address, struct_type)].index
                continue

            # Check if already exists in active datastructs
            if address in active_structs_virt:
                if prev_index > 0 and prev_index != active_structs_virt[address]:
                    active_structs_virt[address].ref_counter.add(prev_index)
                    prev_index = active_structs_virt[address].index

        return child_idx

    else:
        stype = volatility.get_type(struct_type)
        return explore_open_ptr(addr, struct_type, stype.relative_child_offset(member), stype.relative_child_offset(member1))

def explore_dinode(addr, parent):
    global explore_pipeline

    if parent.address not in dentry_socket:
        return explore_ptr(addr, "inode")

    # Explore upper socket struct
    # Ignore invalid pointers
    if is_null_addr(addr):
        return 0

    if is_poison_addr(addr):
        return -1

    if not is_kernel_addr(addr):
        return -2

    socket_alloc_addr = addr - socket_alloc_vfs_inode_offset
    return explore_ptr(socket_alloc_addr, "socket_alloc")


def explore_file_to_dentry(addr, parent):
    global explore_pipeline
    global dentry_socket

    # Check if you have to explore a socket
    parent_vol = volatility.object("file", parent.address)

    if parent_vol.f_op in [sfop, dfop]:
        dentry_socket.add(addr)
    return  explore_ptr(addr, "dentry")

def first_exploration():
    global stop_addresses
    global explore_pipeline

    # vm_area_struct
    ops = {
        field_to_offset(offset_fields, "vm_area_struct.vm_next"): (False,  lambda ptr_addr, addr, first_exp, parent: explore_ptr(addr, "vm_area_struct")),
        field_to_offset(offset_fields, "vm_area_struct.vm_file"): (False,  lambda ptr_addr, addr, first_exp, parent: explore_ptr(addr, "file")),
        field_to_offset(offset_fields, "vm_area_struct.vm_mm"): (False,  lambda ptr_addr, addr, first_exp, parent: explore_ptr(addr, "mm_struct")),
        field_to_offset(offset_fields, "vm_area_struct.vm_rb.rb_right"): (False,  lambda ptr_addr, addr, first_exp, parent: explore_ptr(addr, "vm_area_struct", -field_to_offset(offset_fields, "vm_area_struct.vm_rb"))),
        field_to_offset(offset_fields, "vm_area_struct.vm_rb.rb_left"): (False,  lambda ptr_addr, addr, first_exp, parent: explore_ptr(addr, "vm_area_struct", -field_to_offset(offset_fields, "vm_area_struct.vm_rb"))),
        }
    extra_fields = {
        field_to_offset(offset_fields, "vm_area_struct.vm_pgoff"),
        field_to_offset(offset_fields, "vm_area_struct.vm_start"),
        field_to_offset(offset_fields, "vm_area_struct.vm_end"),
        field_to_offset(offset_fields, "vm_area_struct.vm_flags"),
    }
    DataStruct.datastruct_types["vm_area_struct"] = DataStructType("vm_area_struct", volatility.get_type("vm_area_struct").vol.size, ops, extra_fields)

    # mm_struct
    ops = {
        field_to_offset(offset_fields, "mm_struct.mmap"): (False,  lambda ptr_addr, addr, first_exp, parent: explore_ptr(addr, "vm_area_struct")),
        field_to_offset(offset_fields, "mm_struct.mm_rb.rb_node"): (False,  lambda ptr_addr, addr, first_exp, parent: explore_ptr(addr, "vm_area_struct", -field_to_offset(offset_fields, "vm_area_struct.vm_rb"))),

        }
    extra_fields = {
        field_to_offset(offset_fields, "mm_struct.pgd"),
        field_to_offset(offset_fields, "mm_struct.arg_start"),
        field_to_offset(offset_fields, "mm_struct.arg_end"),
        field_to_offset(offset_fields, "mm_struct.context.vdso"),
        field_to_offset(offset_fields, "mm_struct.start_stack"),
        field_to_offset(offset_fields, "mm_struct.brk"),
        field_to_offset(offset_fields, "mm_struct.start_brk"),
        field_to_offset(offset_fields, "mm_struct.env_start"),
        field_to_offset(offset_fields, "mm_struct.env_end"),
        field_to_offset(offset_fields, "mm_struct.start_code"),
        field_to_offset(offset_fields, "mm_struct.end_code"),
        field_to_offset(offset_fields, "mm_struct.end_data"),
        field_to_offset(offset_fields, "mm_struct.start_data"),
        field_to_offset(offset_fields, "mm_struct.start_stack"),
    }
    DataStruct.datastruct_types["mm_struct"] = DataStructType("mm_struct", volatility.get_type("mm_struct").vol.size, ops, extra_fields)

    # cred
    extra_fields = {
        field_to_offset(offset_fields, "cred.uid"),
        field_to_offset(offset_fields, "cred.gid"),
        field_to_offset(offset_fields, "cred.euid"),
    }
    DataStruct.datastruct_types["cred"] = DataStructType("cred", volatility.get_type("cred").vol.size, {}, extra_fields)

    # thread_struct
    DataStruct.datastruct_types["thread_struct"] = DataStructType("thread_struct", volatility.get_type("thread_struct").vol.size, {}, {})

    # task_struct
    init_task_list = list(volatility.object_from_symbol("init_task").tasks.to_list("vmlinux1!task_struct", "tasks"))
    ops = {
        field_to_offset(offset_fields, "task_struct.tasks.next"): (False,  lambda ptr_addr, addr, first_exp, parent: explore_ptr(addr, "task_struct", -field_to_offset(offset_fields, "task_struct.tasks"))),
        field_to_offset(offset_fields, "task_struct.tasks.prev"): (False,  lambda ptr_addr, addr, first_exp, parent: explore_ptr(addr, "task_struct", -field_to_offset(offset_fields, "task_struct.tasks"))),
        field_to_offset(offset_fields, "task_struct.mm"): (False,  lambda ptr_addr, addr, first_exp, parent: explore_ptr(addr, "mm_struct")),
        field_to_offset(offset_fields, "task_struct.cred"): (False,  lambda ptr_addr, addr, first_exp, parent: explore_ptr(addr, "cred")),
        field_to_offset(offset_fields, "task_struct.thread"): (False,  lambda ptr_addr, addr, first_exp, parent: explore_ptr(addr, "thread_struct")),
        field_to_offset(offset_fields, "task_struct.fs"): (False,  lambda ptr_addr, addr, first_exp, parent: explore_ptr(addr, "fs_struct")),
        field_to_offset(offset_fields, "task_struct.files"): (False,  lambda ptr_addr, addr, first_exp, parent: explore_ptr(addr, "files_struct")),
        field_to_offset(offset_fields, "task_struct.children.next"): (False,  lambda ptr_addr, addr, first_exp, parent: explore_open_head(ptr_addr, addr, "task_struct", "sibling", "children", first_exp)),
        field_to_offset(offset_fields, "task_struct.children.prev"): (False,  lambda ptr_addr, addr, first_exp, parent: explore_open_head(ptr_addr, addr, "task_struct", "sibling", "children", first_exp, False)),

        field_to_offset(offset_fields, "task_struct.sibling.next"): (False,  lambda ptr_addr, addr, first_exp, parent: explore_open_ptr(addr, "task_struct", -field_to_offset(offset_fields, "task_struct.sibling"), -field_to_offset(offset_fields, "task_struct.children"))),
        field_to_offset(offset_fields, "task_struct.sibling.prev"): (False,  lambda ptr_addr, addr, first_exp, parent: explore_open_ptr(addr, "task_struct", -field_to_offset(offset_fields, "task_struct.sibling"), -field_to_offset(offset_fields, "task_struct.children"))),
    }
    extra_fields = {
        field_to_offset(offset_fields, "task_struct.start_time"),
        field_to_offset(offset_fields, "task_struct.comm"),
        field_to_offset(offset_fields, "task_struct.parent"),
        field_to_offset(offset_fields, "task_struct.pid"),
        field_to_offset(offset_fields, "task_struct.thread_group"),
    }
    DataStruct.datastruct_types["task_struct"] = DataStructType("task_struct", volatility.get_type("task_struct").size, ops, extra_fields, True)

    for struct in init_task_list:
        struct_addr = struct.vol.offset
        struct_size = struct.vol.size

        try:
            addr_complete = to_canonical_address(struct_addr)
            ppages = [panda.virt_to_phys(panda.get_cpu(), x) >> 12 << 12 for x in range(addr_complete, addr_complete + struct_size, 0x1000)]
        except Exception:
            print(f"ERROR: {getframeinfo(currentframe()).lineno} Failed to resolve physical addresses for struct task_struct at address {hex(struct_addr)}", file=sys.stdout)
            return

        if (struct_addr, "task_struct") not in explore_pipeline:
            explore_pipeline[struct_addr, "task_struct"] = DataStruct.new(to_volatility_address(struct_addr), timestamp, "task_struct", ppages)

    prev_struct = explore_pipeline[init_task_list[-1].vol.offset, "task_struct"]
    for struct in init_task_list:
        struct_addr = struct.vol.offset
        if prev_struct.index != explore_pipeline[struct.vol.offset, "task_struct"].index:
            explore_pipeline[struct.vol.offset, "task_struct"].ref_counter.add(prev_struct.index)
        prev_struct = explore_pipeline[struct.vol.offset, "task_struct"]

    # file
    extra_fields = {
    }
    ops = {
        field_to_offset(offset_fields, "file.f_path.dentry"): (False,  lambda ptr_addr, addr, first_exp, parent: explore_file_to_dentry(addr, parent)),
        field_to_offset(offset_fields, "file.f_path.mnt"): (False,  lambda ptr_addr, addr, first_exp, parent: explore_ptr(addr, "vfsmount")),
    }
    DataStruct.datastruct_types["file"] = DataStructType("file", volatility.get_type("file").vol.size, ops, extra_fields)

    # socket_alloc
    ops = {
        field_to_offset(offset_fields, "socket_alloc.socket.sk"): (False,  lambda ptr_addr, addr, first_exp, parent: explore_ptr(addr, "sock")),
    }
    DataStruct.datastruct_types["socket_alloc"] = DataStructType("socket_alloc", volatility.get_type("socket_alloc").vol.size, ops, {})

    # sock
    extra_fields = {
        field_to_offset(offset_fields, "sock.sk_type"),
        field_to_offset(offset_fields, "sock.__sk_common.skc_family"),
    }
    ops = {
    }
    DataStruct.datastruct_types["sock"] = DataStructType("sock", volatility.get_type("sock").vol.size, ops, {})

    # fs_struct
    extra_fields = {}
    ops = {
        field_to_offset(offset_fields, "fs_struct.root.dentry"): (False,  lambda ptr_addr, addr, first_exp, parent: explore_ptr(addr, "dentry")),
        field_to_offset(offset_fields, "fs_struct.root.mnt"): (False,  lambda ptr_addr, addr, first_exp, parent: explore_ptr(addr, "vfsmount")),
    }
    DataStruct.datastruct_types["fs_struct"] = DataStructType("fs_struct", volatility.get_type("fs_struct").vol.size, ops, extra_fields)

    # files_struct
    extra_fields = {}
    ops = {
        field_to_offset(offset_fields, "files_struct.fdt"): (False,  lambda ptr_addr, addr, first_exp, parent: explore_ptr(addr, "fdtable")),
    }
    DataStruct.datastruct_types["files_struct"] = DataStructType("files_struct", volatility.get_type("files_struct").vol.size, ops, extra_fields)

    extra_fields = {
        field_to_offset(offset_fields, "dentry.d_name.name")
    }
    ops = {
        field_to_offset(offset_fields, "dentry.d_inode"): (False,  lambda ptr_addr, addr, first_exp, parent: explore_dinode(addr, parent)),
        field_to_offset(offset_fields, "dentry.d_op"): (False,  lambda ptr_addr, addr, first_exp, parent: explore_ptr(addr, "dentry_operations")),
        field_to_offset(offset_fields, "dentry.d_parent"): (False,  lambda ptr_addr, addr, first_exp, parent: explore_ptr(addr, "dentry")),

        field_to_offset(offset_fields, "dentry.d_subdirs.next"): (False,  lambda ptr_addr, addr, first_exp, parent: explore_open_head(ptr_addr, addr, "dentry", "d_child", "d_subdirs", first_exp)),
        field_to_offset(offset_fields, "dentry.d_subdirs.prev"): (False,  lambda ptr_addr, addr, first_exp, parent: explore_open_head(ptr_addr, addr, "dentry", "d_child", "d_subdirs", first_exp, False)),

        field_to_offset(offset_fields, "dentry.d_child.next"): (False,  lambda ptr_addr, addr, first_exp, parent: explore_open_ptr(addr, "dentry", -field_to_offset(offset_fields, "dentry.d_child"), -field_to_offset(offset_fields, "dentry.d_subdirs"))),
        field_to_offset(offset_fields, "dentry.d_child.next"): (False,  lambda ptr_addr, addr, first_exp, parent: explore_open_ptr(addr, "dentry", -field_to_offset(offset_fields, "dentry.d_child"), -field_to_offset(offset_fields, "dentry.d_subdirs"))),


    }
    DataStruct.datastruct_types["dentry"] = DataStructType("dentry", volatility.get_type("dentry").vol.size, ops, extra_fields, True)

    # vfsmount
    extra_fields = {}
    ops = {
        field_to_offset(offset_fields, "vfsmount.mnt_root"): (False,  lambda ptr_addr, addr, first_exp, parent: explore_ptr(addr, "dentry")),
    }
    DataStruct.datastruct_types["vfsmount"] = DataStructType("vfsmount", volatility.get_type("vfsmount").vol.size, ops, extra_fields)

    # Metaclass
    DataStruct.datastruct_types["fdtable_ptrarray"] = DataStructType("fdtable_ptrarray", 0, {}, {})

    # fdtable
    extra_fields = {}
    ops = {
        field_to_offset(offset_fields, "fdtable.max_fds"): (True, lambda ptr_addr, new_value, first_exp, parent: change_size_fdtable(new_value, parent)),
        field_to_offset(offset_fields, "fdtable.fd"): (False,  lambda ptr_addr, addr, first_exp, parent: explore_fdtable(parent)),
    }
    DataStruct.datastruct_types["fdtable"] = DataStructType("fdtable", volatility.get_type("fdtable").vol.size, ops, extra_fields)

    # dentry_operations
    extra_fields = {
        field_to_offset(offset_fields, "dentry_operations.d_dname")
    }
    ops = {
    }
    DataStruct.datastruct_types["dentry_operations"] = DataStructType("dentry_operations", volatility.get_type("dentry_operations").vol.size, ops, extra_fields)

    # inode
    extra_fields = {
        field_to_offset(offset_fields, "inode.i_ino"),
        field_to_offset(offset_fields, "inode.i_mode"),
        field_to_offset(offset_fields, "inode.i_size"),
        field_to_offset(offset_fields, "inode.i_uid"),
        field_to_offset(offset_fields, "inode.i_atime.tv_sec"),
        field_to_offset(offset_fields, "inode.i_mtime.tv_sec"),
        }
    ops = {
        field_to_offset(offset_fields, "inode.i_sb"): (False,  lambda ptr_addr, addr, first_exp, parent: explore_ptr(addr, "super_block")),
#        field_to_offset(offset_fields, "inode.i_mapping"): (False,  lambda ptr_addr, addr, first_exp, parent: explore_ptr(addr, "address_space")), #TODO
    }
    DataStruct.datastruct_types["inode"] = DataStructType("inode", volatility.get_type("inode").vol.size, ops, extra_fields)

    # super_block
    extra_fields = {
        field_to_offset(offset_fields, "super_block.s_flags")
        }
    ops = {
        field_to_offset(offset_fields, "super_block.s_type"): (False,  lambda ptr_addr, addr, first_exp, parent: explore_ptr(addr, "file_system_type")),
        field_to_offset(offset_fields, "super_block.s_root"): (False,  lambda ptr_addr, addr, first_exp, parent: explore_ptr(addr, "dentry")),
    }
    DataStruct.datastruct_types["super_block"] = DataStructType("super_block", volatility.get_type("super_block").vol.size, ops, extra_fields)

    # address_space
    extra_fields = {
        field_to_offset(offset_fields, "address_space.i_pages.xa_head") # TODO?
        }
    ops = {}
    DataStruct.datastruct_types["address_space"] = DataStructType("address_space", volatility.get_type("address_space").vol.size, ops, extra_fields)

    # file_system_type
    extra_fields = {
        field_to_offset(offset_fields, "file_system_type.name")
        }
    ops = {
        field_to_offset(offset_fields, "file_system_type.next"): (False,  lambda ptr_addr, addr, first_exp, parent: explore_ptr(addr, "file_system_type")),
    }
    DataStruct.datastruct_types["file_system_type"] = DataStructType("file_system_type", volatility.get_type("file_system_type").vol.size, ops, extra_fields)

    struct = volatility.object_from_symbol("file_systems")
    struct_addr = struct.vol.offset
    struct_size = struct.vol.size

    try:
        addr_complete = to_canonical_address(struct_addr)
        ppages = [panda.virt_to_phys(panda.get_cpu(), x) >> 12 << 12 for x in range(addr_complete, addr_complete + struct_size, 0x1000)]
    except Exception:
        print(f"ERROR: {getframeinfo(currentframe()).lineno} Failed to resolve physical addresses for struct file_system_type at address {hex(struct_addr)}", file=sys.stdout)
        return
    explore_pipeline[struct_addr, "file_system_type"] = DataStruct.new(to_volatility_address(struct_addr), timestamp, "file_system_type", ppages)

    # Perform exploration
    explore()

def intercept_mempool_free(total_args, debug, cpu, tb, h):
    try:
        args = panda.arch.get_args(cpu, total_args)
        maddr = to_volatility_address(args[0])

        # If the address is not of a tracked struct ignore it
        if maddr not in active_structs_virt:
            return

        if debug:
            print(f"mempool_free {hex(maddr)}")

    except Exception as ex:
        print(f"ERROR: error intercepting mempool_free {ex}", file=sys.stdout)
        return

    # Remove the struct
    unalloc_struct(maddr)

def intercept_dentry_kill(total_args, debug, cpu, tb, h):
    try:
        args = panda.arch.get_args(cpu, total_args)
        maddr = to_volatility_address(args[0])

        # If the address is not of a tracked struct ignore it
        if maddr not in active_structs_virt:
            return

        if debug:
            print(f"__dentry_kill {hex(maddr)}")

    except Exception as ex:
        print(f"ERROR: error intercepting mntput_free {ex}", file=sys.stdout)
        return

    # Remove the struct
    unalloc_struct(maddr)

def intercept_free_vfsmnt(total_args, debug, cpu, tb, h):
    try:
        args = panda.arch.get_args(cpu, total_args)
        maddr = to_volatility_address(args[0]) + mnt_vfsmount_offset

        # If the address is not of a tracked struct ignore it
        if maddr not in active_structs_virt:
            return

        if debug:
            print(f"free_vfsmnt {hex(maddr)}")

    except Exception as ex:
        print(f"ERROR: error intercepting mntput_free {ex}", file=sys.stdout)
        return

    # Remove the struct
    unalloc_struct(maddr)

def intercept_destroy_inode(total_args, debug, cpu, tb, h):
    try:
        args = panda.arch.get_args(cpu, total_args)
        maddr = to_volatility_address(args[0])

        # If the address is not of a tracked struct ignore it
        if maddr not in active_structs_virt:
            return

        if debug:
            print(f"__destroy_inode {hex(maddr)}")

    except Exception as ex:
        print(f"ERROR: error intercepting __destroy_inode {ex}", file=sys.stdout)
        return

    # Remove the struct
    unalloc_struct(maddr)

def intercept_kmem_free(total_args, debug, cpu, tb, h):
    try:
        args = panda.arch.get_args(cpu, total_args)
        kcache_addr = to_volatility_address(args[0])
        maddr = to_volatility_address(args[1])
        kcache = utility.pointer_to_string(volatility.object("kmem_cache", kcache_addr).name, 100)

        # If the address is not of a tracked struct ignore it
        if maddr not in active_structs_virt:
            return

        # Workaround fdtable
        if kcache == "files_cache":
            files = volatility.object("files_struct", maddr)
            if files.fdt == files.fdtab.vol.offset:
                if debug:
                    print(f"WORKAROUND fdtable {hex(files.vol.offset)}")

                if files.fdt in active_structs_virt:
                    unalloc_struct(files.fdt)

                if files.fdt.fd in active_structs_virt:
                    unalloc_struct(files.fdt.fd)

        if debug:
            print(f"kmem_cache_free {kcache} {hex(maddr)}")

    except Exception as ex:
        print(f"ERROR: error intercepting kmem_cache_free {ex}", file=sys.stdout)
        return

    # Remove the struct
    unalloc_struct(maddr)


def unalloc_struct(addr):
    global active_fields
    global active_extra_fields
    global active_structs_virt
    global active_structs_phy
    global dead_structs
    global dentry_socket

    # Update struct counters, remove structure and put it in dead_structs
    try:
        struct = active_structs_virt.pop(addr)
    except KeyError:
        # print(f"ERROR unalloc_struct() missing struct with address {hex(addr)}")
        return

    struct.end_timestamp = timestamp
    struct.dump_version = struct.get_version()
    if struct.struct_type == "dentry":
        dentry_socket.discard(struct.address)

    for offset in struct.fields.keys():
        # Recursive dealloc for ref_counter (if needed)
        active_fields.pop(addr + offset, None)
        try:
            child_s = DataStruct.index2struct[struct.fields[offset].value]
        except KeyError:
            continue
        if struct and child_s != struct:
            child_s.ref_counter.discard(struct.index)
            # if len(child_s.ref_counter) == 0:
            #     unalloc_struct(child_s.address)

    for offset in struct.extra_fields:
        active_extra_fields.pop(addr + offset, None)

    for ppage in struct.ppages:
        dead_structs[ppage].append(active_structs_phy[ppage].pop(addr, None))

    if debug:
        ref_addr = [hex(DataStruct.index2struct[x].address) for x in struct.ref_counter]
        print(f"INFO unalloc_struct() {hex(addr)} {struct.struct_type} {struct.ref_counter} {ref_addr}")


def intercept_kfree(fname, total_args, debug, cpu, tb, h):
    global active_fields
    global active_extra_fields
    global active_structs_virt
    global active_structs_phy
    global dead_structs

    try:
        args = panda.arch.get_args(cpu, total_args)
        addr = args[0]
        maddr = to_volatility_address(addr)
        if addr == 0:
            return

    except Exception as ex:
        print(f"ERROR: Error intercepting {fname} {ex}", file=sys.stdout)
        return

    # Determine if it is a buffer allocated with kmalloc funcs or vmalloc ones
    vmalloc_alloc = (vmalloc_start <= args[0] < vmalloc_start + 0x200000000000)

    # Detetermine buf size
    if vmalloc_alloc:
        buf_size = emu.emu_find_vm_area(addr)
    else:
        buf_size = emu.emu_ksize(addr)

    daddr = maddr
    while(daddr < maddr + buf_size):
        if daddr in active_structs_virt:
            ssize = DataStruct.datastruct_types[active_structs_virt[daddr].struct_type].size
            if ssize == 0:
                ssize = active_structs_virt[daddr].size
            unalloc_struct(daddr)
            if debug:
                print(f"{fname} {hex(daddr)} total buf size {hex(buf_size)}")
            daddr += ssize
        else:
            daddr += 1

def intercept_vfree(total_args, debug, cpu, tb, h):
    global active_fields
    global active_extra_fields
    global active_structs_virt
    global active_structs_phy
    global dead_structs

    try:
        args = panda.arch.get_args(cpu, total_args)
        addr = args[0]
        maddr = to_volatility_address(addr)
        if addr == 0:
            return

    except Exception as ex:
        print(f"ERROR: Error intercepting vfree {ex}", file=sys.stdout)
        return

    buf_size = emu.emu_find_vm_area(addr)

    daddr = maddr
    while(daddr < maddr + buf_size):
        if daddr in active_structs_virt:
            ssize = DataStruct.datastruct_types[active_structs_virt[daddr].struct_type].size
            if ssize == 0:
                ssize = active_structs_virt[daddr].size
            unalloc_struct(daddr)
            if debug:
                print(f"vfree {hex(daddr)} total buf size {hex(buf_size)}")
            daddr += ssize
        else:
            daddr += 1

def explore():
    global explore_pipeline
    global active_structs_phy
    global active_structs_virt
    global active_fields
    global active_extra_fields

    while True:
        try:
            (address, struct_type), struct = explore_pipeline.popitem()
        except KeyError:
            return

        # If the struct is already tracked do not add it
        if address in active_structs_virt:
            continue

        # Add the struct
        active_structs_virt[address] = struct

        for ppage in struct.ppages:
            active_structs_phy[ppage][address] = struct

        # Explore pointers
        for offset, (bypass, f) in struct.ops.items():
            active_fields[address+offset] = struct

            try:
                child_addr = to_volatility_address(panda.virtual_memory_read(panda.get_cpu(), to_canonical_address(address + offset), 8, 'int'))
            except ValueError:
                print(f"ERROR: {getframeinfo(currentframe()).lineno} Error Struct {struct_type} Address {hex(address)} Offset {hex(offset)} return -1 at value reading", file=sys.stdout)
                continue

            if is_null_addr(child_addr):
                child_idx = 0
            else:
                if is_poison_addr(child_addr):
                    child_idx = -1
                else:
                    if not bypass and not is_addr_valid(child_addr):
                        print(f"ERROR: Invalid address {hex(child_addr)} Struct {struct_type}({hex(struct.address)}) offset {offset} dumping page {hex(ppage_in_dump)}", file=sys.stdout)
                        child_idx = -3
                    else:
                        child_idx = f(address+offset, child_addr, True, struct)
                        if child_idx is None:
                            child_idx = struct.index
                        else:
                            if child_idx > 0 and child_idx != struct.index: # Increment the reference counter only if valid and not self referenced
                                DataStruct.index2struct[child_idx].ref_counter.add(struct.index)
            struct.fields[offset] = Field(timestamp, child_idx, "", None, Versioning({},{}))

        # Explore extra fields
        for offset in DataStruct.datastruct_types[struct_type].extra_fields:
            active_extra_fields[address + offset] = struct

            try:
                fvalue = to_volatility_address(panda.virtual_memory_read(panda.get_cpu(), to_canonical_address(address + offset), 8, 'int'))
            except ValueError:
                print(f"ERROR: {getframeinfo(currentframe()).lineno} Error Struct {struct_type} Address {hex(address)} Offset {hex(offset)} return -1 at value reading", file=sys.stdout)
                continue

            struct.extra_fields[offset] = Field(timestamp, fvalue, "", None, Versioning({},{}))

panda = Panda(arch="x86_64", mem=str(args.mem), extra_args=args.extra_args,expect_prompt=args.prompt.encode(),serial_kwargs={"unansi": False}, os="linux")


# Initialize Volatility and explore the memory for the first time
@panda.cb_after_loadvm
def get_base_state(cpu):
    global volatility
    global emu
    global mnt_vfsmount_offset
    global sfop
    global dfop
    global socket_alloc_vfs_inode_offset

    # Workaround print blocking
    fcntl.fcntl(1, fcntl.F_SETFL, 0)

    print("Initializing Volatility 3...")
    volatility = panda.get_volatility_symbols(debug=False)
    # embed()

    print("Initialize unicorn...")
    emu = Emulator(panda, volatility, debug)
    # embed()

    mnt_vfsmount_offset = volatility.get_type("mount").relative_child_offset("mnt")
    sfop = volatility.get_symbol("socket_file_ops").address
    dfop = volatility.get_symbol("sockfs_dentry_operations").address
    socket_alloc_vfs_inode_offset = volatility.get_type("socket_alloc").relative_child_offset("vfs_inode")
    # embed()

    print("Create datastructures definitions and explore them...")
    first_exploration()
    # embed()

    print("Register kmem_cache_free() callback...")
    fn_addr = to_canonical_address(volatility.get_symbol("kmem_cache_free").address)
    intercept_kmem_free_callback = partial(intercept_kmem_free, 2, debug)
    panda.hook(fn_addr, kernel=True)(intercept_kmem_free_callback)

    print("Register mempool_free() callback...")
    fn_addr = to_canonical_address(volatility.get_symbol("mempool_free").address)
    intercept_mempool_free_callback = partial(intercept_mempool_free, 1, debug)
    panda.hook(fn_addr, kernel=True)(intercept_mempool_free_callback)

    print("Register vfree() callback...")
    fn_addr = to_canonical_address(volatility.get_symbol("vfree").address)
    intercept_vfree_callback = partial(intercept_vfree, 1, debug)
    panda.hook(fn_addr, kernel=True)(intercept_vfree_callback)

    print("Register dentry_kill() callback...")
    fn_addr = to_canonical_address(volatility.get_symbol("__dentry_kill").address)
    intercept_dentry_kill_callback = partial(intercept_dentry_kill, 1, debug)
    panda.hook(fn_addr, kernel=True)(intercept_dentry_kill_callback)

    print("Register free_vfsmnt() callback...")
    fn_addr = to_canonical_address(volatility.get_symbol("free_vfsmnt").address)
    intercept_free_vfsmnt_callback = partial(intercept_free_vfsmnt, 1, debug)
    panda.hook(fn_addr, kernel=True)(intercept_free_vfsmnt_callback)

    print("Register __destroy_inode() callback...")
    fn_addr = to_canonical_address(volatility.get_symbol("__destroy_inode").address)
    intercept_destroy_inode_callback = partial(intercept_destroy_inode, 1, debug)
    panda.hook(fn_addr, kernel=True)(intercept_destroy_inode_callback)


    print("Register free() callbacks...")
    # We do not track kvfree) because it calls kfree() or vfree() directly
    for free_f in ["kfree", "kfree_sensitive", "kfree_const"]:
        intercept_kfree_callback = partial(intercept_kfree, free_f, 1, True)
        fn_addr = to_canonical_address(volatility.get_symbol(free_f).address)
        assert(fn_addr)
        panda.hook(fn_addr, kernel=True)(intercept_kfree_callback)

    # # Register CTRL-C handler
    # def handler(_signum, _frame):
    #     embed()
    # signal.signal(signal.SIGINT, handler)

    # embed()
    # panda.end_analysis()

@panda.cb_virt_mem_before_write
def write_event(cpu, pc, address, size, buf):
    global ppage_in_dump
    global active_structs_phy
    global ppage_timing
    global active_extra_fields
    global in_dump
    global timestamp

    # Ignore not in kernel writes
    if address < 0xffff800000000000:
        return

    # Intercept change in dump timestamp (WORKAROUND...fuck! we have to collect time before write on lime_vaddr_start and after lime_vaddr_end...)
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

            # Save field values cristalized in dump
            for datastruct_a in active_structs_phy[ppage_in_dump].keys():
                datastruct = active_structs_phy[ppage_in_dump][datastruct_a]

                # Find fields belonging to the physical page dumped
                for idx, s_ppage in enumerate(datastruct.ppages):
                    if s_ppage == ppage_in_dump:
                        break
                else:
                    print("ERROR: ppage missing?!", file=sys.stdout)
                    return

                m = idx * 0x1000
                M = m + 0x1000

                # Save data structure version only if the dump process does not already
                # dumped another page of the data struct
                if not datastruct.dumped and datastruct.ppages.index(ppage_in_dump) == 0:
                    datastruct.dump_version = datastruct.get_version()

                if datastruct.ppages[-1] == ppage_in_dump:
                    datastruct.dumped = True

                # Save pointer values
                for field in datastruct.fields:
                    if m <= field < M:
                        datastruct.fields[field].dump_value = datastruct.fields[field].value
                        # Save the version of the data structure pointed
                        try:
                            index = datastruct.fields[field].value
                            if index > 0:
                                datastruct.fields[field].dump_type = DataStruct.index2struct[index].struct_type

                            datastruct.fields[field].dump_value = index
                            if index > 0:
                                datastruct.fields[field].dump_target_version = DataStruct.index2struct[index].get_version()
                        except KeyError:
                            print(f"ERROR Missing index {index}")

                # Save extra fields
                for field in datastruct.extra_fields:
                    if m <= field < M:
                        datastruct.extra_fields[field].dump_value = datastruct.extra_fields[field].value
            return

    # Intercept start of page dump
    if address == lime_vaddr_start:

        page_in_dump = int.from_bytes(buf[0:8], "little", signed=False)
        try:
            ppage_in_dump = panda.virt_to_phys(cpu, page_in_dump) >> 12 << 12
        except Exception as ex:
            print(f"ERROR: Error resolving ppage start {ex}", file=sys.stdout)
            return

        # Init values before page dump start to be ignored
        if ppage_in_dump in [0xffffffffff000, 0xfffffffffffff000]:
            return

        in_dump = True

        if debug:
            print(f"Dumping ppage {hex(ppage_in_dump)}")
        return

    # Intercept end of a page dump, save values at dump time
    if address == lime_vaddr_end and ppage_in_dump != -1:

        in_dump = False

        if debug:
            print(f"End dump ppage {hex(ppage_in_dump)}")
        return

    # Intercept extra fields writes
    maddr = to_volatility_address(address)
    if maddr in active_extra_fields:
        struct = active_extra_fields[maddr]
        foff = maddr - struct.address

        # Change last modify only if it is not already dumped
        if not struct.dumped:
            struct.last_modify = timestamp

        # Update counters of the field
        fvalue = int.from_bytes(buf[0:size], "little", signed=False)
        if foff not in struct.extra_fields:
            struct.extra_fields[foff] = Field(timestamp, fvalue, "", None, Versioning({},{}))
        else:
            if not struct.dumped:
                struct.extra_fields[foff].last_modify = timestamp
            struct.extra_fields[foff].value = fvalue
        return

    # Intercept struct kernel write on structural pointer
    if maddr in active_fields:
        struct = active_fields[maddr]
        foff = maddr - struct.address

        new_value = int.from_bytes(buf[0:8], "little", signed=False)
        mnew_value = to_volatility_address(new_value)

        # Get old value
        try:
            old_value = to_volatility_address(panda.virtual_memory_read(cpu, address, 8, 'int'))
        except Exception:
            print(f"ERROR reading struct at address {hex(address)}")
            return

        # Change last modify only if it is not already dumped
        if not struct.dumped:
            struct.last_modify = timestamp

        # Decrement reference counter
        if old_value in active_structs_virt:
            active_structs_virt[old_value].ref_counter.discard(struct.index)
            # if len(active_structs_virt[old_value].ref_counter) == 0:
            #     unalloc_struct(old_value)
            #     if debug:
            #         print(f"Dealloc {hex(old_value)} for ref_counter")

        # Check if it is a tracked pointer in that case check if we need to explore the struct
        if foff in struct.ops:

            if debug:
                print(f"PC: {hex(pc)} - Struct {struct.struct_type} - Address {hex(struct.address)} - Offset: {foff} - Value: {hex(old_value)} -> {hex(mnew_value)}")

            # If the fields is not a valid address ignore it
            if not struct.ops[foff][0] and not is_addr_valid(mnew_value):
                return

            # Call the exploration function for the field and update parent field
            child_idx =  struct.ops[foff][1](maddr, mnew_value, False, struct)
            if child_idx is None:
                child_idx = struct.index

            # Create or update the field
            if foff not in struct.fields:
                struct.fields[foff] = Field(timestamp, child_idx, "", None, Versioning({},{}))
            else:
                if not struct.dumped:
                    struct.fields[foff].last_modify = timestamp
                struct.fields[foff].value = child_idx

            # Explore new struct
            explore()


panda.enable_memcb()
panda.enable_precise_pc() #Needed?!
panda.run_replay(args.record)


# Save results
results = {}
dead_s = {}
results_d = {"structs": results, "dead_structs": dead_s, "ppages": ppages_timestamps, "offset_fields": offset_fields}
for struct in active_structs_virt.values():
    try:
        del struct.ops
    except:
        pass
    results[struct.index] = struct
for struct_l in dead_structs.values():
    for struct in struct_l:
        try:
            del struct.ops
        except:
            pass
        dead_s[struct.index] = struct

dump(results_d, args.output)
args.output.close()
# embed()
