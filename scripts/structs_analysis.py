#!/usr/bin/env python3
# This script analyze inconsistencies in kernel data structures

from pickle import load
from statistics import mean
from collections import defaultdict
import gc
from tqdm import tqdm
from math import ceil
import os


ARTIFACTS = os.getenv("ARTIFACTS")
files = [f"{ARTIFACTS}/smearing/{i}/result_strata_{i}" for i in range(10)]
inconsistencies = [list() for x in range(5)]    # Different type of inconsistency
version_fields_counters = []
dumped = []
existents = []
offset_fields = {}

print("Load datasets... (slow)")
for file_idx, filename in enumerate(tqdm(files)) :
    for i in range(len(inconsistencies) - 1):
        inconsistencies[i].append(defaultdict(list))
    inconsistencies[4].append(0)

    
    version_fields_counters.append({"pointers": defaultdict(int), "extra_fields": defaultdict(int)})
    dumped.append(defaultdict(int))
    existents.append(defaultdict(int))
    
    try:
        # Open file
        with open(filename, "rb") as f:
            data = load(f)
    except Exception as e:
        print(f"{file_idx} INVALID")
    
    # Reorganize data
    tms = data["ppages"]
    structs = data["structs"]
    structs_d = data["dead_structs"]
    
    offset_fields = {}
    for k,v in data["offset_fields"].items():
        offset_fields[k.split("!")[-1]] = v
    
    # Struttures created (present int dump) and not deallocated during the execution
    for struct in structs.values():
        if struct.start_timestamp == 0:
            existents[-1][struct.struct_type] += 1
    
    # Reorganize to speedup lookups
    struct_by_index = {}
    struct_by_ppage = defaultdict(list)
    all_structs = list(structs_d.values()) + list(structs.values())
    for pg in structs.values():
        struct_by_index[pg.index] = pg
        for i in pg.ppages:
            struct_by_ppage[i].append(pg)
    for pg in structs_d.values():
        struct_by_index[pg.index] = pg
        for i in pg.ppages:
            struct_by_ppage[i].append(pg)
        
    for i in struct_by_ppage:
        struct_by_ppage[i].sort(key=lambda x: x.start_timestamp)
        
    # Page tables dumped/not dumped
    dumped_structs = []
    for v in all_structs:
        if v.dumped:
            dumped_structs.append(v)

    offset_fields.update(data["offset_fields"])


    # S in Ps and D in Pd in memory was S->D and in dump dS -?-> dD
    unique_dest = set()
    for pg in dumped_structs:
        
        dumped[-1][pg.struct_type] += 1
        
        # Start and end time of source page dump
        tss = tms[min(pg.ppages)].start_time
        tse = tms[min(pg.ppages)].end_time
        
        if pg.end_timestamp and tse > pg.end_timestamp:
            continue
        
        for entry_idx, entry in pg.fields.items():
                        
            # Consider only entry pointing to tables
            if entry.dump_value <= 0:
                continue
                
            # Start and end time of destination page dump
            dest = struct_by_index[entry.dump_value]
            tds = tms[min(dest.ppages)].start_time
            tde = tms[min(dest.ppages)].end_time
                            
            # Source dumped before destination (inconsistencies type 1,2)
            if tse < tds:
                
                # before dump start
                if dest.end_timestamp == 0:
                    continue
                
                # destination is deallocated before its dump
                if dest.end_timestamp and dest.end_timestamp <= tds:
                    
                    # It exists a replacment? 
                    # The replacement structure must be allocated after the deallocation of dest and has to be survived at least at the dump of the page
                    for new_dest in struct_by_ppage[min(dest.ppages)]:
                        
                        # Self reference 
                        if new_dest.index == dest.index:
                            continue

                        if dest.end_timestamp <= new_dest.start_timestamp and (new_dest.end_timestamp is None or (new_dest.end_timestamp is not None and new_dest.end_timestamp > tde)):
                            
                            if entry.dump_type == new_dest.struct_type:
                                inconsistencies[2][file_idx][pg].append((dest, entry_idx, new_dest))
                            else:
                                inconsistencies[0][file_idx][pg].append((dest, entry_idx, new_dest)) # Type 2
                            break
                    
                    else: # No Page Table has replaced destination => Type 1
                        inconsistencies[0][file_idx][pg].append((dest, entry_idx, None))
                
                
                # Destination was present at dump time
                else:
                    # Check the version
                    if entry.dump_target_version != dest.dump_version: # => Type 2
                        inconsistencies[2][file_idx][pg].append((dest, entry_idx, None))
                        
                        # Update counters
                        if entry.dump_target_version.pointers != dest.dump_version.pointers:
                            tmp = set(entry.dump_target_version.pointers.items())
                            diff = (tmp.union(dest.dump_version.pointers.items())).difference(tmp.intersection(dest.dump_version.pointers.items()))
                            
                            if dest in unique_dest:
                                continue
                            else:
                                unique_dest.add(dest)
                            for offset in entry.dump_target_version.pointers:
                                if entry.dump_target_version.pointers[offset] != dest.dump_version.pointers[offset]:
                                    try:
                                        f_name = dest.struct_type + "." +  offset_fields[dest.struct_type][offset]
                                    except:
                                        f_name = dest.struct_type + ":" + str(offset)
                                    version_fields_counters[file_idx]["pointers"][f_name] += 1
                        
                        if entry.dump_target_version.extra_fields != dest.dump_version.extra_fields:
                            tmp = set(entry.dump_target_version.extra_fields.items())
                            diff = (tmp.union(dest.dump_version.extra_fields.items())).difference(tmp.intersection(dest.dump_version.extra_fields.items()))
                            
                            for offset in entry.dump_target_version.extra_fields:
                                if entry.dump_target_version.extra_fields[offset] != dest.dump_version.extra_fields[offset]:
                                    try:
                                        f_name = dest.struct_type + "." +  offset_fields[dest.struct_type][offset]
                                    except:
                                        f_name = dest.struct_type + ":" + str(offset)
                                    version_fields_counters[file_idx]["extra_fields"][f_name] += 1

            else: # Source dumped after destination (inconsistencies type 5,6,7,8)
                
                # Destination pointed by source (dS1->?) exists at dump time? if yes it can be Type 6
                if dest.start_timestamp <= tds and (dest.end_timestamp is None or (dest.end_timestamp is not None and dest.end_timestamp > tde)):
                    if entry.dump_target_version != dest.dump_version:
                        
                        inconsistencies[3][file_idx][pg].append((dest, entry_idx, None))
                        
                        # Update counters
                        
                        if dest in unique_dest:
                            continue
                        else:
                            unique_dest.add(dest)
                       
                        if entry.dump_target_version.pointers != dest.dump_version.pointers:
                            tmp = set(entry.dump_target_version.pointers.items())
                            diff = (tmp.union(dest.dump_version.pointers.items())).difference(tmp.intersection(dest.dump_version.pointers.items()))
                            for offset in entry.dump_target_version.pointers:
                                if entry.dump_target_version.pointers[offset] != dest.dump_version.pointers[offset]:
                                    try:
                                        f_name = dest.struct_type + "." + offset_fields[dest.struct_type][offset]
                                    except:
                                        f_name = dest.struct_type + ":" + str(offset)
                                    version_fields_counters[file_idx]["pointers"][f_name] += 1
                        
                        
                        if entry.dump_target_version.extra_fields != dest.dump_version.extra_fields:
                            tmp = set(entry.dump_target_version.extra_fields.items())
                            diff = (tmp.union(dest.dump_version.extra_fields.items())).difference(tmp.intersection(dest.dump_version.extra_fields.items()))
                            for offset in entry.dump_target_version.extra_fields:
                                if entry.dump_target_version.extra_fields[offset] != dest.dump_version.extra_fields[offset]:
                                    try:
                                        f_name = dest.struct_type + "." +  offset_fields[dest.struct_type][offset]
                                    except:
                                        f_name = dest.struct_type + ":" + str(offset)
                                    version_fields_counters[file_idx]["extra_fields"][f_name] += 1
                
                else: # Original destination is dead or not exist at dump time Type 5,7 (type 8 = type 5)
                    # It was existed a structure at dump time in the same address of the structure pointed by dS?
                    for old_dest in struct_by_ppage[min(dest.ppages)][::-1]:

                        # Self reference
                        if old_dest.index == dest.index:
                            continue

                        # This structure is dumped (so is the structure that now pointed by the dump)?
                        if old_dest.dumped:
                            if entry.dump_type == old_dest.struct_type:
                                inconsistencies[3][file_idx][pg].append((dest, entry_idx, old_dest))
                            else:
                                inconsistencies[1][file_idx][pg].append((dest, entry_idx, old_dest)) # Type 2
                            break
                    else:
                        inconsistencies[1][file_idx][pg].append((dest, entry_idx, None))
    
        if len(pg.ppages) > 1:
            last_writes = [(k, v.last_modify) for k,v in pg.fields.items()]
            last_writes.sort()
            try:
                for p in range(len(pg.ppages) - 1):
                    ep = tms[pg.ppages[p]].end_time
                    for lw in last_writes:
                        if p * 0x1000 <= lw[0] and lw[1] >= ep:
                            raise Exception
            except:
                inconsistencies[4][file_idx] += 1
    
    del data
    gc.collect()

# Inconsistensies per structure type
inc_per_struct = []

for inc_type in inconsistencies[:-1]:
    inc_per_struct.append([])
    
    for inc_file in inc_type:
        inc_per_struct[-1].append(defaultdict(int))
        
        for pg, l in inc_file.items():
            inc_per_struct[-1][-1][pg.struct_type] += 1


# Reorganize for fast lookup
existents_stats = defaultdict(list)
for i in existents:
    for k,v in i.items():
        existents_stats[k].append(v)
        
dumped_stats = defaultdict(list)
for i in dumped:
    for k,v in i.items():
        dumped_stats[k].append(v)

inc_per_struct_stats = []
for i in inc_per_struct:
    inc_per_struct_stats.append(defaultdict(list))
    for j in i :
        for k,v in j.items():
            inc_per_struct_stats[-1][k].append(v)

for k,v in existents_stats.items():
    existents_stats[k] = (min(v), mean(v), 0, max(v))
for k,v in dumped_stats.items():
    dumped_stats[k] = (min(v), sum(v), 0, max(v))
for idx, i in enumerate(inc_per_struct_stats):
    for k,v in i.items():
        inc_per_struct_stats[idx][k] = (min(v), sum(v), 0, max(v))

affetected_unique = defaultdict(set)
for i in inconsistencies[:-1]:
    for j in i:
        for k in j:
            affetected_unique[k.struct_type].add(k)

# Print table stats (medi)
print("Table 7")
print("Struct\t\t\tInstances\tT1\tT2\tT3\tT4\tPercentage")
for struct_t, v in sorted(existents_stats.items()):
    l = []
    tot = ceil(dumped_stats[struct_t][1])
    try:
        l.append(str(tot) if tot != 0 else "-")
    except:
        l.append("-")
    
    for i in range(4):
        try:
            val = ceil(inc_per_struct_stats[i][struct_t][1])
            l.append(str(ceil(val)) if val != 0 else "-")
        except:
            l.append("-")
    ls = '\t'.join(l)
    print(f"{struct_t}\t\t\t{ls}\t{len(affetected_unique[struct_t])/tot*100}")
print("")
    

# Inconsistencies by type
print("Table 6")
print("Type \tD0\tD1\tD2\tD3\tD4\tD5\tD6\tD7\tD8\tD9")
for idx, i in enumerate(inconsistencies[:-1]):
    j = []
    s = f"Type {idx+1}\t"
    for k in i:
        j.append(len(k))
        v = len(k) if len(k) != 0 else "-"
        s+= f"{v}\t"
    print(s)
print("")

# Plugins -> structure and fields used
plugins = {
 'linux_check_creds': {'task_struct.cred',
                       'task_struct.pid',
                       'task_struct.tasks.next'},
 'linux_check_inline_kernel': {'address_space.i_pages.xa_head',
                               'dentry.d_child.next',
                               'dentry.d_inode',
                               'dentry.d_inode.i_ino',
                               'dentry.d_name.name',
                               'dentry.d_op',
                               'dentry.d_subdirs.next',
                               'dentry.dname.name',
                               'dentry_operations.d_name',
                               'fdtable.fd',
                               'fdtable.max_fds',
                               'file.f_path.dentry',
                               'file.f_path.mnt',
                               'file_system_type.name',
                               'file_system_type.next',
                               'files_struct.fdt',
                               'fs_struct.root.dentry',
                               'fs_struct.root.mnt',
                               'inode.i_ino',
                               'inode.i_mapping',
                               'inode.i_mode',
                               'inode.i_size',
                               'module.list.next',
                               'module.list.prev',
                               'mount.mnt.mnt_sb',
                               'mount.mnt_child.next',
                               'mount.mnt_devname',
                               'mount.mnt_flags',
                               'mount.mnt_hash.next',
                               'mount.mnt_list.next',
                               'mount.mnt_parent',
                               'super_block.s_flags',
                               'super_block.s_root',
                               'super_block.s_type',
                               'task_struct.files',
                               'task_struct.fs',
                               'task_struct.tasks.next'},
 'linux_check_syscalls': {'address_space.i_pages.xa_head',
                          'dentry.d_child.next',
                          'dentry.d_inode',
                          'dentry.d_name.name',
                          'dentry.d_subdirs.next',
                          'dentry.dname.name',
                          'file_system_type.name',
                          'file_system_type.next',
                          'inode.i_ino',
                          'inode.i_mapping',
                          'inode.i_mode',
                          'inode.i_size',
                          'module.core_size',
                          'module.list.next',
                          'module.list.prev',
                          'module.module_core',
                          'module.name',
                          'mount.mnt.mnt_sb',
                          'mount.mnt_child.next',
                          'mount.mnt_devname',
                          'mount.mnt_flags',
                          'mount.mnt_hash.next',
                          'mount.mnt_list.next',
                          'mount.mnt_parent',
                          'super_block.s_flags',
                          'super_block.s_root',
                          'super_block.s_type'},
 'linux_dump_map': {'mm_struct.pgd',
                    'task_struct.mm',
                    'task_struct.pid',
                    'task_struct.tasks.next',
                    'vm_area_struct.vm_end',
                    'vm_area_struct.vm_start'},
 'linux_elfs': {'dentry.d_inode',
                'dentry.d_inode.i_ino',
                'dentry.d_op',
                'dentry.dname.name',
                'dentry_operations.d_name',
                'file.f_path.dentry',
                'file.f_path.mnt',
                'fs_struct.root.dentry',
                'fs_struct.root.mnt',
                'inode.i_ino',
                'mm_struct.mmap',
                'mm_struct.pgd',
                'task_struct.comm',
                'task_struct.fs',
                'task_struct.mm',
                'task_struct.pid',
                'task_struct.tasks.next',
                'vm_area_struct.vm_next'},
 'linux_enumerate_file': {'address_space.i_pages.xa_head',
                          'dentry.d_child.next',
                          'dentry.d_inode',
                          'dentry.d_name.name',
                          'dentry.d_subdirs.next',
                          'dentry.dname.name',
                          'file_system_type.name',
                          'file_system_type.next',
                          'inode.i_ino',
                          'inode.i_mapping',
                          'inode.i_mode',
                          'inode.i_size',
                          'mount.mnt.mnt_sb',
                          'mount.mnt_child.next',
                          'mount.mnt_devname',
                          'mount.mnt_flags',
                          'mount.mnt_hash.next',
                          'mount.mnt_list.next',
                          'mount.mnt_parent',
                          'super_block.s_flags',
                          'super_block.s_root',
                          'super_block.s_type'},
 'linux_find_file': {'address_space.i_pages.xa_head',
                     'dentry.d_child.next',
                     'dentry.d_inode',
                     'dentry.d_name.name',
                     'dentry.d_subdirs.next',
                     'dentry.dname.name',
                     'file_system_type.name',
                     'file_system_type.next',
                     'inode.i_ino',
                     'inode.i_mapping',
                     'inode.i_mode',
                     'inode.i_size',
                     'mount.mnt.mnt_sb',
                     'mount.mnt_child.next',
                     'mount.mnt_devname',
                     'mount.mnt_flags',
                     'mount.mnt_hash.next',
                     'mount.mnt_list.next',
                     'mount.mnt_parent',
                     'super_block.s_flags',
                     'super_block.s_root',
                     'super_block.s_type'},
 'linux_getcwd': {'dentry.d_inode',
                  'dentry.dname.name',
                  'file.f_path.dentry',
                  'file.f_path.mnt',
                  'fs_struct.root.dentry',
                  'fs_struct.root.mnt',
                  'inode.i_ino',
                  'task_struct.fs',
                  'task_struct.tasks.next'},
 'linux_info_regs': {'mm_struct.arg_end',
                     'mm_struct.arg_start',
                     'mm_struct.pgd',
                     'task_struct.comm',
                     'task_struct.mm',
                     'task_struct.pid',
                     'task_struct.tasks.next',
                     'task_struct.thread.sp0'},
 'linux_ldrmodules': {'mm_struct.mmap',
                      'mm_struct.pgd',
                      'task_struct.mm',
                      'task_struct.tasks.next',
                      'tasks_struct.pid',
                      'vm_area_struct.vm_flags',
                      'vm_area_struct.vm_name',
                      'vm_area_struct.vm_next',
                      'vm_area_struct.vm_start'},
 'linux_library_list': {'mm_struct.mmap',
                        'mm_struct.pgd',
                        'task_struct.comm',
                        'task_struct.mm',
                        'task_struct.pid',
                        'task_struct.tasks.next',
                        'vm_area_struct.vm_next'},
 'linux_librarydump': {'mm_struct.mmap',
                       'mm_struct.pgd',
                       'task_struct.comm',
                       'task_struct.mm',
                       'task_struct.pid',
                       'task_struct.tasks.next',
                       'vm_area_struct.vm_next',
                       'vm_area_struct.vm_start'},
 'linux_list_raw': {'dentry.d_inode',
                    'dentry.d_inode.i_ino',
                    'dentry.d_op',
                    'dentry.dname.name',
                    'dentry_operations.d_name',
                    'file.dentry',
                    'file.f_path.dentry',
                    'file.f_path.mnt',
                    'fs_struct.root.dentry',
                    'fs_struct.root.mnt',
                    'inode.i_ino',
                    'inode.i_inolsof',
                    'net.list.next',
                    'net.packet.sklist.first.next',
                    'sock.__sk_common.skc_nulls_node.next',
                    'sock.sk_socket',
                    'task_struct.fs',
                    'task_struct.tasks.next'},
 'linux_lsof': {'dentry.d_inode',
                'dentry.d_inode.i_ino',
                'dentry.d_op',
                'dentry.dname.name',
                'dentry_operations.d_name',
                'fdtable.fd',
                'fdtable.max_fds',
                'file.f_path.dentry',
                'file.f_path.mnt',
                'files_struct.fdt',
                'fs_struct.root.dentry',
                'fs_struct.root.mnt',
                'inode.i_ino',
                'task_struct.comm',
                'task_struct.files',
                'task_struct.fs',
                'task_struct.pid',
                'task_struct.tasks.next'},
 'linux_malfind': {'mm_struct.mmap',
                   'mm_struct.pgd',
                   'task_struct.comm',
                   'task_struct.mm',
                   'task_struct.pid',
                   'task_struct.tasks.next',
                   'vm_area_struct.vm_flags',
                   'vm_area_struct.vm_next',
                   'vm_area_struct.vm_start'},
 'linux_memmap': {'mm_struct.pgd',
                  'task_struct.mm',
                  'task_struct.pid',
                  'task_struct.tasks.next'},
 'linux_mount': {'dentry.d_inode',
                 'dentry.dname.name',
                 'file_system_type.name',
                 'file_system_type.next',
                 'inode.i_ino',
                 'mount.mnt.mnt_sb',
                 'mount.mnt_child.next',
                 'mount.mnt_devname',
                 'mount.mnt_flags',
                 'mount.mnt_hash.next',
                 'mount.mnt_list.next',
                 'mount.mnt_parent',
                 'super_block.s_flags',
                 'super_block.s_root',
                 'super_block.s_type'},
 'linux_netstat': {'fdtable.fd',
                   'fdtable.max_fds',
                   'files_struct.fdt',
                   'task_struct.comm',
                   'task_struct.files',
                   'task_struct.pid',
                   'task_struct.tasks.next'},
 'linux_plthook': {'mm_struct.mmap',
                   'mm_struct.pgd',
                   'task_struct.mm',
                   'task_struct.tasks.next',
                   'vm_area_struct.vm_next'},
 'linux_proc_maps': {'dentry.d_inode',
                     'dentry.d_inode.i_ino',
                     'dentry.d_op',
                     'dentry.dname.name',
                     'dentry_operations.d_name',
                     'file.f_path.dentry',
                     'file.f_path.mnt',
                     'fs_struct.root.dentry',
                     'fs_struct.root.mnt',
                     'inode.i_ino',
                     'inode.i_sb',
                     'mm_struct.brk',
                     'mm_struct.context.vdso',
                     'mm_struct.mmap',
                     'mm_struct.pgd',
                     'mm_struct.start_brk',
                     'mm_struct.start_stack',
                     'super_block.major',
                     'super_block.minor',
                     'task_struct.comm',
                     'task_struct.fs',
                     'task_struct.mm',
                     'task_struct.pid',
                     'task_struct.tasks.next',
                     'vm_area_struct.f_path.dentry',
                     'vm_area_struct.vm_end',
                     'vm_area_struct.vm_file',
                     'vm_area_struct.vm_flags',
                     'vm_area_struct.vm_mm',
                     'vm_area_struct.vm_next',
                     'vm_area_struct.vm_pgoff',
                     'vm_area_struct.vm_start'},
 'linux_proc_maps_rb': {'mm_struct.mm_rb.rb_root.rb_node',
                        'rb_node',
                        'task_struct.mm',
                        'task_struct.tasks.next',
                        'vm_area_struct.rb.rb_left',
                        'vm_area_struct.rb.rb_right',
                        'vm_area_struct.vm_start'},
 'linux_procdump': {'mm_struct.pgd',
                    'mm_struct.start_code',
                    'task_struct.comm',
                    'task_struct.mm',
                    'task_struct.pid',
                    'task_struct.tasks.next'},
 'linux_process_hollow': {'mm_struct.mmap',
                          'mm_struct.pgd',
                          'task_struct.mm',
                          'task_struct.pid',
                          'task_struct.tasks.next',
                          'vm_area_struct.vm_end',
                          'vm_area_struct.vm_next',
                          'vm_area_struct.vm_start'},
 'linux_process_info': {'dentry.d_inode',
                        'dentry.d_inode.i_ino',
                        'dentry.d_op',
                        'dentry.dname.name',
                        'dentry_operations.d_name',
                        'file.f_path.dentry',
                        'file.f_path.mnt',
                        'fs_struct.root.dentry',
                        'fs_struct.root.mnt',
                        'inode.i_ino',
                        'mm_struct.arg_end',
                        'mm_struct.arg_start',
                        'mm_struct.brk',
                        'mm_struct.end_code',
                        'mm_struct.end_data',
                        'mm_struct.env_end',
                        'mm_struct.env_start',
                        'mm_struct.mmap',
                        'mm_struct.pgd',
                        'mm_struct.start_brk',
                        'mm_struct.start_code',
                        'mm_struct.start_data',
                        'mm_struct.start_stack',
                        'task_struct.comm',
                        'task_struct.euid',
                        'task_struct.fs',
                        'task_struct.gid',
                        'task_struct.mm',
                        'task_struct.pid',
                        'task_struct.tasks.next',
                        'task_struct.tgid',
                        'task_struct.thread.sp0',
                        'task_struct.thread_group.next',
                        'vm_area_struct.vm_end',
                        'vm_area_struct.vm_next',
                        'vm_area_struct.vm_start'},
 'linux_psaux': {'mm_struct.arg_end',
                 'mm_struct.arg_start',
                 'mm_struct.pgd',
                 'task_struct.comm',
                 'task_struct.gid',
                 'task_struct.mm',
                 'task_struct.pid',
                 'task_struct.tasks.next',
                 'task_struct.uid'},
 'linux_psenv': {'mm_struct.env_endtask_struct.comm',
                 'mm_struct.env_start',
                 'mm_struct.pgd',
                 'task_struct.mm',
                 'task_struct.pid',
                 'task_struct.tasks.next'},
 'linux_pslist': {'mm_struct.pgd',
                  'task_struct.comm',
                  'task_struct.gid',
                  'task_struct.mm',
                  'task_struct.parent',
                  'task_struct.pid',
                  'task_struct.start_time',
                  'task_struct.tasks.next',
                  'task_struct.uid',
                  'tasks_struct.tasks.prev'},
 'linux_psscan': {'task_struct.pid', 'task_struct.exit_state'},
 'linux_pstree': {'task_struct.children.prev',
                  'task_struct.comm',
                  'task_struct.euid',
                  'task_struct.gid',
                  'task_struct.mm',
                  'task_struct.pid',
                  'task_struct.ppid',
                  'task_struct.siblingtask_struct.children.next',
                  'task_struct.tasks.next'},
 'linux_recover_fs': {'address_space.i_pages.xa_head',
                      'dentry.d_child.next',
                      'dentry.d_inode',
                      'dentry.d_name.name',
                      'dentry.d_subdirs.next',
                      'dentry.dname.name',
                      'file_system_type.name',
                      'file_system_type.next',
                      'inode.i_atime.tv_sec',
                      'inode.i_ino',
                      'inode.i_mapping',
                      'inode.i_mode',
                      'inode.i_mtime.tv_sec',
                      'inode.i_size',
                      'inode.uid',
                      'mount.mnt.mnt_sb',
                      'mount.mnt_child.next',
                      'mount.mnt_devname',
                      'mount.mnt_flags',
                      'mount.mnt_hash.next',
                      'mount.mnt_list.next',
                      'mount.mnt_parent',
                      'super_block.s_flags',
                      'super_block.s_root',
                      'super_block.s_type'},
 'linux_threads': {'mm_struct.mmap',
                   'task_struct.comm',
                   'task_struct.euid',
                   'task_struct.gid',
                   'task_struct.mm',
                   'task_struct.pid',
                   'task_struct.tasks.next',
                   'task_struct.tgid',
                   'task_struct.thread_group.next',
                   'vm_area_struct.vm_end',
                   'vm_area_struct.vm_next',
                   'vm_area_struct.vm_start'},
 'linux_tmpfs': {'dentry.d_inode',
                 'dentry.d_name',
                 'dentry.d_subdirs.next',
                 'dentry.dname.name',
                 'file_system_type.name',
                 'file_system_type.next',
                 'inode.i_atime',
                 'inode.i_ino',
                 'inode.i_mode',
                 'inode.i_mtime',
                 'mount.mnt.mnt_sb',
                 'mount.mnt_child.next',
                 'mount.mnt_devname',
                 'mount.mnt_flags',
                 'mount.mnt_hash.next',
                 'mount.mnt_list.next',
                 'mount.mnt_parent',
                 'super_block.s_flags',
                 'super_block.s_root',
                 'super_block.s_type'},
 'linux_truecrypt': {'mm_struct.brk',
                     'mm_struct.mmap',
                     'mm_struct.pgd',
                     'mm_struct.start_brk',
                     'task_struct.mm',
                     'task_struct.pid',
                     'task_struct.tasks.next',
                     'vm_area_struct.vm_end',
                     'vm_area_struct.vm_next',
                     'vm_area_struct.vm_start'}}


# Table 8

version_fields_counters_stats = {"pointers": defaultdict(int), "extra_fields": defaultdict(int)}
for i in version_fields_counters:
    for k, v in i.items():
        for field, count in v.items():
            version_fields_counters_stats[k][field] += count

fields = set()
fields_extra = set()
for idx_incons in range(len(inconsistencies[:-1])):
    for file_idx in range(len(inconsistencies[idx_incons])):
        for s, inconss in inconsistencies[idx_incons][file_idx].items():
            for incons in inconss:
                try:
                    field = s.struct_type + "." + offset_fields[s.struct_type][incons[1]]
                except:
                    continue
                if idx_incons < 2:
                    fields.add(field)
                else:
                    fields_extra.add(field)

fields.update(version_fields_counters_stats["pointers"].keys())

print("Table 8")
print("Plugin\tCausal\tValue")
for plugin_name, plugin_fields in sorted(plugins.items()):
    s = plugin_name + "\t" 
    s += str(len(fields.intersection(plugin_fields))) + "\t" + str(len(set(version_fields_counters_stats["extra_fields"].keys()).intersection(plugin_fields)))
    print(s)
    