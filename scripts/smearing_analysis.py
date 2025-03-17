#!/usr/bin/env python3

# Analyze smearing results

from pickle import load
from structs import EntryType
from collections import defaultdict
from tqdm import tqdm
import gc
import os

ARTIFACTS = os.getenv("ARTIFACTS")

files = [f"{ARTIFACTS}/smearing/{i}/result_{i}" for i in range(10)]

def calculate_size(start_pg):
    size = 0
    to_be_explored = [start_pg]
    for level in range(min(start_pg.levels),4):
        next_tables = []
        for pg in to_be_explored:
            for entry in pg.entries:
                
                if entry.dump_type == EntryType.HugePage and entry.dump_value !=0:
                    if level == 1:
                        size += 0x40000000
                    elif level == 2:
                        size += 0x200000
                    continue
                
                if entry.dump_type == EntryType.Page and entry.dump_value !=0:
                        size += 0x1000
                        continue

                if entry.dump_type != EntryType.Table or entry.dump_value == 0:
                    continue                    
                next_tables.append(entry.dump_value)
        
        next_tables = set(next_tables)

        to_be_explored = [pgs_by_index[x] for x in next_tables]
    return size

inconsistencies = [list() for x in range(4)]    # Different type of inconsistency
inconsistencies_kernel = [list() for x in range(4)]
version_mismatches = [dict() for x in range(4)] # Type of mismatches in version

pgds = []
pgds_names = []
times = []
distances = []
pgds_sizes = []

version_direct_counters = []
version_reverse_counters = []
timestamps = []
deltas = []
replaced = []
kernel_pages = []

print("Loading data... (slow process)")
for file_idx, filename in enumerate(tqdm(files)) :
    for i in range(len(inconsistencies)):
        inconsistencies[i].append([])
        inconsistencies_kernel[i].append(False)
    
    pgds.append(defaultdict(set))
    pgds_names.append({})
    pgds_sizes.append({})
    kernel_pages.append([])
    
    distances.append(0)
    version_direct_counters.append(defaultdict(int))
    version_reverse_counters.append(defaultdict(int))
    timestamps.append([])
    deltas.append([])
    replaced.append([])
    
    try:
        # Open file
        with open(filename, "rb") as f:
            data = load(f)
    except:
        print(f"{file_idx} INVALID")
        continue
        
    # Time need to dump
    times.append(data["timestamps"][0x13ffff000].end_time - data["timestamps"][0x1000].start_time)

    # Reorganize data
    tms = data["timestamps"]
    pgs = data["page_tables"]
    pgs_d = data["page_tables_dead"]
    
    tm = []
    dt = []
    for x in tms.values():
        tm.append(x.end_time)
        dt.append(abs(x.end_time-x.start_time))
    timestamps[-1] = tm
    deltas[-1] = dt

    pgs_by_index = {}
    pgs_by_ppage = defaultdict(list)
    all_pgs = pgs_d + list(pgs.values())
    for pg in pgs.values():
        pgs_by_index[pg.index] = pg
        pgs_by_ppage[pg.ppage].append(pg)
    for pg in pgs_d:
        pgs_by_index[pg.index] = pg
        pgs_by_ppage[pg.ppage].append(pg)
        
    for i in pgs_by_ppage:
        pgs_by_ppage[i].sort(key=lambda x: x.start_time)
        
    # Page tables dumped/not dumped
    dumped_pgs = []
    notdumped_pgs = []
    for v in all_pgs:
        if v.dumped:
            dumped_pgs.append(v)
        else:
            notdumped_pgs.append(v)
        
    # Reconstruct Radix trees
    for pg_pgd in dumped_pgs:
        if 0 not in pg_pgd.levels:
            continue
            
        # Ignore KPTI
        if pg_pgd.ppage & 0x1000:
            continue
        
        size = 0
        pgds_names[file_idx][pg_pgd.index] = pg_pgd.proc
        to_be_explored = [pg_pgd]
        for level in range(0,4):
            next_tables = []
            for pg in to_be_explored:
                for entry in pg.entries:
                    if entry.dump_type == EntryType.HugePage and entry.dump_value !=0:
                        if level == 1:
                            size += 0x40000000
                        elif level == 2:
                            size += 0x200000
                        continue
                    
                    if entry.dump_type == EntryType.Page and entry.dump_value !=0:
                            size += 0x1000
                            continue
                    
                    if entry.dump_type != EntryType.Table or entry.dump_value == 0:
                        continue
                    next_tables.append(entry.dump_value)
                
            next_tables = set(next_tables)
            for t in next_tables:
                distances.append(pgs_by_index[t].ppage - pg.ppage)
            
            to_be_explored = [pgs_by_index[x] for x in next_tables]
            pgds[file_idx][pg_pgd.index].update(next_tables)
                
        
        pgds_sizes[file_idx][pg_pgd.proc] = size
       

    pages = list(pgds[file_idx].values())
    kernel_pages[-1] = set(pages[0])
    for p in pages:
        kernel_pages[-1].intersection_update(p)
    
    # S in Ps and D in Pd in memory was S->D and in dump dS -?-> dD
    for pg in dumped_pgs:
        
        # Start and end time of source page dump
        tss = tms[pg.ppage].start_time
        tse = tms[pg.ppage].end_time
        
        for entry in pg.entries:
                        
            # Consider only entry pointing to tables
            if entry.dump_type != EntryType.Table or entry.dump_value == 0:
                continue
                
            
            # Start and end time of destination page dump
            dest = pgs_by_index[entry.dump_value]
            tds = tms[dest.ppage].start_time
            tde = tms[dest.ppage].end_time
                            
            # Source dumped before destination (inconsistencies type 1,2,3,4)
            if tse < tds:
                
                # Dump not started
                if dest.end_time == 0:
                    continue
                
                # destination is unallocated before its dump
                if dest.end_time and dest.end_time <= tds:
                    
                    # It exists a replacment Page Table? yes => Type 3 (type 4 = type 1)
                    # The replacement structure must be allocated after the deallocation of dest and has to be survived at least at the dump of the page
                    for new_dest in pgs_by_ppage[dest.ppage]:
                        
                        # Self reference 
                        if new_dest.index == dest.index:
                            continue

                        if dest.end_time <= new_dest.start_time and (new_dest.end_time is None or (new_dest.end_time is not None and new_dest.end_time > tde)):
                            s = calculate_size(dest)
                            inconsistencies[2][file_idx].append((pg, dest, s)) # Type 3 (EX Type 3)
                            
                            if pg.index in kernel_pages[file_idx]:
                                inconsistencies_kernel[2][file_idx] = True
                            
                            # Check if now point to a table of a different process
                            dest_pgd = set([pgd for pgd, pages in pgds[file_idx].items() if dest.index in pages])
                            new_dest_pgd = set([pgd for pgd, pages in pgds[file_idx].items() if new_dest.index in pages])
                            if dest_pgd and new_dest_pgd and not dest_pgd.intersection(new_dest_pgd):
                                replaced[file_idx].append((dest, new_dest, dest_pgd, new_dest_pgd))
                            break
                    
                    else: # No Page Table has replaced destination => Type 1 (EX Type 1)
                        s = calculate_size(dest)
                        inconsistencies[0][file_idx].append((pg, dest, s))
                        
                        if pg.index in kernel_pages[file_idx]:
                            inconsistencies_kernel[0][file_idx] = True
                
                
                # Destination was present at dump time
                else:
                    # Check the version
                    if entry.dump_target_version != dest.dump_version: # => Type 2 (EX Type 2)
                        s = calculate_size(dest)
                        inconsistencies[2][file_idx].append((pg, dest, s))
                        
                        # Ignora pagine kernel
                        if pg.index in kernel_pages[file_idx]:
                            inconsistencies_kernel[2][file_idx] = True
                            continue
                        
                        # Update counters
                        if entry.dump_target_version.present != dest.dump_version.present:
                            version_direct_counters[file_idx]["present"] += 1
                        if entry.dump_target_version.rw != dest.dump_version.rw:
                            version_direct_counters[file_idx]["rw"] += 1
                        if entry.dump_target_version.uk != dest.dump_version.uk:
                            version_direct_counters[file_idx]["uk"] += 1
                        if entry.dump_target_version.x != dest.dump_version.x:
                            version_direct_counters[file_idx]["x"] += 1
                        if entry.dump_target_version.huge != dest.dump_version.huge:
                            version_direct_counters[file_idx]["huge"] += 1
                        if entry.dump_target_version.address != dest.dump_version.address:
                            version_direct_counters[file_idx]["address"] += 1


            else: # Source dumped after destination (inconsistencies type 5,6,7,8)
                
                # Destination pointed by source (dS1->?) exists at dump time? if yes it can be Type 4 (EX Type 6)
                if dest.start_time <= tds and (dest.end_time is None or (dest.end_time is not None and dest.end_time > tde)):
                    if entry.dump_target_version != dest.dump_version:
                        s = calculate_size(dest)
                        inconsistencies[3][file_idx].append((pg, dest, s))
                        
                        # Ignora pagine kernel
                        if pg.index in kernel_pages[file_idx]:
                            inconsistencies_kernel[3][file_idx] = True
                            continue
                        
                        # Update counters
                        if entry.dump_target_version.present != dest.dump_version.present:
                            version_reverse_counters[file_idx]["present"] += 1
                        if entry.dump_target_version.rw != dest.dump_version.rw:
                            version_reverse_counters[file_idx]["rw"] += 1
                        if entry.dump_target_version.uk != dest.dump_version.uk:
                            version_reverse_counters[file_idx]["uk"] += 1
                        if entry.dump_target_version.x != dest.dump_version.x:
                            version_reverse_counters[file_idx]["x"] += 1
                        if entry.dump_target_version.huge != dest.dump_version.huge:
                            version_reverse_counters[file_idx]["huge"] += 1
                        if entry.dump_target_version.address != dest.dump_version.address:
                            version_reverse_counters[file_idx]["address"] += 1
                
                else: # Original destination is dead or not exist at dump time Type 5,7 (type 8 = type 5)
                    # It was existed a structure at dump time in the same address of the structure pointed by dS?
                    for old_dest in pgs_by_ppage[dest.ppage][::-1]:

                        # Self reference
                        if old_dest.index == dest.index:
                            continue

                        # This structure is dumped (so is the structure that now pointed by the dump)?
                        if old_dest.start_time < tde and (old_dest.end_time is None or (old_dest.end_time is not None and old_dest.end_time > tde)):
#                         if old_dest.dumped:
                            s = calculate_size(dest)
                            inconsistencies[3][file_idx].append((pg, dest, s)) # TYPE 4 (EX TYPE 5 == TYPE 6 per page tables)
                            if pg.index in kernel_pages[file_idx]:
                                inconsistencies_kernel[3][file_idx] = True
            
                            # Check if now point to a table of a different process
                            dest_pgd = set([pgd for pgd, pages in pgds[file_idx].items() if dest.index in pages])
                            old_dest_pgd = set([pgd for pgd, pages in pgds[file_idx].items() if old_dest.index in pages])
                            if dest_pgd and old_dest_pgd and not dest_pgd.intersection(old_dest_pgd):
                                replaced[file_idx].append((dest, old_dest, dest_pgd, old_dest_pgd))
                            break
                    else:
                        # Type 2 (EX Type 5)
                        s = calculate_size(dest)
                        inconsistencies[1][file_idx].append((pg, dest, s))
                        if pg.index in kernel_pages[file_idx]:
                            inconsistencies_kernel[1][file_idx] = True
    del data
    gc.collect()


# Identify kernel page tables
kernel_pages = []
for idx, procs in enumerate(pgds):
    kernel_pages.append([])
    pages = list(procs.values())
    kernel_pages[-1] = set(pages[0])
    for p in pages:
        kernel_pages[-1].intersection_update(p)


pgd_touched = []
kernels = []

for t in inconsistencies:
    kernels.append([])
    pgd_touched.append([])
    
    for file_idx, pages in enumerate(t):
        pgd_touched[-1].append([])
        kernels[-1].append([])
        
        kernels[-1][-1] = 0
        for pg, _, _ in pages:
            kk = False
            for p, k in pgds[file_idx].items():
                if pg.index in k:
                    if pg.index not in kernel_pages[file_idx]:
                        pgd_touched[-1][-1].append(pgds_names[file_idx][p])
                    else:
                        kk = True
            if kk:
                kernels[-1][-1] += 1

################## TABEL 4
print("Table 4")
print("       D0\tD1\tD2\tD3\tD4\tD5\tD6\tD7\tD8\tD9")
for idx, i in enumerate(inconsistencies):
    j = []
    s = f"Type {idx+1}\t"
    for k in i:
        j.append(len(k))
        v = len(k) if len(k) != 0 else "-"
        s+= f"{v}\t"
    print(s)
print("")

################ TABLE 5
print("Table 5")
print("       D0\tD1\tD2\tD3\tD4\tD5\tD6\tD7\tD8\tD9")
for idx, v in enumerate(pgd_touched):
    s = f"Type {idx+1}\t"
    for idx2, k in enumerate(v):
        p = len(set(k)) if k else "-"
        s += f"{p}\t"
    print(s)

# Last line
per_dump = [set() for x in range(10)]
for idx, v in enumerate(pgd_touched):
    s = f"Type {idx+1}"
    for idx2, k in enumerate(v):
        per_dump[idx2].update(set(k))
s = "Unique\t"
for i in per_dump:
    s+=f"{len(i)}\t"
print(s)
print("")

# Kernel inconsistencies
print("Table 5, highlithed values")
print("       D0\tD1\tD2\tD3\tD4\tD5\tD6\tD7\tD8\tD9")
for idx, i in enumerate(inconsistencies_kernel):
    j = []
    s = f"Type {idx+1}\t"
    for k in i:
        s+= "H\t" if k != 0 else "-\t"
    print(s)

