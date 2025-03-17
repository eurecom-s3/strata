// FINAL VERSION!

/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Andrea Oliveri andrea.oliveri@eurecom.fr
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */

#define __STDC_FORMAT_MACROS

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <hdf5/serial/hdf5_hl.h>
#include <unordered_map>
#include <map>
#include <unordered_set>
#include <bits/stdc++.h>
using namespace std;

#include "panda/plugin.h"
#define START_SIZE_WRITES 1048576
#define START_SIZE_PPNS 128
#define IOMEM_SIZE 128

#define LOG2(X) ((unsigned) (8*sizeof (unsigned long long) - __builtin_clzll((X)) - 1))

extern "C"
{
    bool init_plugin(void *);
    void uninit_plugin(void *);
    void mem_write_callback(CPUState *cpu, target_ulong pc, target_ulong addr, size_t size, uint8_t *buf);
}

int save_stats_ppn(std::unordered_map<uint32_t, tuple<uint64_t, uint64_t, uint64_t, unordered_set <uint16_t>>> &);
int save_ppn2vpage(std::unordered_map<uint32_t, unordered_set <uint64_t>> &);
int save_stats_vaddr(std::unordered_map<uint64_t, tuple<uint32_t, uint32_t, uint32_t>> &virt_writes_map);

// ################################################################
// IOMEM regions descriptions
struct __attribute__((__packed__)) IOmemRegion {
    uint32_t start_ppn;
    uint32_t end_ppn;
};
struct IOmemRegion iomem_ppns[IOMEM_SIZE];
uint32_t iomem_ppns_size;

inline bool is_ppn_in_ram(uint32_t ppn) {
    for(int i=0;i<iomem_ppns_size;i++){
        if (iomem_ppns[i].start_ppn <= ppn && ppn <= iomem_ppns[i].end_ppn)
            return true;
    }
    return false;
}
// ################################

typedef struct __attribute__((__packed__)) DumpEvent {
    uint64_t start;     // Instruction count at which the dump of the page starts
    uint64_t end;       // Instruction count at which the dump of the page ends
    uint32_t ppn;       // Physical page number of the page
} DumpEvent;

hid_t hdf5_events;
hid_t dumpevent_types[3] = { H5T_STD_U64LE, H5T_STD_U64LE, H5T_STD_U32LE };
size_t dumpevent_size = sizeof(DumpEvent);
size_t dumpevent_offsets[3] = {  HOFFSET(DumpEvent, start), HOFFSET(DumpEvent, end), HOFFSET(DumpEvent, ppn) };
size_t dumpevent_sizes[3] = { sizeof(uint64_t), sizeof(uint64_t), sizeof(uint32_t) };
const char* dumpevent_names[3] = {"start", "end", "ppn"};

struct DumpEvent event;

//###################################

typedef struct __attribute__((__packed__)) WriteEvent {
    uint32_t ppn;       // Physical page number where it is written on
    uint64_t vaddr;     // Virtual address ath which it is written on
    uint8_t size;       // The size of the write
    bool is_zero;       // It was a zero?
    bool is_ptr;        // Is the virtual address a (possible) pointer?
} WriteEvent;

hid_t writeevent_types[5] = { H5T_STD_U32LE, H5T_STD_U64LE, H5T_STD_U8LE, H5T_NATIVE_HBOOL, H5T_NATIVE_HBOOL };
size_t writeevent_size = sizeof(WriteEvent);
size_t writeevent_offsets[5] = { HOFFSET(WriteEvent, ppn), HOFFSET(WriteEvent, vaddr), HOFFSET(WriteEvent, size), HOFFSET(WriteEvent, is_zero),  HOFFSET(WriteEvent, is_ptr) };
size_t writeevent_sizes[5] = { sizeof(uint32_t), sizeof(uint64_t), sizeof(uint8_t), sizeof(bool), sizeof(bool) };
const char* writeevent_names[5] = {"ppn", "vaddr", "size", "is_zero", "is_ptr"};

// ###################################

typedef struct __attribute__((__packed__)) WrittenPPN {
    uint32_t current_ppn;  // Current PPN in dumping/just dumped
    uint32_t written_ppn;  // Written PPN
    uint32_t total_writes; // Number of writes for the written_ppn
    uint32_t total_size;   // Total data size written on written_ppn
    bool written_in_dump;  // Written at least once during the dump phase
} WrittenPPN;

hid_t writtenppn_types[5] = { H5T_STD_U32LE, H5T_STD_U32LE, H5T_STD_U32LE, H5T_STD_U32LE, H5T_NATIVE_HBOOL };
size_t writtenppn_size = sizeof(WrittenPPN);
size_t writtenppn_offsets[5] = { HOFFSET(WrittenPPN, current_ppn), HOFFSET(WrittenPPN, written_ppn), HOFFSET(WrittenPPN, total_writes), HOFFSET(WrittenPPN, total_size), HOFFSET(WrittenPPN, written_in_dump) };
size_t writtenppn_sizes[5] = { sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(bool) };
const char* writtenppn_names[5] = {"current_ppn", "written_ppn", "total_writes", "total_size", "written_in_dump"};

// ###################################

// Temporary and auxiliary data structures
bool dump_started = false;          // True if the dump process is started
bool in_dump = false;               // True if it is currently dumping a page
target_ulong cur_page_vaddr = 0;    // The virtual address of the page currently under dump by LiME
target_ulong cur_slot_start = 0;    // Current timeslot 
uint64_t first_instr = -1;          // The first instruction at which LiME starts to save ppages
uint32_t current_ppn = -1;          // The PPN of the page current under dump
hid_t per_ppn_stats_hdf5; // Result file for PPN written during the dump of another PPN

// ##################################################################

// Plugin parameters
target_ulong lime_start_var = 0;
target_ulong lime_end_var = 0;
uint64_t lime_page_timestamp = 0;
uint64_t lime_skip_range = 0;
uint64_t lime_dio_enabled = 0;
bool extended_results = false;
bool reduced_stats = true;
int c  = 0;
int lime_dio_enabled_value = 0;
int skipped_range = 0;

// Counters and data datastructs
uint64_t tot_writes = 0;                 // Total KERNEL writes
uint64_t not_ram_writes = 0;             // Total KERNEL writes on special regions of physical pages (EFI + ACPI + others)
uint64_t mmio_writes = 0;                // Total writes on MMIO devices
uint64_t ram_writes = 0;                 // Total KERNEL writes on ordinary memory physical pages
uint64_t tot_size = 0;                   // Total data size written
uint64_t written_sizes[5] = {0,0,0,0,0}; // Total data written by size (1, 2, 4, 8, more than 8 bytes)
std::unordered_map<uint32_t, tuple<uint64_t, uint64_t, uint64_t, unordered_set <uint16_t>>> ppn_stats_map; // Map PPN -> (write counts, zero counts, total bytes, set of all offsets written)
std::unordered_map<uint32_t, unordered_set <uint64_t>> ppn2vpage_map; // Map PPN -> VPAGE
struct WriteEvent *writes;              // Array for write events, its capacity and its count
uint64_t writes_capacity = 0;
uint64_t writes_count = 0;
std::map<uint32_t, tuple<uint32_t, uint32_t, bool>> written_in_slot; // Map written PPNs -> (total writes, total size, writes at least one time during the dump of the PPN) 
struct WrittenPPN *writtenppns;           // Array for written PPN during a time slot and its capacity
uint64_t writtenppns_capacity = 0;
std::unordered_map<uint64_t, tuple<uint32_t, uint32_t, uint32_t>> virt_writes_map; // Map virtual address -> (count of total writes, zero writes, writes_recognized as possible ptr) (directly written only, no for adjacent writes)

// HDF5 datastructs
#if defined(TARGET_X86_64)

// ###################################
inline void save_detailed_writes() {
    // Save all the writes during a time slot (during a page dump or between two
    // of them)

    char new_hdf5_name[256];
    hid_t new_hdf5;
    herr_t status;

    // Create hdf5 file containing writes during a time slot
    sprintf(new_hdf5_name, "%lu.h5", cur_slot_start);
    new_hdf5 = H5Fcreate(new_hdf5_name, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    status = H5TBmake_table("All write records during a time slot", new_hdf5, "data", 5, 0, 
        writeevent_size, writeevent_names, 
        writeevent_offsets, writeevent_types, 8192, NULL, 3, NULL);
    if (status<0) {
        printf("%s %d Error creating result file %s\n", __FILE__, __LINE__, new_hdf5_name);
        writes_count = 0;
        return;
    }

    // Append results
    status = H5TBappend_records(new_hdf5, "data", writes_count, writeevent_size, writeevent_offsets, writeevent_sizes, writes);
    if (status<0) {
        printf("%s %d Error writing on result file %s\n", __FILE__, __LINE__, new_hdf5_name);
        writes_count = 0;
        return;
    }
    H5Fclose(new_hdf5);

    writes_count = 0;
}

void mem_write_callback(CPUState *cpu, target_ulong pc, target_ulong address, size_t size, uint8_t *buf)
{
    uint64_t vpage;
    hwaddr paddr;
    uint32_t ppn;
    uint16_t offset;
    herr_t status;
    void *tmp;
    uint64_t i;
    uint64_t log_size;
    bool value_is_zero;
    bool is_ptr;


    // Ignore address which are not in kernel space
    if(address < 0xffff800000000000)
        return;

    // At the beginning of a page dump...
    if(address == lime_start_var) {

        // Get the virtual address of the page currently under dump
        if(panda_virtual_memory_rw(cpu, address, (uint8_t *)&cur_page_vaddr, 8, 0)) {
            printf("%s %d Error reading virtual address 0x%lx!\n", __FILE__, __LINE__, address);
            return;
        }
        
        // If it's the first dump save the "timestamp"
        if(first_instr == -1) {
            first_instr = event.start;
            dump_started = true;
        }
        
        // Save the relative timestamp
        if(panda_virtual_memory_rw(cpu, lime_page_timestamp, (uint8_t *)&event.start, 8, 0)) {
                printf("Error reading lime_page_timestamp\n", __FILE__, __LINE__);
                event.start = -1;
        }

        cur_slot_start = event.start;
        in_dump = true;

        // Get paddr of the page
        paddr = panda_virt_to_phys(cpu, cur_page_vaddr);
        if(paddr == -1) {
            printf("%s %d Error translating virtual address 0x%lx!\n", __FILE__, __LINE__, cur_page_vaddr);
            return;
        }

        // Save previous written ppns
        if (current_ppn != -1) {

            // Extend buffer size if needed
            if (written_in_slot.size() >= writtenppns_capacity) {
                while(writtenppns_capacity <= written_in_slot.size())
                    writtenppns_capacity *= 2;

                tmp = reallocarray(writtenppns, writtenppns_capacity, sizeof(struct WrittenPPN));
                if (!tmp) {
                    printf("%s %d Error reallocarray()\n", __FILE__, __LINE__);
                    exit(-1);
                }
                writtenppns = (struct WrittenPPN *) tmp;
            }

            // Fill the buffer of struct (used to speed up the writes)
            i = 0;
            for (auto uit = written_in_slot.begin(); uit != written_in_slot.end(); ++uit, ++i) {
                writtenppns[i].current_ppn = current_ppn;
                writtenppns[i].written_ppn = uit->first;
                
                auto [tot_write_ppn, tot_size_ppn, written_in_dump] = uit->second;
                writtenppns[i].total_writes = tot_write_ppn;
                writtenppns[i].total_size = tot_size_ppn;
                writtenppns[i].written_in_dump = written_in_dump;
            }
            written_in_slot.clear();

            // Save the results
            status = H5TBappend_records(per_ppn_stats_hdf5, "data", i, writtenppn_size, writtenppn_offsets, writtenppn_sizes, writtenppns);
            if (status<0) {
                printf("%s %d Error writing on written_ppn.h5\n", __FILE__, __LINE__);
                return;
            }
        }

        // Save current ppn in dump phase
        current_ppn = paddr >> 12;

        // Save writes happended between two dump slots
        if(extended_results && dump_started && writes_count) {
            save_detailed_writes();
        }

        return;
    }

    // At the end of a page dump
    else if(address == lime_end_var) {
        
        // Get the virtual address of the dumped page
        if(panda_virtual_memory_rw(cpu, address, (uint8_t *)&vpage, 8, 0)) {
                printf("%s %d Error reading virtual address 0x%lx!\n", __FILE__, __LINE__, address);
                return;
        }

        // Check if it correspond to the address saved when the dump starts
        if(vpage != cur_page_vaddr) {
            printf("%s %d Error, the current page 0x%lx does not correspond to the saved one 0x%lx\n", __FILE__, __LINE__, vpage, cur_page_vaddr);
            // return;
        }

        // Get the physical address of the page
        paddr = panda_virt_to_phys(cpu, vpage);
        if(paddr == -1) {
            printf("%s %d Error translating virtual address 0x%lx!\n", __FILE__, __LINE__, vpage);
            return;
        }

        // Get the ppage part of the address and save the event
        ppn = paddr >> 12;
        event.ppn = ppn;

        // Get end timestamp
        if(panda_virtual_memory_rw(cpu, lime_page_timestamp, (uint8_t *)&event.end, 8, 0)) {
            printf("Error reading lime_page_timestamp\n", __FILE__, __LINE__);
            event.end = -1;
        }

        // Save the dump event on file
        status = H5TBappend_records(hdf5_events, "data", 1, dumpevent_size, dumpevent_offsets, dumpevent_sizes, &event);
        if(status < 0) printf("%s %d Error write saving dump event!\n", __FILE__, __LINE__);
        
        cur_slot_start = event.end;
        in_dump = false;
        
        // Save writes happended during dump slots
        if (extended_results && dump_started && writes_count) {
            save_detailed_writes();
        }
        
        return;
    }

    // Skipped range counter updated
    else if(address == lime_skip_range) {
        skipped_range =  *((uint32_t *) buf);
    }

    // Save if we are in DIO mode
    else if(address == lime_skip_range) {
        if(panda_virtual_memory_rw(cpu, lime_dio_enabled, (uint8_t *)&lime_dio_enabled_value, 4, 0)) {
            printf("Fail to read lime_dio_enabled variable\n", __FILE__, __LINE__);
        }
    }

    // All other writes
    // Ignore writes before dump is started
    if(!dump_started) return;
    
    // Determine physical address written by the kernel
    paddr = panda_virt_to_phys(cpu, address);
    if(paddr == -1) {
        printf("%s %d Error translating virtual address 0x%lx!\n", __FILE__, __LINE__, address);
        return;
    }
    
    ppn = paddr >> 12;
    tot_writes++;
    tot_size += size;

    // If it is a write not in ordinary RAM update only the counter
    if (!is_ppn_in_ram(ppn)) {
        not_ram_writes++;
        return;
    }            
    
    // Update statistics
    offset = paddr & 0x1FFF;
    auto& [ppn_count, zero_count, ppn_tot_size, unique_offset_set] = ppn_stats_map[ppn];
    ppn_count++;

    // Stats on how much data is written
    if((log_size = LOG2(size)) > 3)
        log_size = 4;
    written_sizes[log_size] += 1;

    // Save the written ppn
    auto& [tot_write_ppn, tot_size_ppn, written_in_dump] = written_in_slot[ppn];
    tot_write_ppn++;
    tot_size_ppn += size;
    written_in_dump |= in_dump;
    ram_writes++;

    // Save ppn to vpage mappings
    ppn2vpage_map[ppn].insert(address & 0xFFFFFFFFFFFFF000);

    is_ptr = false;
    value_is_zero = false;
    if(!reduced_stats) {

        value_is_zero = true;
        switch(size) {
            case 1:
                value_is_zero = *((uint8_t *) buf) == 0;
                unique_offset_set.insert(offset);
                break;
            case 2:
                value_is_zero = *((uint16_t *) buf) == 0;
                unique_offset_set.insert(offset);
                unique_offset_set.insert(offset+1);
                break;
            case 4:
                value_is_zero = *((uint32_t *) buf) == 0;
                unique_offset_set.insert(offset);
                unique_offset_set.insert(offset+1);
                unique_offset_set.insert(offset+2);
                unique_offset_set.insert(offset+3);
                break;
            case 8:
                value_is_zero = *((uint64_t *) buf) == 0;
                unique_offset_set.insert(offset);
                unique_offset_set.insert(offset+1);
                unique_offset_set.insert(offset+2);
                unique_offset_set.insert(offset+3);
                unique_offset_set.insert(offset+4);
                unique_offset_set.insert(offset+5);
                unique_offset_set.insert(offset+6);
                unique_offset_set.insert(offset+7);
                break;
            default:
                for(i=0;i<size;++i) {
                    value_is_zero &= *((uint8_t *) buf) == 0;
                    unique_offset_set.insert(offset+i);
                }
        };

        // Read the data written and check if can be an address (it can be a pointer variable!)
        if (size == 8 && !value_is_zero) {
            // Check if it could be a virtual address
            is_ptr = panda_virt_to_phys(cpu, *((uint64_t *)buf)) != -1;
        }
        else is_ptr = false;
    
        auto& [tot_vaddr_writes, zero_writes, ptr_count] = virt_writes_map[address];
        
        tot_vaddr_writes++;
        
        if(value_is_zero) {
            zero_writes++;
        }
        
        ppn_tot_size += size;
        ptr_count += is_ptr;

        // Save the extended event of a write
        if(extended_results) {
            // Extend the buffer if needed
            if(writes_count == writes_capacity) {
                while(writes_capacity <= writes_count)
                    writes_capacity *= 2;

                tmp = reallocarray(writes, writes_capacity, sizeof(struct WriteEvent));
                if (!tmp) {
                    printf("%s %d Error reallocarray()\n", __FILE__, __LINE__);
                    exit(-1);
                }
                writes = (struct WriteEvent *) tmp;
                writes_capacity *= 2;
                //printf("realloc() current writes buffer size %lu, \n", writes_capacity);
            }
            
            writes[writes_count].is_ptr = is_ptr;
            writes[writes_count].ppn = ppn;
            writes[writes_count].vaddr = address;
            writes[writes_count].size = size;
            writes[writes_count].is_zero = value_is_zero;
            writes_count += 1;
        }
    }

    // //TO STOP THE PLUGIN AFTER X ITERATIONS, DEBUGGING ONLY       
    // if(c == 1000000)
    //     panda_replay_end();
    // else
    //     c+=1;

    return;
}

void mmio_write_callback(CPUState *env, target_ptr_t physaddr, target_ptr_t vaddr, size_t size, uint64_t *val) {
    mmio_writes++;
}

#endif

bool init_plugin(void *self)
{
    #if defined(TARGET_X86_64)
    char *output_path;
    char *iomem_path;
    char *kallsyms_path;
    
    FILE *fd;
    char iomem_buf[512];
    uint64_t iomem_start, iomem_end, symbol_addr;
    char iomem_type[256];
    int iomem_actual_size = 0;

    struct stat st = {0};
    panda_cb pcb;
    herr_t status;

    // Get args
    panda_arg_list *args = panda_get_args("collector");
    extended_results = panda_parse_bool(args, "extended");
    dump_started = panda_parse_bool(args, "force_start"); // For "idle" snapshots: force the collection of data also if no dump machinery is started
    iomem_path = panda_parse_string(args, "iomem", "./iomem");
    kallsyms_path = panda_parse_string(args, "kallsyms", "./kallsyms");
    output_path = panda_parse_string(args, "path", "./output/");
    reduced_stats = panda_parse_bool(args, "reduced_stats");

    // Create ouput dir
    if (stat(output_path, &st) == -1) {
        mkdir(output_path, 0770);
    }
    chdir(output_path);

    // Load iomem
    fd = fopen(iomem_path, "r");
    if(!fd) {
        printf("%s %d Error opening iomem file\n", __FILE__, __LINE__);
        return false;
    }

    while (fgets(iomem_buf, sizeof(iomem_buf), fd)) {
        sscanf(iomem_buf, "%lx-%lx : %[^\n]", &iomem_start, &iomem_end, iomem_type);
        // printf("%lx %lx %s\n", iomem_start, iomem_end, iomem_type);
        if (strstr(iomem_type, "System RAM") != NULL) {
            iomem_ppns[iomem_actual_size].start_ppn = iomem_start >> 12;
            iomem_ppns[iomem_actual_size].end_ppn = iomem_end >> 12;
            iomem_actual_size++;
        }
    }

    iomem_ppns_size = iomem_actual_size;
    fclose(fd);

    // Load kallsyms addresses
    fd = fopen(kallsyms_path, "r");
    if(!fd) {
        printf("%s %d Error opening kallsyms file\n", __FILE__, __LINE__);
        return false;
    }

    while (fgets(iomem_buf, sizeof(iomem_buf), fd)) {
        sscanf(iomem_buf, "%lx %*c %s", &symbol_addr, iomem_type);
        // printf("%lx %s\n", symbol_addr, iomem_type);
        if (strstr(iomem_type, "lime_vaddr_start") != NULL) { lime_start_var = symbol_addr; }
        else if (strstr(iomem_type, "lime_vaddr_end") != NULL) { lime_end_var = symbol_addr; }
        else if (strstr(iomem_type, "lime_page_timestamp") != NULL) { lime_page_timestamp = symbol_addr; }
        else if (strstr(iomem_type, "lime_skip_range") != NULL) { lime_skip_range = symbol_addr; }
        else if (strstr(iomem_type, "lime_dio_enabled") != NULL) { lime_dio_enabled = symbol_addr; }
    }
    fclose(fd);

    // Create the dump events HDF5 file
    hdf5_events = H5Fcreate("events.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    status = H5TBmake_table("Physical dump events", hdf5_events, "data", 3, 0, 
        dumpevent_size, dumpevent_names, 
        dumpevent_offsets, dumpevent_types, 512, NULL, 3, NULL);
    if (status<0) return false;
    
    // Create PerPPN writing stats
    per_ppn_stats_hdf5 = H5Fcreate("per_ppn_writes.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    status = H5TBmake_table("Map PPNs written during the timeslot dump of a certain PPN", per_ppn_stats_hdf5, "data", 5, 0, 
        writtenppn_size, writtenppn_names, 
        writtenppn_offsets, writtenppn_types, 512, NULL, 3, NULL);
    if (status<0) return false;
    
    // Allocate event array
    writtenppns = (struct WrittenPPN *)calloc(START_SIZE_PPNS, sizeof(struct WrittenPPN));
    if(!writtenppns) {
        printf("%s %d Error allocating writtenpps\n", __FILE__, __LINE__);
        return false;
    }
    writtenppns_capacity = START_SIZE_PPNS;

    // Alocate detailed writes array
    if(extended_results) {
        writes = (struct WriteEvent *)calloc(START_SIZE_WRITES, sizeof(struct WriteEvent));
        if(!writes) {
            printf("%s %d Error allocating writes\n", __FILE__, __LINE__);
            return false;
        }
        writes_capacity = START_SIZE_WRITES;
    }

    // Free arguments
    panda_free_args(args);

    // Enable memory logging
    panda_enable_memcb();

    // Register memory write callback
    pcb.virt_mem_after_write = mem_write_callback;
    panda_register_callback(self, PANDA_CB_VIRT_MEM_AFTER_WRITE, pcb);

    // Register MMIO write callback
    pcb.mmio_before_write = mmio_write_callback;
    panda_register_callback(self, PANDA_CB_MMIO_BEFORE_WRITE, pcb);

    return true;
    #else
    return false;
    #endif
}

void uninit_plugin(void *self)
{
    #if defined(TARGET_X86_64)
    FILE *stats_fd;
    
    // Save stats per PPN
    save_stats_ppn(ppn_stats_map);

    // Save PPN to virtual page mapping
    save_ppn2vpage(ppn2vpage_map);

    // Save stats per virtual address
    save_stats_vaddr(virt_writes_map);

    // Save general statitiscs
    stats_fd = fopen("stats", "w");
    fprintf(stats_fd, "# DIO enabled: %d\n", lime_dio_enabled_value);
    fprintf(stats_fd, "# Skip range(s): %d\n", skipped_range);
    fprintf(stats_fd, "# Total kernel write events: %lu\n", tot_writes);
    fprintf(stats_fd, "# Total kernel write events on ordinary RAM pages: %lu (%f%%)\n", ram_writes, (double)ram_writes/tot_writes * 100);
    fprintf(stats_fd, "# Total kernel write events on special regions pages: %lu (%f%%)\n", not_ram_writes, (double)not_ram_writes/tot_writes * 100);
    fprintf(stats_fd, "# Total bytes written by the kernel: %lu\n", tot_size);
    for (int i=0; i<4; ++i)
        fprintf(stats_fd, "# Total kernel write events of size %d bytes: %lu (%f%%)\n", 1<<i, written_sizes[i], (double)written_sizes[i]/tot_writes * 100);
    fprintf(stats_fd, "# Total kernel write events of size > 8 bytes: %lu (%f%%)\n", written_sizes[4], (double)written_sizes[4]/tot_writes * 100);
    fprintf(stats_fd, "# Total different phisical pages: %lu\n", ppn_stats_map.size());
    fprintf(stats_fd, "# Total different virtual addresses: %lu\n", virt_writes_map.size());
    fprintf(stats_fd, "# Total kernel write on MMIO regions pages: %lu\n", mmio_writes);

    fclose(stats_fd);


    // Save general statitiscs RAW
    stats_fd = fopen("stats_raw", "a+");
    fprintf(stats_fd, "%lu,%lu,%lu,%lu,", tot_writes, ram_writes, not_ram_writes, tot_size);
    for (int i=0; i<4; ++i)
        fprintf(stats_fd, "%lu,", written_sizes[i]);
    fprintf(stats_fd, "%lu,%lu,%lu,%lu\n", written_sizes[4], ppn_stats_map.size(), virt_writes_map.size(), mmio_writes);

    fclose(stats_fd);

    // Close HD5file
    H5Fclose(per_ppn_stats_hdf5);
    H5Fclose(hdf5_events);
    free(writtenppns);
    
    if (extended_results) {
        free(writes);
    }

    #endif
}
