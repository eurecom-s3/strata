#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <hdf5/serial/hdf5_hl.h>
#include <unordered_map>
#include <unordered_set>
#include <bits/stdc++.h>

using namespace std;

// Save stats writes on ppages
int save_stats_ppn(std::unordered_map<uint32_t, tuple<uint64_t, uint64_t, uint64_t, unordered_set <uint16_t>>> &ppn_stats_map) {
    hid_t statsppn_hd5;
    herr_t status;
    int i = 0;
    struct StatsPPN *stats_array;

    printf("Saving ppn_stats.h5 mapping...\n");

    // HDF5 struct to store data
    struct __attribute__((__packed__)) StatsPPN {
        uint32_t ppn;           // Current PPN in dumping/just dumped
        uint64_t write_count;   // Number of write on the ppage
        uint64_t zero_count;    // Number of zero writes (any size) on the ppage
        uint64_t total_bytes;   // Number of total bytes written on it
        uint16_t unique_locs;   // Unique locations written
    };

    hid_t statsppn_types[5] = { H5T_STD_U32LE, H5T_STD_U64LE, H5T_STD_U64LE, H5T_STD_U64LE, H5T_STD_U16LE };
    size_t statsppn_size = sizeof(StatsPPN);
    size_t statsppn_offsets[5] = { HOFFSET(StatsPPN, ppn), HOFFSET(StatsPPN, write_count), HOFFSET(StatsPPN, zero_count), HOFFSET(StatsPPN, total_bytes), HOFFSET(StatsPPN, unique_locs) };
    size_t statsppn_sizes[5] = { sizeof(uint32_t), sizeof(uint64_t), sizeof(uint64_t), sizeof(uint64_t), sizeof(uint16_t) };
    const char* statsppn_names[5] = {"ppn", "write_count", "zero_count", "total_bytes", "unique_locs"};

    // Create HDF5 file and table
    statsppn_hd5 = H5Fcreate("ppn_stats.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    status = H5TBmake_table("Cumulative statistics on each single PPN", statsppn_hd5, "data", 5, 0, 
        statsppn_size, statsppn_names, 
        statsppn_offsets, statsppn_types, 512, NULL, 3, NULL);
    if (status<0) {
        printf("%s, %d Error creating HDF5 file\n", __FILE__, __LINE__);
        return -1;
    }

    // Alloc array for fast writes
    stats_array = (struct StatsPPN *)malloc(ppn_stats_map.size() * sizeof(struct StatsPPN));
    if(!stats_array) {
        printf("%s, %d Error allocating buffer\n", __FILE__, __LINE__);
        return -1;
    }

    // Copy in the array
    for (auto it = ppn_stats_map.begin(); it != ppn_stats_map.end(); ++it, ++i) {
        auto [count, zero_count, ssize, unique_offset_set] = it->second;
        stats_array[i].ppn = it->first;
        stats_array[i].write_count = count;
        stats_array[i].zero_count = zero_count;
        stats_array[i].total_bytes = ssize;
        stats_array[i].unique_locs = unique_offset_set.size();
    }

    // Write on HDF5 file
    status = H5TBappend_records(statsppn_hd5, "data", i, statsppn_size, statsppn_offsets, statsppn_sizes, stats_array);
    
    H5Fclose(statsppn_hd5);    
    free(stats_array);

    if(status < 0) {
        printf("%s, %d Error write HDF5 data structures\n", __FILE__, __LINE__);
        return -1;
    }

    return 0;
}

// Save PPN to virtual page mapping
int save_ppn2vpage(std::unordered_map<uint32_t, unordered_set <uint64_t>> &ppn2vpage_map) {
    hid_t ppn2vpage_hd5;
    herr_t status;
    struct PPN2VPage *ppn2vpage_array;
    int tot_buf_elems = 0;
    int i = 0;

    printf("Saving ppn2vpage.h5 mapping...\n");

    // HDF5 struct to store data
    struct __attribute__((__packed__)) PPN2VPage {
        uint32_t ppn;           // PPN 
        uint64_t vpage;         // Associated vpage
    };

    hid_t ppn2vpage_types[2] = { H5T_STD_U32LE, H5T_STD_U64LE };
    size_t ppn2vpage_size = sizeof(struct PPN2VPage);
    size_t ppn2vpage_offsets[2] = { HOFFSET(PPN2VPage, ppn), HOFFSET(PPN2VPage, vpage) };
    size_t ppn2vpage_sizes[2] = { sizeof(uint32_t), sizeof(uint64_t) };
    const char* ppn2vpage_names[2] = {"ppn", "vpage"};

    // Create HDF5 file
    ppn2vpage_hd5 = H5Fcreate("ppn2vpage.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    status = H5TBmake_table("Mapping between PPN and virtual pages", ppn2vpage_hd5, "data", 2, 0, 
        ppn2vpage_size, ppn2vpage_names, 
        ppn2vpage_offsets, ppn2vpage_types, 512, NULL, 3, NULL);
    if (status<0) {
        printf("%s, %d Error creating HDF5 file\n", __FILE__, __LINE__);
        return -1;
    }

    // Alloc array for fast writes
    for (auto it = ppn2vpage_map.begin(); it != ppn2vpage_map.end(); ++it)
        tot_buf_elems += it->second.size();

    ppn2vpage_array = (struct PPN2VPage *)malloc(tot_buf_elems * sizeof(struct PPN2VPage));
    if(!ppn2vpage_array) {
        printf("%s %d Error allocating buffer\n", __FILE__, __LINE__);
        return -1;
    }

    for (auto it = ppn2vpage_map.begin(); it != ppn2vpage_map.end(); ++it) {
        for (auto sit = (it->second).begin(); sit != (it->second).end(); ++sit, ++i) {
            ppn2vpage_array[i].ppn = it->first;
            ppn2vpage_array[i].vpage = *sit;
        }
    }

    // Write on HDF5 file
    status = H5TBappend_records(ppn2vpage_hd5, "data", i, ppn2vpage_size, ppn2vpage_offsets, ppn2vpage_sizes, ppn2vpage_array);
    
    H5Fclose(ppn2vpage_hd5);
    free(ppn2vpage_array);

    if(status < 0) {
        printf("%s, %d Error write HDF5 data structures\n", __FILE__, __LINE__);
        return -1;
    }

    return 0;
}

// Save stats writes on virtual addresses stats
int save_stats_vaddr(std::unordered_map<uint64_t, tuple<uint32_t, uint32_t, uint32_t>> &virt_writes_map) {
    hid_t statsvaddr_hd5;
    herr_t status;
    int i = 0;
    struct StatsVaddr *stats_array;

    printf("Saving vaddr_stats.h5 mapping...\n");

    // HDF5 struct to store data
    struct __attribute__((__packed__)) StatsVaddr {
        uint64_t vaddr;         // Virtual address :)
        uint32_t write_count;   // Number of write on the vaddr (only direct write)
        uint32_t zero_count;    // Number of zero writes (any size) on the vaddr
        uint32_t ptr_count;     // Number of writes recognized as ptr (only 4/8 writes, non zero)
    };

    hid_t statsvaddr_types[4] = { H5T_STD_U64LE, H5T_STD_U32LE, H5T_STD_U32LE, H5T_STD_U32LE };
    size_t statsvaddr_size = sizeof(StatsVaddr);
    size_t statsvaddr_offsets[4] = { HOFFSET(StatsVaddr, vaddr), HOFFSET(StatsVaddr, write_count), HOFFSET(StatsVaddr, zero_count), HOFFSET(StatsVaddr, ptr_count) };
    size_t statsvaddr_sizes[4] = { sizeof(uint64_t), sizeof(uint32_t), sizeof(uint32_t), sizeof(uint32_t) };
    const char* statsvaddr_names[4] = {"vaddr", "write_count", "zero_count", "ptr_count"};

    // Create HDF5 file and table
    statsvaddr_hd5 = H5Fcreate("vaddr_stats.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    status = H5TBmake_table("Statistics on each single virtual address", statsvaddr_hd5, "data", 4, 0, 
        statsvaddr_size, statsvaddr_names, 
        statsvaddr_offsets, statsvaddr_types, 512, NULL, 3, NULL);
    if (status<0) {
        printf("%s, %d Error creating HDF5 file\n", __FILE__, __LINE__);
        return -1;
    }

    // Alloc array for fast writes
    stats_array = (struct StatsVaddr *)malloc(virt_writes_map.size() * sizeof(struct StatsVaddr));
    if(!stats_array) {
        printf("%s, %d Error allocating buffer\n", __FILE__, __LINE__);
        return -1;
    }

    // Copy in the array
    for (auto it = virt_writes_map.begin(); it != virt_writes_map.end(); ++it, ++i) {
        auto [count, zero_count, ptr_count] = it->second;
        stats_array[i].vaddr = it->first;
        stats_array[i].write_count = count;
        stats_array[i].zero_count = zero_count;
        stats_array[i].ptr_count = ptr_count;
    }

    // Write on HDF5 file
    status = H5TBappend_records(statsvaddr_hd5, "data", i, statsvaddr_size, statsvaddr_offsets, statsvaddr_sizes, stats_array);
    
    H5Fclose(statsvaddr_hd5);    
    free(stats_array);

    if(status < 0) {
        printf("%s, %d Error write HDF5 data structures\n", __FILE__, __LINE__);
        return -1;
    }

    return 0;
}