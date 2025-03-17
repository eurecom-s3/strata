Collector2 output:

events.h5 -> "timestamps" at which LiME dumps a PPN
    start: Timestamp at which the dump of the physical page starts
    end: Timestamp at which the dump of the physical page ends
    ppn: physical page number

per_ppn_writes.h5 -> During the dump of "current_ppn" which other PPNs are written
    current_ppn: PPN currently under dump (if written_in_dump = True) or just
    dumped (LiME is preparing to dump the next page)
    written_ppn: PPN on which it is written 
    total_writes: Total number of write events on the PPN
    total_size: Total size of the data written on the PPN 
    written_in_dump: The PPN is written durin a dump event

ppn2vpage.h5 -> map PPN to virtual pages
    ppn: PPN :D
    vpage: virtual page :D

ppn_stats.h5 -> aggregated statistics for each PPN
    ppn: PPN currently under dump/just dumped  
    write_count: total number of write event on the PPN
    zero_count: number of zero only writes on the PPN
    total_bytes: total number of bytes written on the PPN
    unique_locs: unique locations (physical addresses) written on the PPN

vaddr_stats.h5 -> aggregated statistics for each virtual address
    vaddr: virtual address
    write_count: total number of write on the virtual address (only direct ones)
    zero_count: number of zero only writes on the virtual address
    ptr_count: Number of writes recognized as ptr (only 4/8 writes, non zero)


Detailed output:
    for each time slot (period starting from the dump of a PPN and the next one)
    create XXXX.h5 containing
    ppn:      Physical page number where it is written on
    vaddr:    Virtual address ath which it is written on
    size:     The size of the write
    is_zero:  was it a zero write?
    bool is_ptr:   Is the virtual address a (possible) pointer? 