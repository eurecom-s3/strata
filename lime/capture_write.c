#include <linux/module.h>
#include <linux/types.h>

void * lime_vaddr_start;
void * lime_vaddr_end;
u64 lime_page_timestamp;
int lime_skip_range;
int lime_dio_enabled;
EXPORT_SYMBOL_GPL(lime_vaddr_start);
EXPORT_SYMBOL_GPL(lime_vaddr_end);
EXPORT_SYMBOL_GPL(lime_page_timestamp);
EXPORT_SYMBOL_GPL(lime_skip_range);
EXPORT_SYMBOL_GPL(lime_dio_enabled);

void noinline lime_pre_write(void *v) { lime_vaddr_start = v; lime_page_timestamp = ktime_get_raw_fast_ns();}
void noinline lime_post_write(void *v) { lime_vaddr_end = v; lime_page_timestamp = ktime_get_raw_fast_ns(); }
