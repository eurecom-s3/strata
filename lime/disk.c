/*
 * LiME - Linux Memory Extractor
 * Copyright (c) 2011-2014 Joe Sylve - 504ENSICS Labs
 *
 *
 * Author:
 * Joe Sylve       - joe.sylve@gmail.com, @jtsylve
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include "lime.h"

ssize_t write_vaddr_disk(void *, size_t);

static struct file * f = NULL;

extern int lime_dio_enabled;
extern void *vpage;
extern int mode;

static int dio_write_test(char *path, int oflags)
{
    /*  Need because if we reopen an existing file, also with O_TRUNK, the underlying FS
        known that a file exists and has inode associated an refuse to perform O_DIRECT.
        So we create a test file only for DIO test (we cannot use O_TMPFILE because some 
        FS do not support it)
    */
    int ok;
    int path_len = min(strlen(path) + 5, PAGE_SIZE);
    snprintf(vpage, path_len, "%s_dio", path);

    f = filp_open(vpage, oflags | O_DIRECT | O_SYNC, 0444);
    if (f && !IS_ERR(f)) {
        ok = write_vaddr_disk(vpage, PAGE_SIZE) == PAGE_SIZE;
        filp_close(f, NULL);
        memset(vpage, '\x00', PAGE_SIZE);
    } else {
        ok = 0;
    }

    return ok;
}

int setup_disk(char *path, int dio) {
    int oflags = O_WRONLY | O_CREAT | O_LARGEFILE | O_TRUNC;
    int err = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
    mm_segment_t fs;

    fs = get_fs();
    set_fs(KERNEL_DS);
#endif

    // If we use LiME format or padded one they are not aligned (TODO CRYPT AND GZIP)!
    if (dio && mode == LIME_MODE_RAW && dio_write_test(path, oflags)) {
        oflags |= O_DIRECT | O_SYNC;
	    DBG("Direct IO Enabled");
        lime_dio_enabled = 1;
    } else {
        lime_dio_enabled = 0;
        DBG("Direct IO Disabled");
    }

    f = filp_open(path, oflags, 0444);

    if (!f || IS_ERR(f)) {
        DBG("Error opening file %ld", PTR_ERR(f));

        err = (f) ? PTR_ERR(f) : -EIO;
        f = NULL;
    }

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
    set_fs(fs);
#endif

    return err;
}

void cleanup_disk(void) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
    mm_segment_t fs;

    fs = get_fs();
    set_fs(KERNEL_DS);
#endif

    if(f) filp_close(f, NULL);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
    set_fs(fs);
#endif
}

ssize_t write_vaddr_disk(void * v, size_t is) {
    ssize_t s;
    loff_t pos;

    pos = f->f_pos;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
    mm_segment_t fs;

    fs = get_fs();
    set_fs(KERNEL_DS);
    s = vfs_write(f, v, is, &pos);
    set_fs(fs);
#else
    s = kernel_write(f, v, is, &pos);
#endif

    if (s == is) {
        f->f_pos = pos;
    }

    return s;
}
