#!/usr/bin/env python3

import pandas as pd
import os

ARTIFACTS = os.getenv("ARTIFACTS")

# Get reference timestamp
t = pd.read_hdf(f"{ARTIFACTS}/fs/sata_mode/results/xfs/nodio_1024/pages/events.h5", key="data")
ref_time = t.iloc[-1]["end"] - t.iloc[0]["start"]

print("USB FSs")
for fs in ["btrfs", "exfat", "ext4", "ext4nj", "f2fs", "ntfs", "vfat", "xfs"]:
    t = pd.read_hdf(f"{ARTIFACTS}/fs/usb_mode/results/{fs}/nodio_1024/pages/events.h5", key="data")
    print(fs, (t.iloc[-1]["end"] - t.iloc[0]["start"]) / ref_time)

t = pd.read_hdf(f"{ARTIFACTS}/fs/usb_mode/results/net/pages/events.h5", key="data")
print("net", (t.iloc[-1]["end"] - t.iloc[0]["start"]) / ref_time)

for fs in ["btrfs", "exfat", "vfat"]:
    t = pd.read_hdf(f"{ARTIFACTS}/fs/usb_mode/results/{fs}/dio_1024/pages/events.h5", key="data")
    print(fs + "_dio", (t.iloc[-1]["end"] - t.iloc[0]["start"]) / ref_time)

print("SATA FSs")
for fs in ["btrfs", "exfat", "ext4", "ext4nj", "f2fs", "ntfs", "vfat", "xfs"]:
    t = pd.read_hdf(f"{ARTIFACTS}/fs/sata_mode/results/{fs}/nodio_1024/pages/events.h5", key="data")
    print(fs, (t.iloc[-1]["end"] - t.iloc[0]["start"]) / ref_time)

for fs in ["btrfs", "exfat", "vfat"]:
    t = pd.read_hdf(f"{ARTIFACTS}/fs/sata_mode/results/{fs}/dio_1024/pages/events.h5", key="data")
    print(fs + "_dio", (t.iloc[-1]["end"] - t.iloc[0]["start"]) / ref_time)