#!/bin/bash

for fs in exfat ntfs ext4 ext4nj xfs btrfs f2fs vfat
do
    mkdir $ARTIFACTS/fs/sata_mode/results/$fs/nodio_1024/new/
    eval "/usr/local/bin/panda-system-x86_64 -kernel $ARTIFACTS/fs/sata_mode/bzImage -hda $ARTIFACTS/fs/sata_mode/rootfs.qcow2 -netdev user,id=vmnic -device e1000,netdev=vmnic -append 'rootwait root=/dev/sda console=tty1 console=ttyS0 nokaslr' -drive if=none,id=sata,format=qcow2,file=$ARTIFACTS/fs/sata_mode/external.qcow2,snapshot=off -device ich9-ahci,id=ahci -device ide-drive,drive=sata,bus=ahci.0 -m 1024 -panda collector2:force_start=y,path=$ARTIFACTS/fs/sata_mode/results/$fs/nodio_1024/new/,iomem=$ARTIFACTS/fs/sata_mode/results/$fs/nodio_1024/iomem_$fs,kallsyms=$ARTIFACTS/fs/sata_mode/results/$fs/nodio_1024/kallsyms_$fs,reduced_stats=y -replay $ARTIFACTS/fs/sata_mode/results/$fs/nodio_1024/$fs" &
done

for fs in exfat btrfs vfat
do
    mkdir $ARTIFACTS/fs/sata_mode/results/$fs/dio_1024/new/
    eval "/usr/local/bin/panda-system-x86_64 -kernel $ARTIFACTS/fs/sata_mode/bzImage -hda $ARTIFACTS/fs/sata_mode/rootfs.qcow2 -netdev user,id=vmnic -device e1000,netdev=vmnic -append 'rootwait root=/dev/sda console=tty1 console=ttyS0 nokaslr' -drive if=none,id=sata,format=qcow2,file=$ARTIFACTS/fs/sata_mode/external.qcow2,snapshot=off -device ich9-ahci,id=ahci -device ide-drive,drive=sata,bus=ahci.0 -m 1024 -panda collector2:force_start=y,path=$ARTIFACTS/fs/sata_mode/results/$fs/dio_1024/new/,iomem=$ARTIFACTS/fs/sata_mode/results/$fs/dio_1024/iomem_$fs,kallsyms=$ARTIFACTS/fs/sata_mode/results/$fs/dio_1024/kallsyms_$fs,reduced_stats=y -replay $ARTIFACTS/fs/sata_mode/results/$fs/dio_1024/$fs" &
done

for fs in exfat ntfs ext4 ext4nj xfs btrfs f2fs vfat net
do
    mkdir $ARTIFACTS/fs/usb_mode/results/$fs/nodio_1024/new/
    eval "/usr/local/bin/panda-system-x86_64 -kernel $ARTIFACTS/fs/usb_mode/bzImage -hda $ARTIFACTS/fs/usb_mode/rootfs.qcow2 -netdev user,id=vmnic -device e1000,netdev=vmnic -append 'rootwait root=/dev/sda console=tty1 console=ttyS0 nokaslr' -drive if=none,id=stick,format=qcow2,file=$ARTIFACTS/fs/usb_mode/external.qcow2,snapshot=off -device usb-ehci,id=ehci -device usb-storage,bus=ehci.0,drive=stick -m 1024 -panda collector2:force_start=y,path=$ARTIFACTS/fs/usb_mode/results/$fs/nodio_1024/new/,iomem=$ARTIFACTS/fs/usb_mode/results/$fs/nodio_1024/iomem_$fs,kallsyms=$ARTIFACTS/fs/usb_mode/results/$fs/nodio_1024/kallsyms_$fs,reduced_stats=y -replay $ARTIFACTS/fs/usb_mode/results/$fs/nodio_1024/$fs" &
done

for fs in exfat btrfs vfat
do
    mkdir $ARTIFACTS/fs/usb_mode/results/$fs/dio_1024/new/
    eval "/usr/local/bin/panda-system-x86_64 -kernel $ARTIFACTS/fs/usb_mode/bzImage -hda $ARTIFACTS/fs/usb_mode/rootfs.qcow2 -netdev user,id=vmnic -device e1000,netdev=vmnic -append 'rootwait root=/dev/sda console=tty1 console=ttyS0 nokaslr' -drive if=none,id=stick,format=qcow2,file=$ARTIFACTS/fs/usb_mode/external.qcow2,snapshot=off -device usb-ehci,id=ehci -device usb-storage,bus=ehci.0,drive=stick -m 1024 -panda collector2:force_start=y,path=$ARTIFACTS/fs/usb_mode/results/$fs/dio_1024/new/,iomem=$ARTIFACTS/fs/usb_mode/results/$fs/dio_1024/iomem_$fs,kallsyms=$ARTIFACTS/fs/usb_mode/results/$fs/dio_1024/kallsyms_$fs,reduced_stats=y -replay $ARTIFACTS/fs/usb_mode/results/$fs/dio_1024/$fs" &
done

# Collect results
cd $ARTIFACTS/fs/sata_mode/results/
echo "fs,events,ram,noram,bytes,size1,size2,size4,size8,size8+,phys,virts,time" > table3_new
for fs in exfat ntfs ext4 ext4nj xfs btrfs f2fs vfat
do
    cat $ARTIFACTS/fs/sata_mode/results/$fs/nodio_1024/new/stats_raw >> table3_new
done

for fs in exfat btrfs vfat
do
    cat $ARTIFACTS/fs/sata_mode/results/$fs/dio_1024/new/stats_raw >> table3_new
done

cd $ARTIFACTS/fs/usb_mode/results/
echo "fs,events,ram,noram,bytes,size1,size2,size4,size8,size8+,phys,virts,time" > table3_new
for fs in exfat ntfs ext4 ext4nj xfs btrfs f2fs vfat net
do
    cat $ARTIFACTS/fs/usb_mode/results/$fs/nodio_1024/new/stats_raw >> table3_new
done

for fs in exfat btrfs vfat
do
    cat $ARTIFACTS/fs/usb_mode/results/$fs/dio_1024/new/stats_raw >> table3_new
done