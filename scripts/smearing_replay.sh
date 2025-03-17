#!/bin/bash

# Reproduce smearing results

for i in `seq 0 9`
do
   ./scripts/smearing.py --mem 4096 --extra-args="-hda $ARTIFACTS/smearing/rootfs2.qcow2 -netdev user,id=vmnic -device e1000,netdev=vmnic -drive if=none,id=stick,format=qcow2,file=$ARTIFACTS/smearing/external2.qcow2,snapshot=off -device usb-ehci,id=ehci -device usb-storage,bus=ehci.0,drive=stick -nographic" $ARTIFACTS/smearing/$i/record-0 $ARTIFACTS/smearing/$i/kallsyms-0 $ARTIFACTS/smearing/$i/iomem-0 --debug $ARTIFACTS/smearing/$i/result_$i &
done