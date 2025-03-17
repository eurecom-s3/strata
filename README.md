# Strata plugins
PANDA plugins that we have developed are in ```plugins```, in ```scripts/universal.py```, ```scripts/smearing.py```,```scripts/strata.py```

# Environment for artifact evaluation
To run all the experiments a machine with Ubuntu Desktop 20.04 x86_64 with a
minimum of 16 cores, 256GB of RAM, 512GB disk space and approximately 8 days of computation are needed. Otherwise, if you want to reproduce the analysis starting from intermediate files it requires a 8 core machine with 16 GB of RAM, 180GB of disk space and 3 hours of computation.

```script
sudo apt update
sudo apt install --no-install-recommends build-essential git libhdf5-dev cargo p7zip-full libvdeplug-dev libpng16-16 libsdl2-2.0-0
git clone https://github.com/eurecom-s3/strata
cd strata
```

## Build PANDA and STRATA plugins (NECESSARY ONLY TO REPRODUCE ALL THE INTERMEDIATE FILES, READ AFTER THIS SECTION FOR MORE INFO)
```script
git clone https://github.com/panda-re/panda
cd panda
git checkout 272272456171f03bad5ebeb72929bf5cf676346d
sudo apt install --no-install-recommends $(cat panda/dependencies/ubuntu:20.04_base.txt | grep -o '^[^#]*')
sudo apt install --no-install-recommends $(cat panda/dependencies/ubuntu:20.04_build.txt | grep -o '^[^#]*')
git apply ../strata/patches/panda.patch
cp -r ../strata/plugins/collector2 panda/plugins/
cp -r ../strata/patches/qemu_helpers.h panda/python/core/pandare/include/qemu_helpers.h
mkdir -p build
cd build
../build.sh --python x86_64-softmmu,i386-softmmu --prefix=/usr/local/ --extra-cflags=-Wno-error --extra-cxxflags=-Wno-error --enable-llvm --with-llvm=/usr/lib/llvm-11
sudo make install
pip3 uninstall protobuffer
pip3 install pycparser "https://foss.heptapod.net/pypy/cffi/-/archive/branch/default/cffi-branch-default.zip" colorama
patch ../panda/python/core/pandare/panda.py < ../strata/patches/panda.py.patch
cd ../panda/python/core; sudo python3 setup.py build; sudo python3 setup.py install
```

## Install Volatility 3 and Linux profile (NECESSARY ONLY TO REPRODUCE ALL THE INTERMEDIATE FILES, READ AFTER THIS SECTION FOR MORE INFO)
```script
pip3 install git+https://github.com/volatilityfoundation/volatility3.git@054a3618b8389cbdb647f173915917c15657a92d
python_version=$(readlink -f /usr/bin/python3 | xargs  basename)
find ~/.local/lib/$python_version/site-packages/volatility -type f -exec sed -i 's/@functools.lru_cache/#@functools.lru_cache/g' {} +
mkdir ~/.local/lib/$python_version/site-packages/volatility/symbols/linux/
cp strata/patches/ubuntu2204_desktop.json.xz ~/.local/lib/$python_version/site-packages/volatility/symbols/linux/
```

## Create artifact directory
***Due to the size of the artifacts, we suggest to download each artifact archive
separately, expand it, delete the archive, run the tests, delete the expanded
dataset and results and continue with the next one.***

Change directory to the one in which you want to store the artifacts 
```script
cd YOUR_STORAGE_DIRECTORY
mkdir artifacts/
cd artifacts
export ARTIFACTS=$(pwd)
```

## Reproduce Table 1, Table 2 and Figure 3
1) Extract the idle dataset download from [idle.7z](https://www.s3.eurecom.fr/datasets/datasets/applications/03:2025_03:2025_andrea_strata/idle.7z) in ```$ARTIFACTS/idle``` and enter in it
```cd $ARTIFACTS/idle```.

2) ### (OPTIONAL) Reproduce intermediate files for Table 1
    - If you want to reproduce the intermediate analysis files
    (already present precomputed in the dataset) it is required at least 32GB of
    RAM and 6 hours to replay the PANDA snapshots.

    - Create a target directory tree
    ```mkdir -p new/ubuntu new/vxWorks new/win10```

    - For Linux: ```/usr/local/bin/panda-system-x86_64 -m 4096 -hda
        $ARTIFACTS/idle/ubuntu/rootfs.qcow2 -netdev
        user,hostfwd=tcp::8888-:8888,hostfwd=tcp::2222-:22,id=vmnic -device
        e1000,netdev=vmnic -drive
        if=none,id=stick,format=qcow2,file=$ARTIFACTS/idle/ubuntu/external.qcow2,snapshot=off
        -device usb-ehci,id=ehci -device usb-storage,bus=ehci.0,drive=stick -replay
        $ARTIFACTS/idle/ubuntu/record-0 -panda
        "collector2:force_start=y,path=$ARTIFACTS/idle/new/ubuntu,iomem=$ARTIFACTS/idle/ubuntu/iomem,kallsyms=$ARTIFACTS/idle/ubuntu/iomem"```

    - For vxWorks: ```/usr/local/bin/panda-system-x86_64 -m 4096 -M q35 -cpu
        core2duo -netdev user,id=vmnic -device e1000,netdev=vmnic -kernel
        $ARTIFACTS/idle/vxWorks/vxWorks -append "bootline:fs(0,0)host:vxWorks
        h=10.0.2.2 e=10.0.2.15 u=target pw=vxTarget o=gei0 p=2121" -replay
        $ARTIFACTS/idle/vxWorks/record-0 -panda
        "collector2:force_start=y,path=$ARTIFACTS/idle/new/vxWorks,iomem=$ARTIFACTS/idle/vxWorks/iomem,kallsyms=/$ARTIFACTS/idle/vxWorks/iomem"```

    - For Windows 10: ```/usr/local/bin/panda-system-x86_64 -m 4096 -hda $ARTIFACTS/idle/win10/win10.qcow2 -netdev user,id=vmnic -device e1000,netdev=vmnic -replay $ARTIFACTS/idle/win10/record-0 -panda "collector2:force_start=y,path=$ARTIFACTS/idle/new/win10,iomem=$ARTIFACTS/idle/win10/iomem,kallsyms=$ARTIFACTS/idle/win10/iomem"```


    - At the end of the three commands overwrite the result files from
        ```$ARTIFACTS/idle/new/XXX``` to ```$ARTIFACTS/idle/XXX```

3) For each OS, results of Table 1 are in ```$ARTIFACTS/idle/XXX/stats```. In
   particular values: "Total kernel write events", "Total bytes written by the
   kernel" in Bytes (must be divided by 1048576), "Total kernel write events of
   size 1", "Total kernel write events of size 2", "Total kernel write events of
   size 4", "Total kernel write events of size 8", "Total different phisical
   pages" and "Total different virtual addresses"

4) ### (OPTIONAL) Reproduce intermediate files for Table 2 and Figure 3
    - If you want to reproduce the intermediate analysis files
    (already present precomputed in the dataset) it is required at least 32GB of
    RAM and approximately 24 hours to replay the PANDA snapshots.

    - Create a target directory tree
    ```mkdir -p new/ubuntu new/vxWorks new/win10```

    - Reproduce intermediate results ***(WARNING! Each command MUST be executed
        serially, DO NOT execute them at the same time!)***

    - For Linux: ```python3 ./scripts/universal.py --debug --mem 4096
      --extra-args="-hda $ARTIFACTS/idle/ubuntu/rootfs.qcow2 -netdev
      user,hostfwd=tcp::8888-:8888,hostfwd=tcp::2222-:22,id=vmnic -device
      e1000,netdev=vmnic -drive
      if=none,id=stick,format=qcow2,file=$ARTIFACTS/idle/ubuntu/external.qcow2,snapshot=off
      -device usb-ehci,id=ehci -device usb-storage,bus=ehci.0,drive=stick"
      $ARTIFACTS/idle/ubuntu/record-0 $ARTIFACTS/idle/ubuntu/mtree
      $ARTIFACTS/idle/ubuntu/total_instrs $ARTIFACTS/idle/new```

    - For vxWorks: ```python3 ./scripts/universal.py --mem 4096 --extra-args="-M
      q35 -cpu core2duo -netdev user,id=vmnic -device e1000,netdev=vmnic -kernel
      $ARTIFACTS/idle/vxWorks/vxWorks -append 'bootline:fs(0,0)host:vxWorks
      h=10.0.2.2 e=10.0.2.15 u=target pw=vxTarget o=gei0 p=2121'"
      $ARTIFACTS/idle/vxWorks/record-0 $ARTIFACTS/idle/vxWorks/mtree
      $ARTIFACTS/idle/vxWorks/total_instrs $ARTIFACTS/idle/new```

    - For Windows: ```python3 ./scripts/universal.py --debug --mem 4096
      --extra-args="-hda $ARTIFACTS/idle/win10/win10.qcow2 -netdev user,id=vmnic
      -device e1000,netdev=vmnic" $ARTIFACTS/idle/win10/record-0
      $ARTIFACTS/idle/win10/mtree $ARTIFACTS/idle/win10/total_instrs
      $ARTIFACTS/idle/new```

    - At the end of the three commands overwrite the result files from
        ```$ARTIFACTS/idle/new/XXX``` to ```$ARTIFACTS/idle/XXX```

5) Run the ```./scripts/idle_analysis.py``` to produce Table 2 results and
   Figure 3 PNG file.


## Reproduce statistics about Linux virtual address space (Section 4 IDLE KERNEL ACTIVITY)

- Run ```./scripts/linux_vaddrs.py --kallsyms $ARTIFACTS/idle/ubuntu/kallsyms
  --panda-args="-hda $ARTIFACTS/idle/ubuntu/rootfs.qcow2 -netdev
  user,hostfwd=tcp::8888-:8888,hostfwd=tcp::2222-:22,id=vmnic -device
  e1000,netdev=vmnic -drive
  if=none,id=stick,format=qcow2,file=$ARTIFACTS/idle/ubuntu/external.qcow2,snapshot=off
  -device usb-ehci,id=ehci -device usb-storage,bus=ehci.0,drive=stick"
  --panda-replay $ARTIFACTS/idle/ubuntu/record-0
  $ARTIFACTS/idle/ubuntu/vaddr_stats.h5```

- The command shows a table, results are in column "Writes" (statistics about the total
  amount of writed data) and "Addresses" (statistics about different addresses
  written).


## Reproduce results AVML vs LiME (Beginning of IMPACT OF THE ACQUISITION TECHNIQUE)
- Delete ```idle``` dataset (no more neeeded)
- Download the avml dataset [avml.7z](https://www.s3.eurecom.fr/datasets/datasets/applications/03:2025_03:2025_andrea_strata/avml.7z) and extract it into ```$ARTIFACTS/avml```

1) ### (OPTIONAL) Reproduce intermediate files
  - If you want to reproduce the intermediate analysis files (already present
    precomputed in the dataset) it is required at least 32GB of RAM and 3.5
    hours to replay the PANDA snapshots (if the two commands are run in parallel).
  - Create a target directory tree ```mkdir -p $ARTIFACTS/avml/new/lime $ARTIFACTS/avml/new/avml```
  - Run (in parallel) : ```/usr/local/bin/panda-system-x86_64 -hda $ARTIFACTS/avml/rootfs.qcow2 -netdev user,id=vmnic -device e1000,netdev=vmnic -drive if=none,id=stick,format=qcow2,file=$ARTIFACTS/avml/external_64.qcow2,snapshot=off -device usb-ehci,id=ehci -device usb-storage,bus=ehci.0,drive=stick -nographic -m 4096 -panda collector2:force_start=y,path=$ARTIFACTS/avml/new/lime,iomem=$ARTIFACTS/avml/lime/iomem-0,kallsyms=$ARTIFACTS/avml/lime/kallsyms-0,reduced_stats=y -replay $ARTIFACTS/avml/lime/record-0```
  - Run : ```/usr/local/bin/panda-system-x86_64 -hda $ARTIFACTS/avml/rootfs.qcow2 -netdev user,id=vmnic -device e1000,netdev=vmnic -drive if=none,id=stick,format=qcow2,file=$ARTIFACTS/avml/external_64.qcow2,snapshot=off -device usb-ehci,id=ehci -device usb-storage,bus=ehci.0,drive=stick -nographic -m 4096 -panda collector2:force_start=y,path=$ARTIFACTS/avml/new/avml,iomem=$ARTIFACTS/avml/avml/iomem-0,kallsyms=$ARTIFACTS/avml/avml/kallsyms-0,reduced_stats=y -replay $ARTIFACTS/avml/avml/record-0```
  - At the end of the two commands overwrite the result files from
    ```$ARTIFACTS/avml/new/XXX``` to ```$ARTIFACTS/avml/XXX```

2) For LiME and AVML dump technique results are in ```$ARTIFACTS/avml/XXX/stats```. In
   particular values: "Total kernel write events", "Total bytes written by the
   kernel" in Bytes (must be divided by 1048576) and  "Total different phisical
   pages"

## Reproduce Table 3
  - Delete ```avml``` dataset (no more needed)
  - Download the fs dataset [fs.7z](https://www.s3.eurecom.fr/datasets/datasets/applications/03:2025_03:2025_andrea_strata/fs.7z) and extract it into ```$ARTIFACTS/fs```

1) ### (OPTIONAL) Reproduce intermediate files
    - If you want to reproduce the intermediate analysis files (already present
      precomputed in the dataset) it is required at least 16GB of RAM and 10
      hours to replay the PANDA snapshots
    - Run script ```./scripts/fs_analysis.sh```

2)  Results are reported in ```table3``` files in
    ```$ARTIFACTS/fs/XXX/results``` (or in ```table3_new``` files in
    ```$ARTIFACTS/fs/XXX/results``` in case you have reproduced intermediate files). In
   Table 3 we have reported the following columns from the two files: "fs",
   "events", "noram", "bytes" (divided by 1073741824), "phys"

3) To obtain the "Time" columns run ```./scripts/fs_analysis_time.py```


## Reproduce Table 4 and Table 5
- Delete ```avml``` dataset (no more neeeded)
- Download the smearing dataset [smearing.7z](https://www.s3.eurecom.fr/datasets/datasets/applications/03:2025_03:2025_andrea_strata/smearing.7z) and extract it into ```$ARTIFACTS/smearing```

1) ### (OPTIONAL) Reproduce intermediate files
    - If you want to reproduce the intermediate analysis files (already present
      precomputed in the dataset) it is required at least 256GB of RAM, other 256GB of disk space and 2 days
      to replay the PANDA snapshots
    
    - Download the machine files [machine.7z](https://www.s3.eurecom.fr/datasets/datasets/applications/03:2025_03:2025_andrea_strata/machine.7z) and expand it into in ```$ARTIFACTS/smearing``` ***If you want to reproduce also the intermediate files of next section do NOT delete the machine files archive, it can be reused***
    - From ```strata_acasac2024``` directory run
    ```script
    ./scripts/smearing_replay.sh
    ```

2) ### Analysis
- Run
  ``` script
  ./scripts/smearing_analysis.py
  ```

## Reproduce Table 6, Table 7 and Table 8
- ***DO NOT DELETE ```smearing``` DATASET***

1) ### (OPTIONAL) Reproduce intermediate files
    - If you want to reproduce the intermediate analysis files (already present
      precomputed in the dataset) it is required at least 256GB of RAM and 1 day
      to replay the PANDA snapshots
    
    - Download the machine files [machine.7z](https://www.s3.eurecom.fr/datasets/datasets/applications/03:2025_03:2025_andrea_strata/machine.7z) and expand it into in ```$ARTIFACTS/smearing```
    - From ```strata_acasac2024``` directory run
    ```script
    ./scripts/structs_replay.sh
    ```

2) ### Analysis
- Run
  ``` script
  ./scripts/structs_analysis.py
  ```
