#!/usr/bin/env python3

# This script permit to take a complete snapshot (RAM + DISK) of the machine to be used then
# in record/replay phase or to run a PANDA record from an existing complete snapshot

import argparse
import time
from pandare import Panda

parser = argparse.ArgumentParser()
parser.add_argument('--mem', "-m", type=str, default=4096, help='Panda mem in MB')
parser.add_argument('--extra-args', "-e", default="", type=str, help='Panda extra command line')
parser.add_argument('--prompt', "-p", type=str, default=r"[$#]$", help='Prompt shown on serial port')

parser.add_argument('--loadvm', "-lvm", type=None, help='Restart Panda from snapshot')
parser.add_argument('--snap', "-s", default=-1, type=int, help='Take disk snapshot after XX seconds from the boot')
parser.add_argument('--idle', "-i", default=-1, type=int, help='Take panda snapshot after XX seconds from the boot')

parser.add_argument('--command', "-c", default=None, help='Command to be recorded')
parser.add_argument('--info_files', "-if", default=False, action='store_true', help='Dump iomem and kallsyms')
parser.add_argument('--dump', "-d", default=False, action="store_true", help="Perform a memory dump using dump_guest_memory before executing the command")
parser.add_argument('--dump-virt', "-dv", default=False, action="store_true", help="Perform a memory dump using dump_guest_memory with paging before executing the command")
parser.add_argument('record', type=str, help='Record name')
args = parser.parse_args()

panda = Panda(arch="x86_64", mem=str(args.mem), extra_args=args.extra_args,expect_prompt=args.prompt.encode(),serial_kwargs={"unansi": False})

@panda.queue_blocking
def run_cmd():

    # Restore snapshot
    if args.loadvm:
        print(f"Restoring snapshot {args.loadvm}...")
        panda.revert_sync(args.loadvm) # Can't use self.revert because that would run async and we'd keep going before the revert happens
        panda.run_monitor_cmd("cont")


    # Take snapshot of the disk if time is passed
    if args.snap >= 0:
        print(f"Snap disk after {args.snap} seconds...")
        time.sleep(args.snap)
        panda.run_monitor_cmd(f'savevm {args.record}')
        print("Snapshot completed")
        panda.end_analysis()
        return

    # Take panda snapshot if time is passed
    if args.idle >= 0:
        print(f"Panda record machine in idle  {args.idle} seconds...")
        panda.run_monitor_cmd(f"begin_record {args.record}")
        time.sleep(args.idle)
        panda.run_monitor_cmd("end_record")
        print("Snapshot completed")
        panda.end_analysis()
        return

    # panda.serial_console.send_eol() # Unlock the console if locked
    # panda.serial_console.expect(timeout=None) # WORKAROUND Consume old output in serial line

    # type commmand (note we type command, start recording, finish command)
    panda.type_serial_cmd(args.command)

    # Dump ram!
    if args.dump:
        print("Dump physical memory...")
        r = panda.run_monitor_cmd(f"dump-guest-memory {args.record + '_start.dump'}")

    if args.dump_virt:
        print("Dump virtual memory...")
        r = panda.run_monitor_cmd(f"dump-guest-memory -p {args.record + '_virt_start.dump'}")
        print(r)
    # start recording
    print("Start recording...")
    panda.run_monitor_cmd(f"begin_record {args.record}")

    # finish command
    print(f"Running command {args.command}")
    panda.serial_console.send_eol()
    result = panda.serial_console.expect(timeout=None)

    # End recording
    panda.run_monitor_cmd("end_record")
    print("Finished recording")

    # Collect auxiliary infos
    if args.info_files:
        path = "/".join(args.record.split("/")[:-1]) #BRUTAL
        filename = args.record.split("/")[-1] # BRUTAL!
        # Collect kallsyms
        print("Collect kallsyms and iomem")
        r = panda.run_serial_cmd("cat /proc/kallsyms", no_timeout=True)
        with open(f"{path}/kallsyms_{filename}", "w") as kallsyms:
            kallsyms.write(r)

        # Collect iomem
        r = panda.run_serial_cmd("cat /proc/iomem")
        with open(f"{path}/iomem_{filename}", "w") as iomem:
            iomem.write(r)

    panda.end_analysis()
    return

panda.run()
