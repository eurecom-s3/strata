#!/usr/bin/env python3

# This script permit to take snapshots for idle experiments

import argparse
import time
from pandare import Panda

parser = argparse.ArgumentParser()
parser.add_argument('--mem', "-m", type=str, default=4096, help='Panda mem in MB')
parser.add_argument('--extra-args', "-e", type=str, help='Panda command line')

parser.add_argument('--loadvm', "-lvm", type=None, help='Restart Panda from snapshot')
parser.add_argument('--idle', "-i", default=-1, type=int, help='Wait XX seconds after the boot')
parser.add_argument('--wait', "-w", default=-1, type=int, help='Wait XX seconds after the idle time (while recording)')

parser.add_argument('--no-network', "-nn", action='store_true', default=False, help='Start with network cable detached')
parser.add_argument('--info_files', "-if", action='store_true', default=False, help='Save info files')
parser.add_argument('--prompt', "-p", type=str, default=r"root@ubuntu:~#", help='Prompt shown on serial port')

parser.add_argument('--command', "-c", default=None, help='Command to be recorded')
parser.add_argument('experiments', type=int, help='Number of repetitions')
parser.add_argument('result_path', type=str, help="Path to save results")
args = parser.parse_args()

path = args.result_path

if args.no_network:
    args.extra_args += " -S"
panda = Panda(arch="x86_64", mem=str(args.mem), expect_prompt=args.prompt, extra_args=args.extra_args,serial_kwargs={"unansi": False})

@panda.queue_blocking
def run_cmd():

    # Detach network cable and start the machine
    if args.no_network:
        panda.run_monitor_cmd("set_link e1000.0 off")
        panda.run_monitor_cmd("set_link user.0 off")
        panda.run_monitor_cmd("cont")

    # Restore snapshot
    if args.loadvm:
        print(f"Restoring snapshot {args.loadvm}...")
        panda.revert_sync(args.loadvm) # Can't use self.revert because that would run async and we'd keep going before the revert happen

    panda.run_monitor_cmd("cont")

    print("Take 4 fake snapshots (due to a panda bug...)")
    for _ in range(4):
        panda.run_monitor_cmd(f"begin_record {path}/record-0")
        time.sleep(1)
        panda.run_monitor_cmd("end_record")


    for exp in range(args.experiments):

        # Wait XX seconds after the boot
        if args.idle >= 0:
            print(f"Waiting {args.idle} seconds...")
            time.sleep(args.idle)

        if args.command:
            # type commmand (note we type command, start recording, finish command)
            panda.type_serial_cmd(args.command)

        # start recording
        print("Start recording...")
        panda.run_monitor_cmd(f"begin_record {path}/record-{exp}")

        if args.wait >= 0:
            print(f"Panda snapshot idle machine after {args.wait} seconds...")
            time.sleep(args.wait)

        if args.command:
            # finish command
            print(f"Running command {args.command}")
            panda.serial_console.send_eol()
            result = panda.serial_console.expect(timeout=None)

        # End recording
        panda.run_monitor_cmd("end_record")
        print("Finished recording")

        if args.info_files:
            if exp == args.experiments - 1:

                # Collect kallsyms
                print("Collect kallsyms and iomem")
                r = panda.run_serial_cmd("cat /proc/kallsyms", no_timeout=True)
                with open(f"{path}/kallsyms-{exp}", "w") as kallsyms:
                    kallsyms.write(r)

                # Collect iomem
                r = panda.run_serial_cmd("cat /proc/iomem")
                print(f"{path}/iomem-{exp}")
                with open(f"{path}/iomem-{exp}", "w") as iomem:
                    iomem.write(r)

    panda.end_analysis()
    return

panda.run()
