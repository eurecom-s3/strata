#!/usr/bin/env python3

# This script is used to get the PANDA snapshots for idle experiments

import argparse
import time
from pandare import Panda
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--mem', "-m", type=str, default=4096, help='Panda mem in MB')
parser.add_argument('--extra-args', "-e", type=str, help='Panda command line')

parser.add_argument('--loadvm', "-lvm", type=None, help='Restart Panda from snapshot')
parser.add_argument('--idle', "-i", default=-1, type=int, help='Wait XX seconds after the boot')
parser.add_argument('--wait', "-w", default=-1, type=int, help='Wait XX seconds after the idle time (while recording)')

parser.add_argument('--info-files', "-if", action='store_true', default=False, help='Save info files')
parser.add_argument('--prompt', "-p", type=str, default=r"root@ubuntu:~#", help='Prompt shown on serial port')

parser.add_argument('--command', "-c", default="", type=str, help='Command to be recorded')
parser.add_argument('--net-cmd', "-n", default="", type=str, help='Command to be run on the host to perform network dump')
parser.add_argument('experiments', type=int, help='Number of repetitions')
parser.add_argument('result_path', type=str, help="Path to save results")
args = parser.parse_args()

path = args.result_path

for exp in range(args.experiments):
    panda = Panda(arch="x86_64", mem=str(args.mem), expect_prompt=args.prompt, extra_args=args.extra_args,serial_kwargs={"unansi": False})

    @panda.queue_blocking
    def run_cmd():
        # Restore snapshot
        if args.loadvm:
            print(f"Restoring snapshot {args.loadvm}...")
            panda.revert_sync(args.loadvm) # Can't use self.revert because that would run async and we'd keep going before the revert happens
            panda.run_monitor_cmd("cont")

        # Wait for the prompt
        print("Wait to complete boot...")
        panda.serial_read_until(args.prompt.encode())
        print("Boot completed")

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

            # Run netdump command
            if args.net_cmd:
                print("Start net dump host command...")
                time.sleep(60)
                subprocess.Popen(args.net_cmd.split(), stdout=subprocess.PIPE, shell=True)

            result = panda.serial_console.expect(timeout=None)

        # End recording
        panda.run_monitor_cmd("end_record")
        print("Finished recording")

        if args.info_files:
            # Collect kallsyms
            print("Collect kallsyms and iomem")
            r = panda.run_serial_cmd("sudo cat /proc/kallsyms", no_timeout=True)
            with open(f"{path}/kallsyms-{exp}", "w") as kallsyms:
                kallsyms.write(r)

            # Collect iomem
            r = panda.run_serial_cmd("sudo cat /proc/iomem")
            print(f"{path}/iomem-{exp}")
            with open(f"{path}/iomem-{exp}", "w") as iomem:
                iomem.write(r)


        panda.end_analysis()

    panda.run()
