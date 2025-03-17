#!/usr/bin/env python3

from pickle import load
from dataclasses import dataclass
from collections import defaultdict
from tqdm import tqdm
import matplotlib.pyplot as plt
from statistics import mean
from math import log2, ceil
from hilbertcurve.hilbertcurve import HilbertCurve
from matplotlib.colors import ListedColormap
import os

ARTIFACTS = os.getenv("ARTIFACTS")

@dataclass
class PageTiming:
    start_time: int
    end_time: int

class Page:
    def __init__(self, ppage: int):
        self.ppage =  ppage
        self.pointers = {}
        self.dump_version = None


hilberts_incons = {}
page_to_index = {}

results_files = [
     f"{ARTIFACTS}/idle/ubuntu/results_pointers",
     f"{ARTIFACTS}/idle/vxWorks/results_pointers",
     f"{ARTIFACTS}/idle/win10/results_pointers",
]

pages_files = [

     f"{ARTIFACTS}/idle/ubuntu/kernel_pages",
     f"{ARTIFACTS}/idle/vxWorks/kernel_pages",
     f"{ARTIFACTS}/idle/win10/kernel_pages",
]

ranges = [
     f"{ARTIFACTS}/idle/ubuntu/mtree",
     f"{ARTIFACTS}/idle/vxWorks/mtree",
     f"{ARTIFACTS}/idle/win10/mtree",
]

oss = ["Linux", "vxWorks", "Windows 10"]

# Create the Hibert Curve
pfn = 1048488
p = ceil(0.5 * log2(pfn + 1))
hc = HilbertCurve(p, 2)

for file_idx, file in enumerate(results_files):

    # Load anomalies data
    with open(file, "rb") as f:
        data = load(f)

    # Load physical pages present at dump start
    with open(pages_files[file_idx], "rb") as f:
        ppages_d = load(f)

    ppages = ppages_d["ppages"]
    ppages_huge = ppages_d["ppages_huge"]
    ppages.update(ppages_huge)

    # Load mtree file
    with open(ranges[file_idx], "r") as f:
        i = 0
        for line in f:
            s = line.split()
            if not len(s):
                continue
            if "pc.ram" not in s[-1] and "pc.ram" not in s[-2]:
                continue

            r_start, r_end = s[0].split("-")
            for p in range(int(r_start,16), int(r_end,16), 0x1000):
                page_to_index[p] = i
                i+=1

    pointers = 0  # Total virtual pointers
    broken_pointers = 0 # Total number of virtual pointers with inconsistences
    pages_inconsistentecies = set() # Pages with at least an inconsistency
    distances = [] # Distances between two physical pages linked by pointers
    inconsistent_write = set()

    pages = data["pages"]

    for page, page_o in tqdm(pages.items()):

        # No pointers, ignore it
        if not page_o.pointers:
            continue

        # Not a kernel page (RAM only) at the start of the dump => ignore it (help to esclude false positives)
        if page not in page_to_index or page not in ppages:
            continue

        for dest_page, (pointers_c, version_saved) in page_o.pointers.items():

            # Not a kernel page (RAM only) at the start of the dump => ignore it (help to esclude false positives)
            if dest_page not in page_to_index or dest_page not in ppages:
                continue

            # Not a valid RAM page => ignore it (page_to_index contains more pages, we need this filter to!)
            if dest_page not in pages:
                continue

            pointers += pointers_c
            distance = abs(page - dest_page)
            distances.append(distance)

            # There is an inconsistency?
            if pages[dest_page].dump_version != version_saved:

                if page in data['total_writes']:
                    inconsistent_write.add(page)

                pages_inconsistentecies.add(page)
                broken_pointers += pointers_c

    # Collect data for Hilbert curves
    for i in pages_inconsistentecies:
        try:
            point = tuple(hc.point_from_distance(page_to_index[i]))
        except:
            continue
        if point not in hilberts_incons:
            hilberts_incons[point] = file_idx
        else:
            hilberts_incons[point] = len(results_files)

    print(f"########## {oss[file_idx]}")
    print(f"Broken pointers: {broken_pointers} {broken_pointers/pointers* 100}%")
    print(f"Mean distance between pointer and pointed data (MiB): {int(mean(distances)) / 0x100000}")


# Plot the heatmap according to the Hilbert Curve
x, y = zip(*(hilberts_incons.keys()))
cmap = ListedColormap(["red", "dodgerblue", "darkcyan", "black"])
legend_labels = ["Linux", "vxWorks", "Windows 10", "Multiple OSs"]
scatter = plt.scatter(x,y, c=list(hilberts_incons.values()), cmap=cmap, s=1, marker='.')
plt.xlim(0, 1024)
plt.ylim(0, 1024)
plt.axis("off")

plt.hlines(y=256, xmin=0, xmax=1024, color='black', linestyle="--")
plt.hlines(y=512, xmin=0, xmax=1024, color='black', linestyle="--")
plt.vlines(x=512, ymin=0, ymax=1024, color='black', linestyle="--")
plt.vlines(x=256, ymin=512, ymax=1024, color='black', linestyle="--")
plt.vlines(x=768, ymin=512, ymax=1024, color='black', linestyle="--")


plt.text(256, 128, "512MB", fontsize=12, color='black', alpha=0.7, ha='center', va='center', weight='bold')
plt.text(256, 384, "1024MB", fontsize=12, color='black', alpha=0.7, ha='center', va='center', weight='bold')
plt.text(128, 768, "1536MB", fontsize=12, color='black', alpha=0.7, ha='center', va='center', weight='bold')
plt.text(384, 768, "2048MB", fontsize=12, color='black', alpha=0.7, ha='center', va='center', weight='bold')
plt.text(640, 768, "2560MB", fontsize=12, color='black', alpha=0.7, ha='center', va='center', weight='bold')
plt.text(896, 768, "3072MB", fontsize=12, color='black', alpha=0.7, ha='center', va='center', weight='bold')
plt.text(768, 384, "3584MB", fontsize=12, color='black', alpha=0.7, ha='center', va='center', weight='bold')
plt.text(768, 128, "4096MB", fontsize=12, color='black', alpha=0.7, ha='center', va='center', weight='bold')


plt.legend(handles=scatter.legend_elements()[0], labels=legend_labels, loc='upper right', bbox_to_anchor=(1.02, 1.03), prop={'size': 6})
plt.show()
plt.savefig('inconsistencies.png', dpi=600, bbox_inches='tight')

print("Hilbert curve heatmap created in 'inconsistencies.png'")