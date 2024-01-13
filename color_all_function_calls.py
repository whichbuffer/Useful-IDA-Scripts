from idautils import *
from idaapi import *
from idc import *

# Use get_segm_start and get_segm_end for getting the segment start and end addresses
seg_start = get_segm_start(here())
seg_end = get_segm_end(here())
heads = Heads(seg_start, seg_end)
functionCalls = []

for i in heads:
    if print_insn_mnem(i) == "call":
        functionCalls.append(i)

print("Number of calls found: %d" % len(functionCalls))

for i in functionCalls:
    # Use set_color in newer versions of IDA Pro
    set_color(i, CIC_ITEM, 0xc7fdff)
