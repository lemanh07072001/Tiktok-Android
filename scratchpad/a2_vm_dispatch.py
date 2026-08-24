#!/usr/bin/env python3
"""
A2.2: VM Dispatch decoder & bytecode instruction extraction
"""

class VMDispatcher:
    """Decode Pitaya bytecode instructions"""

    def __init__(self, predicate=0x9b374, handler_table_base=0x1d9488, so_base=0x783d001000):
        self.predicate = predicate
        self.handler_table_base = handler_table_base
        self.so_base = so_base

    def decode_op(self, bytecode, offset):
        """
        Extract opcode from bytecode word at offset.
        Bytecode layout: each instruction = 1 qword (8 bytes, little-endian)
        opcode = word & 0x3f (bits 0-5)
        operands = word >> 6

        Returns: (opcode, operands, next_offset) or (None, None, None) if EOF
        """
        if offset + 8 > len(bytecode):
            return None, None, None

        word = int.from_bytes(bytecode[offset:offset+8], 'little')

        op = word & 0x3f
        operands = word >> 6
        next_ptr = offset + 8

        return op, operands, next_ptr

    def resolve_handler_type(self, op):
        """Map opcode to handler type name"""
        handler_map = {
            44: 'block_header',
            40: 'op40_self_modify',
            18: 'micro_op_alu1',
            38: 'micro_op_load2',
            15: 'micro_op_cmp',
            1: 'control_jump',
            5: 'control_loop',
            37: 'control_branch',
            42: 'control_misc',
            31: 'control_exit',
            51: 'data_move',
            46: 'data_arith',
        }
        return handler_map.get(op, f'unknown_op{op}')

    def scan_blocks(self, bytecode):
        """
        Scan bytecode for block headers (op44).
        Each block = header + instructions until next header/exit.

        Returns: list of {'offset': int, 'op': int, 'operands': int}
        """
        blocks = []
        offset = 0

        while offset < len(bytecode):
            op, operands, next_offset = self.decode_op(bytecode, offset)
            if op is None:
                break

            blocks.append({
                'offset': offset,
                'op': op,
                'operands': operands,
                'handler': self.resolve_handler_type(op),
            })

            if op == 44:  # block_header
                # Skip to next block (look for next op44 or end)
                offset = next_offset
            else:
                offset = next_offset

        return blocks

if __name__ == '__main__':
    # Test: load bytecode and scan
    with open('../huongB_devirt19/sign_bytecode.bin', 'rb') as f:
        bytecode = f.read()

    print(f"Bytecode size: {len(bytecode)} bytes")

    dispatcher = VMDispatcher()
    blocks = dispatcher.scan_blocks(bytecode)

    print(f"\nFound {len(blocks)} instructions (first 20):")
    for block in blocks[:20]:
        print(f"  [{block['offset']:6d}] op{block['op']:2d} ({block['handler']:20s}) operands=0x{block['operands']:x}")

    # Count opcodes
    op_counts = {}
    for block in blocks:
        op = block['op']
        op_counts[op] = op_counts.get(op, 0) + 1

    print(f"\nOpcode distribution:")
    for op in sorted(op_counts.keys()):
        print(f"  op{op:2d}: {op_counts[op]:5d} times")
