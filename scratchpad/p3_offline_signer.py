#!/usr/bin/env python3
"""
P3.4-P3.5: Offline slot16 signer (from bytecode trace)

Will be populated after trace analysis.
Structure: regfile state machine + slot16 output extraction.
"""

class OfflineVMSimulator:
    """Simulate VM bytecode execution offline"""

    def __init__(self, trace_json_path=None):
        self.opcode_handlers = {}
        self.trace = None

        if trace_json_path:
            self.load_trace(trace_json_path)

    def load_trace(self, json_path):
        import json
        with open(json_path) as f:
            data = json.load(f)
        self.trace = data.get('trace', [])
        print(f"Loaded trace: {len(self.trace)} opcodes")

    def simulate(self, psk, device_state, query):
        """
        Simulate bytecode execution to compute slot16.

        Args:
            psk: bytes (32B PSK material)
            device_state: dict with device metadata
            query: query string

        Returns:
            slot16: 16-byte hex string
        """
        if not self.trace:
            raise ValueError("No trace loaded")

        # Initialize regfile from device state
        regfile = self._init_regfile(psk, device_state, query)

        # Execute each opcode in trace
        for entry in self.trace[:100]:  # Simulate first 100 opcodes for testing
            op = entry['op']
            regfile = self._execute_op(op, regfile, entry)

        # Extract output (typically regfile[0] or specific register)
        slot16_output = self._extract_slot16(regfile)

        return slot16_output

    def _init_regfile(self, psk, device_state, query):
        """Initialize regfile[32] with PSK + device state"""
        regfile = {}
        for i in range(32):
            regfile[i] = 0

        # Seed regfile with PSK (regfile[0-3] = PSK qwords)
        psk_qwords = [int.from_bytes(psk[i*8:(i+1)*8], 'little') for i in range(4)]
        for i, qw in enumerate(psk_qwords):
            regfile[i] = qw

        # Seed regfile[29] = ratchet (from device state or default)
        regfile[29] = device_state.get('ratchet', 0x9d3450fc)

        return regfile

    def _execute_op(self, op, regfile, entry):
        """Execute one opcode on regfile"""
        # Placeholder: implement based on opcode semantics from trace analysis

        if op == 40:
            # op40: ratchet XOR
            regfile[29] ^= 0xa123f43
        elif op in [18, 38, 15]:
            # Micro-ops: placeholder (will be derived from trace)
            pass
        elif op in [1, 5, 37, 42]:
            # Control: placeholder
            pass

        return regfile

    def _extract_slot16(self, regfile):
        """Extract 16-byte slot16 from regfile output"""
        # Placeholder: typically regfile[0:2] or a specific output buffer

        # For now: return regfile[1] (arbitrary)
        slot16_qword = regfile.get(1, 0)
        return slot16_qword.to_bytes(16, 'little').hex()

def compute_slot16_offline(psk, device_state, query):
    """
    Main API: compute slot16 offline (no phone needed)

    Args:
        psk: 32B hex string
        device_state: dict with device metadata + ratchet
        query: query string

    Returns:
        slot16: 32-char hex string
    """
    psk_bytes = bytes.fromhex(psk)
    sim = OfflineVMSimulator()

    # Load trace if available
    try:
        sim.load_trace('huongB_devirt19/execution_trace.json')
    except FileNotFoundError:
        print("[!] execution_trace.json not found — using stub")
        # Return stub for testing
        return 'stub_slot16_32_chars_placeholder00'

    slot16 = sim.simulate(psk_bytes, device_state, query)
    return slot16

if __name__ == '__main__':
    # Test stub
    psk = 'c02f250f86cc4f198d5706398d292a8b74169aba61affe7cba02e4a3b5198163'
    device_state = {
        'device_id': '7666223875861513749',
        'ratchet': 0x9d3450fc,
    }
    query = 'device_platform=android&os=android&ssmix=a&_rticket=1787492671771'

    slot16 = compute_slot16_offline(psk, device_state, query)
    print(f"Slot16: {slot16}")
