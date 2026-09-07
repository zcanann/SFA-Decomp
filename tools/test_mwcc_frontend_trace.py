import struct
import unittest

from mwcc_frontend_trace import State


class Register:
    def __init__(self, values, name):
        self.values, self.name = values, name

    def GetValueAsUnsigned(self):
        return self.values[self.name]

    def SetValueFromCString(self, value):
        self.values[self.name] = int(value)
        return True


class Frame:
    def __init__(self, pc):
        self.pc = pc
        self.values = {"rsp": 0x8000, "rbx": 0x3000, "rbp": 0x2000, "rdi": 0x2000, "rax": 0xFFFFFFFF}

    def FindRegister(self, name):
        return Register(self.values, name)

    def GetPC(self):
        return self.pc

    def SetPC(self, pc):
        self.pc = pc
        return True


class FrontendPropagationTests(unittest.TestCase):
    def fixture(self, pc, active=True):
        state = State.__new__(State)
        state.wanted, state.events = {"sampleRootDelta"}, []
        state.stages = [("sampleRootDelta", "IRO_ScalarizeClassDataMembers")]
        memory = {}
        def write(address, data):
            memory.update({address + i: byte for i, byte in enumerate(data)})
        state.read = lambda address, size: bytes(memory[address + i] for i in range(size))
        state.write = write
        state.string = lambda address: "sampleRootDelta"
        for address, value in [(0x5E6610, 0x1000), (0x100A, 0x1100), (0x2000, 0x4000),
                               (0x5E6CA0, 0x5000), (0x5000, 2), (0x5008, 2 if active else 0)]:
            write(address, struct.pack("<I", value))
        for address, value in [(0x2004, 33), (0x4008, 135), (0x3008, 145)]:
            write(address, struct.pack("<H", value))
        write(0x7FF8, bytes(16))
        return state, Frame(pc)

    def test_guest_call_pushes_four_byte_return_address(self):
        state, frame = self.fixture(0x46F26B)
        state.trace_propagation(frame, 0x8000)
        self.assertEqual(frame.values["rsp"], 0x7FFC)
        self.assertEqual(state.read(0x7FF8, 12), bytes(4) + struct.pack("<I", 0x46F270) + bytes(4))
        self.assertEqual(frame.pc, 0x52A3D0)
        self.assertEqual(state.events[0]["kind"], "assign_destination")

    def test_expression_replacement_pushes_guest_operand(self):
        state, frame = self.fixture(0x46F182)
        state.trace_propagation(frame, 0x8000)
        self.assertEqual(state.read(0x7FFC, 4), struct.pack("<I", 0x3000))
        self.assertEqual(frame.pc, 0x46F183)
        self.assertEqual(state.events[0]["kind"], "replace_expression")

    def test_dependency_event_distinguishes_already_unavailable_candidate(self):
        for active in (False, True):
            state, frame = self.fixture(0x46F2FB, active)
            state.trace_propagation(frame, 0x8000)
            self.assertEqual(state.events, [{"function": "sampleRootDelta", "after_stage": 0,
                                            "kind": "assign_dependency", "definition": 135, "use": 145,
                                            "available_before": active}])
            self.assertEqual(frame.values["rax"], 33)
            self.assertEqual(frame.values["rsp"], 0x8000)
            self.assertEqual(frame.pc, 0x46F2FF)

    def test_other_functions_are_resumed_without_recording(self):
        state, frame = self.fixture(0x46F26B)
        state.wanted = set()
        state.trace_propagation(frame, 0x8000)
        self.assertEqual(state.events, [])
        self.assertEqual(frame.pc, 0x52A3D0)


if __name__ == "__main__":
    unittest.main()
