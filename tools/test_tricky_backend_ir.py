import copy
import struct
import unittest

from tricky_backend_ir import (
    capture_snapshot, decode, describe, emitted_instructions, immediate_commoning, instruction_history,
    operand, validate_alignment, validate_snapshot,
)


def reg(number, flags=2, register_class=4):
    return struct.pack("<BBHII", 0, register_class, flags, number, 0)


def immediate(value):
    return struct.pack("<BBi6x", 2, 0, value)


def fixture():
    """Two blocks: li r7,0; fallthrough branch; mr r4,r7; blr."""
    def instruction(address, owner, previous, following, opcode, args, line):
        raw = b"".join(args)
        return {"address": address, "words": [following, previous, owner, 0, 0, 0, 0, line,
                                               opcode | (len(args) << 16)] + list(struct.unpack("<" + "I" * (len(raw) // 4), raw))}

    load = instruction(0x1000, 0x100, 0, 0x1100, 0x89, [reg(7), immediate(0)], 42)
    branch = instruction(0x1100, 0x100, 0x1000, 0, 0, [struct.pack("<BBI6x", 4, 0, 0x300)], 42)
    move = instruction(0x1200, 0x200, 0, 0x1300, 0x8B, [reg(4), reg(7, 1)], 0xFFFFFFFF)
    ret = instruction(0x1300, 0x200, 0x1200, 0, 0x11, [], 43)
    return {
        "name": "test", "stage": "FINAL CODE", "head": 0x100,
        "blocks": [
            {"address": 0x100, "words": [0x200, 0, 0, 0, 0, 0x1000, 0x1100, 1, 0, 0, 0x40002], "instructions": [load, branch]},
            {"address": 0x200, "words": [0, 0x100, 0x300, 0, 0, 0x1200, 0x1300, 2, 0, 0, 0x40002], "instructions": [move, ret]},
        ],
        "labels": {"768": [0, 0x200, 0x10001]},
    }


class BackendIRTests(unittest.TestCase):
    def test_packed_negative_immediate(self):
        self.assertEqual(operand(struct.unpack("<3I", immediate(-48)))["value"], -48)

    def test_register_flags_and_class(self):
        value = operand(struct.unpack("<3I", reg(74, 5, 3)))
        self.assertEqual((value["number"], value["flags"], value["register_class"]), (74, 5, 3))

    def test_register_number_is_a_signed_short(self):
        words = list(struct.unpack("<3I", reg(74)))
        words[1] |= 0xABCD0000
        self.assertEqual(operand(words)["number"], 74)
        words[1] = 0xABCDFFFF
        self.assertEqual(operand(words)["number"], -1)

    def test_immediate_commoning_range_is_inclusive(self):
        instruction = decode(fixture()["blocks"][0]["instructions"][0])
        for number, eligible in [(42, False), (43, True), (202, True), (203, False)]:
            instruction["operands"][0]["number"] = number
            with self.subTest(number=number):
                self.assertEqual(immediate_commoning(instruction, {"first_register": 43, "last_register": 202}), eligible)
        self.assertIsNone(immediate_commoning(None, {}))
        with self.assertRaisesRegex(ValueError, "inverted"):
            immediate_commoning(instruction, {"first_register": 44, "last_register": 43})

    def test_shifted_immediate_gate_and_invalid_destination(self):
        instruction = decode(fixture()["blocks"][0]["instructions"][0])
        instruction["opcode"] = 0x8A
        self.assertTrue(immediate_commoning(instruction, {"first_register": 7, "last_register": 9}))
        instruction["operands"][0]["register_class"] = 3
        with self.assertRaisesRegex(ValueError, "unrecognized immediate destination"):
            immediate_commoning(instruction, {"first_register": 7, "last_register": 9})

    def test_unknown_operand_remains_opaque(self):
        self.assertEqual(operand([3, 123, 0]), {"kind": 3, "raw": struct.pack("<3I", 3, 123, 0).hex()})

    def test_fallthrough_branch_is_not_emitted(self):
        records = emitted_instructions(fixture())
        self.assertEqual([r["opcode"] for r in records], [0x89, 0x8B, 0x11])
        self.assertIsNone(records[1]["line"])

    def test_nonfallthrough_branch_is_emitted(self):
        data = fixture()
        data["labels"]["768"][1] = 0x100
        self.assertEqual(len(emitted_instructions(data)), 4)

    def test_missing_final_target_is_rejected(self):
        data = fixture()
        data["labels"]["768"][1] = 0
        with self.assertRaisesRegex(ValueError, "absent basic block"):
            emitted_instructions(data)

    def test_alignment_checks_real_operand_encoding(self):
        code = bytes.fromhex("38e00000 7ce43b78 4e800020")
        asm = ["li r7,0", "mr r4,r7", "blr"]
        self.assertEqual(len(validate_alignment(fixture(), asm, code)), 3)
        with self.assertRaisesRegex(ValueError, "operand encoding failed"):
            validate_alignment(fixture(), asm, bytes.fromhex("38e00000 7ce53b78 4e800020"))

    def test_alignment_rejects_shift_and_unknown_opcode(self):
        with self.assertRaisesRegex(ValueError, "counts differ"):
            validate_alignment(fixture(), ["li r7,0"], bytes(4))
        with self.assertRaisesRegex(ValueError, "opcode alignment"):
            validate_alignment(fixture(), ["li r7,0", "addi r4,r7,0", "blr"], bytes.fromhex("38e00000 7ce43b78 4e800020"))

    def test_alignment_checks_explicit_registers(self):
        with self.assertRaisesRegex(ValueError, "register alignment"):
            validate_alignment(fixture(), ["li r6,0", "mr r4,r7", "blr"], bytes.fromhex("38e00000 7ce43b78 4e800020"))

    def test_malformed_immediate_cannot_bypass_encoding_check(self):
        data = fixture()
        data["blocks"][0]["instructions"][0]["words"][12] = 3
        with self.assertRaisesRegex(ValueError, "invalid immediate"):
            validate_alignment(data, ["li r7,0", "mr r4,r7", "blr"], bytes.fromhex("38e00000 7ce43b78 4e800020"))

    def test_missing_block_head_label(self):
        data = fixture()
        data["blocks"][0]["words"][2] = 1234
        with self.assertRaisesRegex(ValueError, "missing block-head label"):
            validate_snapshot(data)

    def test_corrupt_links_counts_and_widths(self):
        for word, value in [(0, 0), (1, 123), (5, 0), (6, 0), (10, 0)]:
            data = fixture()
            data["blocks"][0]["words"][word] = value
            with self.subTest(word=word), self.assertRaises(ValueError):
                validate_snapshot(data)
        for word in (0, 1, 2, 8):
            data = fixture()
            data["blocks"][0]["instructions"][0]["words"][word] = 123
            with self.subTest(instruction_word=word), self.assertRaises(ValueError):
                validate_snapshot(data)

    def test_duplicate_address_and_cyclic_label(self):
        data = fixture()
        data["blocks"][1]["address"] = 0x100
        with self.assertRaisesRegex(ValueError, "duplicate"):
            validate_snapshot(data)
        data = fixture()
        data["labels"]["768"][0] = 768
        with self.assertRaisesRegex(ValueError, "cyclic label"):
            validate_snapshot(data)

    def test_nonfinal_stage_cannot_align(self):
        data = fixture()
        data["stage"] = "AFTER REGISTER COLORING"
        with self.assertRaisesRegex(ValueError, "only FINAL CODE"):
            emitted_instructions(data)

    def test_history_keeps_repeated_stages_and_absence(self):
        data = fixture()
        earlier = copy.deepcopy(data)
        earlier["stage"] = "AFTER COPY PROPAGATION"
        earlier["blocks"] = []
        history = instruction_history([earlier, earlier, data], decode(data["blocks"][0]["instructions"][0]))
        self.assertEqual([r["stage_index"] for r in history], [0, 1, 2])
        self.assertIsNone(history[0]["record"])
        self.assertIn("gpr7", describe(history[2]["record"]))

    def memory_fixture(self, data):
        memory = {}
        for block in data["blocks"]:
            for item in [block] + block["instructions"]:
                raw = struct.pack("<" + "I" * len(item["words"]), *item["words"])
                memory.update({item["address"] + i: byte for i, byte in enumerate(raw)})
        for address, words in data["labels"].items():
            raw = struct.pack("<3I", *words)
            memory.update({int(address) + i: byte for i, byte in enumerate(raw)})
        return memory

    def test_capture_reads_only_proven_widths(self):
        data = fixture()
        memory = self.memory_fixture(data)
        def read(address, size):
            return bytes(memory[address + i] for i in range(size))
        self.assertEqual(capture_snapshot(read, "test", "FINAL CODE", 0x100), data)

    def test_capture_handles_call_clobber_operand_tail(self):
        data = fixture()
        call = data["blocks"][1]["instructions"][1]
        call["words"][8] = (54 << 16) | 1
        call["words"].extend(list(struct.unpack("<162I", reg(3, 3) * 54)))
        memory = self.memory_fixture(data)
        captured = capture_snapshot(lambda a, n: bytes(memory[a + i] for i in range(n)), "test", "FINAL CODE", 0x100)
        self.assertEqual(len(decode(captured["blocks"][1]["instructions"][1])["operands"]), 54)

    def test_capture_rejects_block_cycle_and_short_read(self):
        data = fixture()
        data["blocks"][1]["words"][0] = 0x100
        memory = self.memory_fixture(data)
        with self.assertRaisesRegex(ValueError, "cyclic"):
            capture_snapshot(lambda a, n: bytes(memory[a + i] for i in range(n)), "test", "FINAL CODE", 0x100)
        with self.assertRaisesRegex(ValueError, "short IR"):
            capture_snapshot(lambda a, n: b"", "test", "FINAL CODE", 0x100)


if __name__ == "__main__":
    unittest.main()
