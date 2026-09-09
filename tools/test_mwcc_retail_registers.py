import unittest

from mwcc_retail_registers import project


def instruction(address, opcode, *registers):
    return {"address": address, "opcode": opcode,
            "operands": [{"kind": 0, "register_class": 4, "number": register} for register in registers]}


def capture(records, colors, edges=()):
    graph, colored = [], []
    for register in range(max(colors, default=31) + 1):
        prefix = [0] * 9
        prefix[6] = register if register < 32 else -1
        prefix[7] = 4 if register < 32 else 0
        neighbors = [b if a == register else a for a, b in edges if register in (a, b)]
        graph.append({"prefix": prefix, "neighbors": neighbors})
        final = prefix.copy()
        final[6] = colors.get(register, register if register < 32 else 0)
        colored.append({"prefix": final, "neighbors": neighbors})
    return {"class": 4, "final": records, "records": {r["address"]: r for r in records},
            "graph": graph, "colored": colored}


class RetailRegisterTests(unittest.TestCase):
    def test_commuted_add_does_not_invent_a_split(self):
        records = [instruction(1, 0x3F, 32, 32), instruction(2, 0x3F, 33, 33),
                   instruction(3, 0x3C, 3, 32, 33)]
        data = capture(records, {32: 24, 33: 30}, [(32, 33)])
        result = project(data, ["addi r24,r24,1", "addi r30,r30,4", "add r3,r24,r30"],
                         ["addi r31,r31,1", "addi r30,r30,4", "add r3,r30,r31"])
        self.assertTrue(result["retail_projection_valid_with_unmapped_colors_unchanged"])
        self.assertEqual(result["changes"], [{"virtual": 32, "current": 24, "retail": 31,
                                              "instruction_indices": [0, 2]}])

    def test_incompatible_roles_are_rejected(self):
        data = capture([instruction(1, 0x3F, 32, 32), instruction(2, 0x3F, 32, 32)], {32: 23})
        with self.assertRaisesRegex(ValueError, "incompatible virtual-register roles"):
            project(data, ["addi r23,r23,1"] * 2, ["addi r23,r23,1", "addi r27,r27,1"])

    def test_unconstrained_commutative_choice_is_not_claimed_valid(self):
        data = capture([instruction(1, 0x3C, 3, 32, 33)], {32: 24, 33: 30}, [(32, 33)])
        result = project(data, ["add r3,r24,r30"], ["add r3,r30,r31"])
        self.assertEqual(result["unresolved_colors"], {"32": [30, 31], "33": [30, 31]})
        self.assertFalse(result["retail_projection_valid_with_unmapped_colors_unchanged"])

    def test_unmapped_interfering_value_prevents_projection(self):
        data = capture([instruction(1, 0x3F, 32, 32)], {32: 23, 33: 27}, [(32, 33)])
        result = project(data, ["addi r23,r23,1"], ["addi r27,r27,1"])
        self.assertEqual(result["projection_collisions"], [[32, 33, 27]])
        self.assertFalse(result["retail_projection_valid_with_unmapped_colors_unchanged"])

    def test_fixed_alias_cannot_be_recolored(self):
        data = capture([instruction(1, 0x3F, 32, 32)], {32: 3})
        data["graph"][32]["prefix"][6] = 3
        with self.assertRaisesRegex(ValueError, "incompatible virtual-register roles"):
            project(data, ["addi r3,r3,1"], ["addi r4,r4,1"])

    def test_structural_mismatch_is_rejected(self):
        data = capture([instruction(1, 0x3F, 32, 32)], {32: 23})
        with self.assertRaisesRegex(ValueError, "mnemonic differs"):
            project(data, ["addi r23,r23,1"], ["mulli r23,r23,1"])
        with self.assertRaisesRegex(ValueError, "counts differ"):
            project(data, ["addi r23,r23,1"], [])

    def test_d_form_zero_base_and_symbol_names(self):
        data = capture([instruction(1, 0x22, 32, 0)], {32: 23})
        result = project(data, ["lwz r23,0(0) <r12_symbol>"], ["lwz r27,0(0) <r13_symbol>"])
        self.assertEqual(result["changes"][0]["retail"], 27)
        self.assertTrue(result["retail_projection_valid_with_unmapped_colors_unchanged"])


if __name__ == "__main__":
    unittest.main()
