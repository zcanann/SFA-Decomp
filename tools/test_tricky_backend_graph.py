import copy
import struct
import unittest

from tricky_backend_graph import (capture_color_policy, capture_graph, coloring_order, describe_node,
                                 replay_coloring, replay_simplification, validate_graph, validate_rewrite)


def fixture():
    nodes = [{"address": 0x1000 + 64 * i, "prefix": [0, 0, 0, 0, i, 0, i, 0, 0], "neighbors": []}
             for i in range(32)]
    nodes += [
        {"address": 0x1800, "prefix": [0x1840, 0, 0, 10, 32, 1, 29, 2, 1], "neighbors": [33]},
        {"address": 0x1840, "prefix": [0, 0, 0, 5, 33, 1, 28, 2, 1], "neighbors": [32]},
    ]
    return nodes


def simplification_fixture(removal_order, weights=(10, 5)):
    before = fixture()
    for node in before[32:]:
        node["prefix"][0] = 0
        node["prefix"][3] = 0
        node["prefix"][6] = -1
        node["prefix"][7] = 0
    after = copy.deepcopy(before)
    previous = 0
    for register in removal_order:
        node = after[register]
        node["prefix"][0] = previous
        node["prefix"][3] = weights[register - 32]
        node["prefix"][6] = register - 4
        node["prefix"][7] = 2
        previous = node["address"]
        for neighbor in node["neighbors"]:
            after[neighbor]["prefix"][5] -= 1
    return before, after


class BackendGraphTests(unittest.TestCase):
    def test_capture_color_banks_and_saved_reset_state(self):
        values = {
            0x1E6584: struct.pack("<i", 3), 0x1E0DF0: struct.pack("<3i", 0, 3, 4),
            0x1E67A4: struct.pack("<i", 2), 0x1E10F0: struct.pack("<2i", 31, 30),
            0x1DCA90: struct.pack("<h", 1), 0x1DCA70: bytes([0, 1] + [0] * 30),
        }
        def memory(address, size):
            return values[address - 0x400000][:size]
        self.assertEqual(capture_color_policy(memory, 0x400000), {
            "initial": [0, 3, 4], "reserve": [31, 30], "reserve_cursor": 1, "blocked": [1],
        })
        values[0x1E6584] = struct.pack("<i", 33)
        with self.assertRaisesRegex(ValueError, "bank size"):
            capture_color_policy(memory, 0x400000)
        values[0x1E6584] = b""
        with self.assertRaisesRegex(ValueError, "short GPR color policy"):
            capture_color_policy(memory, 0x400000)

    def test_color_replay_expands_bank_in_declared_order(self):
        before, after = simplification_fixture([32, 33])
        policy = {"initial": [], "reserve": [29, 28], "reserve_cursor": 0, "blocked": []}
        decisions = replay_coloring(before, after, policy)
        self.assertEqual([(d["register"], d["color"], d["expanded_bank"]) for d in decisions],
                         [(33, 29, True), (32, 28, True)])
        self.assertEqual(decisions[1]["blockers"], {29: [33]})
        self.assertEqual(before[32]["prefix"][6], -1)
        self.assertEqual(policy["reserve_cursor"], 0)

    def test_color_replay_uses_lowest_enabled_color_not_bank_order(self):
        before, after = simplification_fixture([32, 33])
        after[33]["prefix"][6], after[32]["prefix"][6] = 28, 29
        policy = {"initial": [29, 28], "reserve": [], "reserve_cursor": 0, "blocked": []}
        self.assertFalse(any(d["expanded_bank"] for d in replay_coloring(before, after, policy)))

    def test_color_replay_skips_blocked_registers_and_consumed_reserve(self):
        before, after = simplification_fixture([32, 33])
        policy = {"initial": [0], "reserve": [31, 30, 29, 28], "reserve_cursor": 1, "blocked": [0, 30]}
        self.assertEqual([d["color"] for d in replay_coloring(before, after, policy)], [29, 28])

    def test_excluded_color_slots_still_block_when_physical(self):
        before, after = simplification_fixture([32, 33])
        for graph in (before, after):
            graph.append({"address": 0x1880, "prefix": [0, 0, 0, 0, 34, 1, 28, 4, 1], "neighbors": [33]})
            graph[33]["neighbors"].append(34)
            graph[33]["prefix"][8] += 1
        policy = {"initial": [28, 29], "reserve": [], "reserve_cursor": 0, "blocked": []}
        self.assertEqual(replay_coloring(before, after, policy)[0]["blockers"], {28: [34]})
        before[34]["prefix"][6] = after[34]["prefix"][6] = 300
        after[33]["prefix"][6], after[32]["prefix"][6] = 28, 29
        self.assertEqual(replay_coloring(before, after, policy)[0]["blockers"], {})

    def test_color_replay_rejects_a_legal_but_unreproduced_assignment(self):
        before, after = simplification_fixture([32, 33])
        after[32]["prefix"][6] = 30
        policy = {"initial": [29], "reserve": [28], "reserve_cursor": 0, "blocked": []}
        validate_graph(after)
        with self.assertRaisesRegex(ValueError, "disagrees.*GPR 32"):
            replay_coloring(before, after, policy)

    def test_color_replay_does_not_invent_spill_behavior(self):
        before, after = simplification_fixture([32, 33])
        policy = {"initial": [29], "reserve": [], "reserve_cursor": 0, "blocked": []}
        with self.assertRaisesRegex(ValueError, "uncaptured spill/retry"):
            replay_coloring(before, after, policy)

    def test_color_replay_rejects_negative_slots_other_than_unassigned(self):
        before, after = simplification_fixture([32, 33])
        for graph in (before, after):
            graph.append({"address": 0x1880, "prefix": [0, 0, 0, 0, 34, 1, -2, 4, 1], "neighbors": [33]})
            graph[33]["neighbors"].append(34)
            graph[33]["prefix"][8] += 1
        policy = {"initial": [29], "reserve": [28], "reserve_cursor": 0, "blocked": []}
        with self.assertRaisesRegex(ValueError, "unsupported negative GPR color slot"):
            replay_coloring(before, after, policy)

    def test_color_replay_rejects_invalid_policy(self):
        before, after = simplification_fixture([32, 33])
        policy = {"initial": [29], "reserve": [28], "reserve_cursor": 0, "blocked": []}
        for key, value in [("initial", [32]), ("reserve", [28, 28]), ("blocked", [-1]), ("reserve_cursor", 2)]:
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "invalid GPR"):
                replay_coloring(before, after, dict(policy, **{key: value}))

    def test_uncolored_graph_accepts_unassigned_colors(self):
        before, _ = simplification_fixture([32, 33])
        validate_graph(before, colored=False)
        with self.assertRaisesRegex(ValueError, "physical GPR color"):
            validate_graph(before)

    def test_low_degree_sweep_reverses_removal_order(self):
        before, after = simplification_fixture([32, 33])
        self.assertEqual(replay_simplification(before, after, [28, 29], 34), [])
        self.assertEqual(coloring_order(after), [33, 32])

    def test_high_degree_cost_and_descending_id_tie(self):
        for weights, selected in [((10, 5), 33), ((5, 10), 32), ((5, 5), 33)]:
            before, after = simplification_fixture([selected, 65 - selected], weights)
            with self.subTest(weights=weights):
                self.assertEqual(replay_simplification(before, after, [28], 34),
                                 [{"register": selected, "degree": 1, "weight": weights[selected - 32]}])

    def test_new_temporaries_have_lower_removal_priority(self):
        before, after = simplification_fixture([32, 33], (100, 0))
        self.assertEqual(replay_simplification(before, after, [28], 33),
                         [{"register": 32, "degree": 1, "weight": 100}])

    def test_replay_rejects_wrong_order_and_final_degrees(self):
        before, after = simplification_fixture([33, 32])
        with self.assertRaisesRegex(ValueError, "disagrees"):
            replay_simplification(before, after, [28, 29], 34)
        before, after = simplification_fixture([32, 33])
        after[32]["prefix"][5] += 1
        with self.assertRaisesRegex(ValueError, "disagrees"):
            replay_simplification(before, after, [28, 29], 34)

    def test_replay_rejects_invalid_available_set_and_count(self):
        before, after = simplification_fixture([32, 33])
        for available in ([], [28, 28], [-1], [32]):
            with self.subTest(available=available), self.assertRaisesRegex(ValueError, "available GPR"):
                replay_simplification(before, after, available, 34)
        with self.assertRaisesRegex(ValueError, "incompatible"):
            replay_simplification(before, after, [28, 29], 35)

    def rewrite_fixture(self, register):
        return {"blocks": [{"instructions": [{"address": 1, "words": [0, 0, 2, 0, 0, 0, 0, 3,
                    (1 << 16) | 0x89, 0x00020400, register, 0]}]}]}

    def test_colors_must_agree_with_rewritten_operands(self):
        before = self.rewrite_fixture(32)
        before["coloring_graph"] = fixture()
        self.assertEqual(validate_rewrite(before, self.rewrite_fixture(29)), 1)
        with self.assertRaisesRegex(ValueError, "disagrees"):
            validate_rewrite(before, self.rewrite_fixture(27))

    def test_rewrite_cannot_claim_absent_or_reused_record(self):
        before = self.rewrite_fixture(32)
        before["coloring_graph"] = fixture()
        final = self.rewrite_fixture(29)
        final["blocks"][0]["instructions"][0]["words"][7] = 4
        with self.assertRaisesRegex(ValueError, "no surviving"):
            validate_rewrite(before, final)

    def test_linked_coloring_order_not_numeric_order(self):
        nodes = fixture()
        self.assertEqual(coloring_order(nodes), [32, 33])
        nodes[32]["prefix"][0], nodes[33]["prefix"][0] = 0, 0x1800
        self.assertEqual(coloring_order(nodes), [33, 32])
        self.assertIn("color order=1", describe_node(nodes, 32))

    def test_excluded_node_color_is_not_a_physical_gpr(self):
        nodes = fixture()
        nodes[32]["prefix"][7] = 4
        nodes[32]["prefix"][6] = 300
        self.assertEqual(coloring_order(nodes), [33])
        self.assertIn("excluded node; raw color slot=300", describe_node(nodes, 32))

    def test_interference_conflicts_are_rejected(self):
        nodes = fixture()
        nodes[32]["prefix"][6] = 28
        with self.assertRaisesRegex(ValueError, "same physical GPR"):
            validate_graph(nodes)

    def test_asymmetry_and_edge_bounds_are_rejected(self):
        for neighbor, error in [(31, "asymmetric"), (34, "outside graph"), (32, "self interference")]:
            nodes = fixture()
            nodes[32]["neighbors"] = [neighbor]
            with self.subTest(neighbor=neighbor), self.assertRaisesRegex(ValueError, error):
                validate_graph(nodes)

    def test_corrupt_node_fields(self):
        for position, value in [(4, 5), (6, 32), (8, 2)]:
            nodes = fixture()
            nodes[32]["prefix"][position] = value
            with self.subTest(position=position), self.assertRaises(ValueError):
                validate_graph(nodes)
        nodes = fixture()
        nodes[33]["address"] = nodes[32]["address"]
        with self.assertRaisesRegex(ValueError, "duplicate"):
            validate_graph(nodes)

    def test_coloring_chain_rejects_cycles_and_external_links(self):
        nodes = fixture()
        nodes[33]["prefix"][0] = nodes[32]["address"]
        with self.assertRaisesRegex(ValueError, "one chain"):
            coloring_order(nodes)
        nodes[33]["prefix"][0] = 1234
        with self.assertRaisesRegex(ValueError, "outside active nodes"):
            coloring_order(nodes)

    def test_no_active_nodes(self):
        self.assertEqual(coloring_order(fixture()[:32]), [])
        with self.assertRaisesRegex(ValueError, "out of range"):
            describe_node(fixture(), 34)

    def test_live_capture_reads_exact_record_widths(self):
        nodes = fixture()
        memory = {}
        def put(address, data):
            memory.update({address + i: value for i, value in enumerate(data)})
        put(0x1E67D0, struct.pack("<I", 0x200))
        put(0x1E6A8C, struct.pack("<I", len(nodes)))
        for index, node in enumerate(nodes):
            put(0x200 + 4 * index, struct.pack("<I", node["address"]))
            put(node["address"], struct.pack("<3Ii3hHh", *node["prefix"]) + struct.pack("<" + "h" * len(node["neighbors"]), *node["neighbors"]))
        self.assertEqual(capture_graph(lambda a, n: bytes(memory[a + i] for i in range(n)), 0), nodes)

    def test_capture_rejects_short_global_read(self):
        with self.assertRaisesRegex(ValueError, "short GPR graph read"):
            capture_graph(lambda a, n: bytes(n - 1), 0)


if __name__ == "__main__":
    unittest.main()
