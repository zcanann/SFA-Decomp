import unittest

from tricky_source_order_probe import compile_command, reorder


SOURCE = """\
static inline int helper(int value) {
    return value + 1;
}
int first(int value) {
    return helper(value);
}
static inline int other(int value) {
    return value - 1;
}
int last(int value) {
    return other(value);
}
"""


class SourceOrderTests(unittest.TestCase):
    def body_order(self, source):
        markers = {
            "helper": "return value + 1;",
            "first": "return helper(value);",
            "other": "return value - 1;",
            "last": "return other(value);",
        }
        return sorted(markers, key=lambda name: source.index(markers[name]))

    def test_default_order(self):
        self.assertEqual(self.body_order(reorder(SOURCE, False)),
                         ["helper", "first", "other", "last"])
        self.assertEqual(self.body_order(reorder(SOURCE, True)),
                         ["last", "other", "first", "helper"])

    def test_inline_partition_preserves_relative_order(self):
        self.assertEqual(self.body_order(reorder(SOURCE, True, "first")),
                         ["other", "helper", "last", "first"])
        self.assertEqual(self.body_order(reorder(SOURCE, True, "last")),
                         ["last", "first", "other", "helper"])

    def test_declarations_precede_all_bodies(self):
        result = reorder(SOURCE, True, "first")
        first_body = result.index("{")
        for declaration in ("static inline int helper(int value);",
                            "int first(int value);",
                            "static inline int other(int value);",
                            "int last(int value);"):
            self.assertLess(result.index(declaration), first_body)
        self.assertEqual(result.count("return "), 4)

    def test_invalid_placement(self):
        with self.assertRaises(ValueError):
            reorder(SOURCE, False, "invalid")


class CompilerPolicyTests(unittest.TestCase):
    def test_deferred_preserves_automatic_inlining(self):
        base = ["mwcc", "-inline", "auto", "-MMD", "-c", "old.c", "-o", "old"]
        command = compile_command(base, "probe.c", "probe", deferred=True)
        self.assertEqual(command, [
            "mwcc", "-inline", "auto", "-c", "probe.c", "-o", "probe", "-inline", "deferred",
        ])
        self.assertIn("-MMD", base)

    def test_explicit_policy_override(self):
        base = ["mwcc", "-inline", "noauto", "-c", "old.c", "-o", "old"]
        for policy, flag in [("on", "auto"), ("off", "noauto")]:
            command = compile_command(base, "probe.c", "probe", auto_inline=policy)
            self.assertEqual(command[-2:], ["-inline", flag])
        with self.assertRaises(ValueError):
            compile_command(base, "probe.c", "probe", auto_inline="invalid")


if __name__ == "__main__":
    unittest.main()
