from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import search_corpus


class SearchCorpusTests(unittest.TestCase):
    def test_discovery_is_compact_and_smallest_first(self) -> None:
        large_insns = ["lwz r3,0(r4)"] * 8
        small_insns = ["lwz r3,0(r4)", "blr"]
        large = search_corpus.Func(
            "melee",
            "both_off",
            "reference_projects/melee/large.c",
            "large",
            large_insns,
            "\n".join(large_insns),
        )
        small = search_corpus.Func(
            "mp4",
            "both_off",
            "reference_projects/mp4/small.c",
            "small",
            small_insns,
            "\n".join(small_insns),
        )
        output = io.StringIO()
        with redirect_stdout(output):
            search_corpus.print_discovery(
                [(large, 0, 3), (small, 0, 3)], 2, "both_off", 10
            )
        rendered = output.getvalue()
        self.assertLess(rendered.index("small"), rendered.index("large"))
        self.assertNotIn("lwz r3", rendered)
        self.assertIn(small.result_id, rendered)
        self.assertEqual(small.result_id, small.result_id)

    def test_show_returns_complete_assembly_and_c(self) -> None:
        function = search_corpus.Func(
            "mp4",
            "both_off",
            "reference_projects/mp4/example.c",
            "example",
            ["li r3,1", "blr"],
            "li r3,1\nblr",
        )
        output = io.StringIO()
        with (
            patch.object(search_corpus, "load", return_value=[function]),
            patch.object(
                search_corpus,
                "extract_c_function",
                return_value="int example(void) { return 1; }",
            ),
            redirect_stdout(output),
        ):
            search_corpus.show_function(function.result_id)
        rendered = output.getvalue()
        self.assertIn("--- assembly ---", rendered)
        self.assertIn("li r3,1", rendered)
        self.assertIn("--- C ---", rendered)
        self.assertIn("int example", rendered)


if __name__ == "__main__":
    unittest.main()
