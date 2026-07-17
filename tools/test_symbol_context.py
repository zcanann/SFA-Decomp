from __future__ import annotations

import unittest

import symbol_context


class SymbolContextTests(unittest.TestCase):
    def test_scanner_extracts_compounds_and_function_pointer_alias_only(self) -> None:
        source = """
typedef void (*Callback)(int mode, float distance);
typedef struct Foo {
    int value;
} Foo, *FooPtr;
typedef Foo FooAlias;
"""
        definitions = symbol_context.scan_definitions(source, "sample.h")
        names = {name for definition in definitions for name in definition.names}
        self.assertIn("Callback", names)
        self.assertIn("Foo", names)
        self.assertIn("FooPtr", names)
        self.assertIn("FooAlias", names)
        self.assertNotIn("mode", names)
        self.assertNotIn("distance", names)

    def test_extract_function_includes_return_and_parameter_types(self) -> None:
        source = """
typedef struct Foo Foo;
Foo* prototype(Foo* value);

Foo* target(Foo* value)
{
    return value;
}
"""
        function = symbol_context.extract_function(source, "target")
        self.assertIsNotNone(function)
        self.assertTrue(function.startswith("Foo* target"))
        self.assertIn("return value", function)


if __name__ == "__main__":
    unittest.main()
