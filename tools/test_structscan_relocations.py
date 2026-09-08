"""Exercise disassembly relocation attachment using real big-endian PPC objects."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import structscan
import strucdiff


class InstructionRelocationTests(unittest.TestCase):
    def test_relocation_field_positions(self):
        match = structscan.relocation_belongs_to_instruction
        self.assertTrue(match(0x10, 0x10, 'R_PPC_REL24'))
        self.assertTrue(match(0x10, 0x10, 'R_PPC_ADDR16_HA'))
        self.assertTrue(match(0x10, 0x12, 'R_PPC_ADDR16_HA'))
        self.assertTrue(match(0x10, 0x12, 'R_PPC_ADDR16_LO'))
        self.assertFalse(match(0x10, 0x12, 'R_PPC_REL24'))
        self.assertFalse(match(0x10, 0x12, 'R_PPC_EMB_SDA21'))
        self.assertFalse(match(0x10, 0x12, 'R_PPC_UNKNOWN'))
        self.assertFalse(match(0x10, 0x14, 'R_PPC_ADDR16_LO'))

    def assemble(self, directory, name, target):
        assembler = Path(structscan.OD).with_name('powerpc-eabi-as')
        if not assembler.is_file() or not Path(structscan.OD).is_file():
            self.skipTest('project PowerPC binutils are required')
        source = directory / (name + '.s')
        obj = directory / (name + '.o')
        source.write_text('''
.text
.globl probe
.type probe, @function
probe:
    lis 3, %s@ha
    addi 3, 3, %s@l
    lis 4, dataValue@ha
    addi 4, 4, dataValue@l
    bl calledFunction
    blr
.size probe, .-probe
.data
.globl dataValue
dataValue:
    .long 123
''' % (target, target))
        subprocess.run([str(assembler), '-mgekko', '-o', str(obj), str(source)], check=True)
        return str(obj)

    def test_halfword_and_branch_targets(self):
        with tempfile.TemporaryDirectory() as temporary:
            obj = self.assemble(Path(temporary), 'probe', 'callbackA')
            words = structscan.words(obj, 'probe')
            self.assertEqual(len(words), 6)
            self.assertEqual([w[3] for w in words], [
                'R_PPC_ADDR16_HA', 'R_PPC_ADDR16_LO',
                'R_PPC_ADDR16_HA', 'R_PPC_ADDR16_LO', 'R_PPC_REL24', None])
            self.assertEqual([w[4] for w in words], [
                'callbackA', 'callbackA', 'POOL', 'POOL', 'calledFunction', None])
            lines = strucdiff.text_lines(obj, 'probe')
            self.assertTrue(all('<callbackA>' in line for line in lines[:2]))
            self.assertTrue(all('<dataValue>' in line for line in lines[2:4]))
            self.assertIn('<calledFunction>', lines[4])
            raw = structscan.words(obj, 'probe', raw=True)
            self.assertTrue(all(w[4] is None for w in raw))

    def test_different_function_addresses_are_not_identical(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = self.assemble(root, 'first', 'callbackA')
            second = self.assemble(root, 'second', 'callbackB')
            # The assembler leaves identical zero immediates; only their
            # halfword relocations distinguish these function pointers.
            self.assertEqual(structscan.fn_diff(first, second, 'probe', raw=True), (0, 0, 6, 6))
            self.assertEqual(structscan.fn_diff(first, second, 'probe'), (2, 0, 6, 6))
            a = structscan.words(first, 'probe')
            b = structscan.words(second, 'probe')
            self.assertFalse(structscan.reloc_equal(a[0], b[0]))
            self.assertFalse(structscan.reloc_equal(a[1], b[1]))
            self.assertTrue(structscan.reloc_equal(a[4], b[4]))
            with patch.object(strucdiff, 'obj_paths', return_value=(first, second)):
                rows, target, current, target_count, current_count = strucdiff.analyse('fixture', 'probe')
            self.assertEqual((target_count, current_count), (6, 6))
            self.assertEqual([row[0] for row in rows], ['r', 'r', ' ', ' ', ' ', ' '])


if __name__ == '__main__':
    unittest.main()
