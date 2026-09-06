"""Positive and corruption checks for the compiled bone-particle data audit."""
import copy
import json
import unittest

from bone_particle_data_audit import ROOT, UNIT, audit
from tricky_object_compare import read_object


class BoneParticleDataAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        config = ROOT / "objdiff.json"
        if not config.is_file():
            raise unittest.SkipTest("configure and build GSAE01 all_source first")
        unit = next(unit for unit in json.loads(config.read_text())["units"] if unit["name"] == UNIT)
        paths = [ROOT / unit[key] for key in ("target_path", "base_path")]
        if not all(path.is_file() for path in paths):
            raise unittest.SkipTest("build GSAE01 all_source first")
        cls.target, cls.current = map(read_object, paths)

    def test_current_object(self):
        result = audit(self.target, self.current)
        self.assertEqual(result["buffer_pointers"], 7)
        self.assertEqual(result["initialized_bytes_exact"], 1832)

    def test_reject_eighth_pointer(self):
        current = copy.deepcopy(self.current)
        symbol = current.symbols["gBoneParticleEffectBuffers"]
        current.symbols["gBoneParticleEffectBuffers"] = (*symbol[:2], 32, *symbol[3:])
        with self.assertRaisesRegex(ValueError, "seven buffer pointers"):
            audit(self.target, current)

    def test_reject_wrong_section_alignment(self):
        current = copy.deepcopy(self.current)
        section = current.sections[".bss"]
        current.sections[".bss"] = (*section[:2], 4, *section[3:])
        with self.assertRaisesRegex(ValueError, "section alignment"):
            audit(self.target, current)

    def test_reject_extra_bss_storage(self):
        current = copy.deepcopy(self.current)
        section = current.sections[".bss"]
        current.sections[".bss"] = (*section[:3], 32, section[4] + bytes(4))
        with self.assertRaisesRegex(ValueError, "section extent"):
            audit(self.target, current)

    def test_reject_changed_vertex_data(self):
        current = copy.deepcopy(self.current)
        section = current.sections[".data"]
        data = bytearray(section[4])
        data[0x1B0] ^= 1
        current.sections[".data"] = (*section[:4], bytes(data))
        with self.assertRaisesRegex(ValueError, "initialized data differs"):
            audit(self.target, current)


if __name__ == "__main__":
    unittest.main()
