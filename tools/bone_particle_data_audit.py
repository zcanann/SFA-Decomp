"""Check the recovered EN bone-particle tables against the retail object.

This audits initialized data, topology, and buffer storage, not renderer code or
its literal pool.
Run after configuring and building all_source for GSAE01.
"""

import json
from pathlib import Path
import struct

from tricky_object_compare import read_object


ROOT = Path(__file__).resolve().parents[1]
UNIT = "main/dlls/engine/24/24"
TABLES = {
    "gBoneParticleCornersXZ": (0x000, 0x90),
    "gBoneParticleCornersYZ": (0x090, 0x90),
    "gBoneParticleCornersXY": (0x120, 0x90),
    "gBoneParticleInitVertices": (0x1B0, 0x140),
    "gBoneParticleTriangles": (0x2F0, 0x2A0),
    "gBoneParticleJointPlanes": (0x590, 0x22),
    "gBoneParticleJointIds": (0x5B4, 0x23),
    "gBoneParticleJointXYScales": (0x5D8, 0x8C),
    "gBoneParticleJointZScales": (0x664, 0x8C),
    "boneParticleEffect_funcs": (0x6F0, 0x38),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def audit(target, current):
    retail_data = target.sections[".data"][4]
    data = current.sections[".data"][4]
    require(data == retail_data, "initialized data differs from retail")
    require(len(data) == 0x728, "unexpected initialized-data extent")
    relocations = ".rela.data -> .data"
    require([record[:4] for record in current.relocations[relocations]] ==
            [record[:4] for record in target.relocations[relocations]],
            "descriptor callback relocations differ")
    for name, (offset, size) in TABLES.items():
        require(current.symbols[name][:3] == (".data", offset, size),
                f"incorrect layout for {name}")

    buffers = current.symbols["gBoneParticleEffectBuffers"]
    require(buffers[:3] == (".bss", 0, 7 * 4), "expected seven buffer pointers")
    bss = current.sections[".bss"]
    retail_bss = target.sections[".bss"]
    require(bss[0] == retail_bss[0] == "SHT_NOBITS", "buffer storage is not BSS")
    require(bss[2] == retail_bss[2] == 8, "unexpected buffer-section alignment")
    require(bss[3] == 28 and retail_bss[3] == 32, "unexpected buffer-section extent")
    require((bss[3] + bss[2] - 1) & -bss[2] == retail_bss[3],
            "buffer-section tail is not accounted for by alignment")
    require(bss[4] + bytes(4) == retail_bss[4], "buffer-section bytes differ")

    indices = [tuple(data[i + 1:i + 4]) for i in range(0x2F0, 0x590, 16)]
    expected = []
    for ring in range(4):
        for corner in range(4):
            a = ring * 4 + corner
            b = ring * 4 + (corner + 1) % 4
            expected.extend(((a, a + 4, b + 4), (a, b + 4, b)))
    for ring in range(5):
        a = ring * 4
        expected.extend(((a, a + 2, a + 1), (a, a + 2, a + 3)))
    require(indices == expected, "triangle ring/cap topology differs")

    planes = data[0x590:0x5B2]
    joint_ids = data[0x5B4:0x5D7]
    require(all(joint < len(planes) for joint in joint_ids), "joint ID out of bounds")
    require(all(planes[joint] in (0, 1, 2) for joint in joint_ids), "invalid plane")
    for start, zero_axis in ((0, 1), (0x90, 0), (0x120, 2)):
        corners = list(struct.iter_unpack(">3f", data[start:start + 0x90]))
        require(corners[:4] == corners[4:8] == corners[8:12],
                "retained corner copies differ")
        require(all(corner[zero_axis] == 0 for corner in corners), "invalid plane corners")

    return {"initialized_bytes_exact": len(data), "vertices": 20,
            "drawn_triangles": 32, "retained_cap_triangles": 10,
            "joint_groups": len(joint_ids) // 5, "max_joint_id": max(joint_ids),
            "buffer_pointers": 7, "buffer_bytes": 20 * 16, "bss_alignment_bytes": 4}


def main():
    project = json.loads((ROOT / "objdiff.json").read_text())
    unit = next(unit for unit in project["units"] if unit["name"] == UNIT)
    result = audit(read_object(ROOT / unit["target_path"]),
                   read_object(ROOT / unit["base_path"]))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
