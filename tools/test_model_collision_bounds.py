#!/usr/bin/env python3
"""Execute production skeleton-bound initialization with native model records.

The object adapter changes pointer widths and offsets; model records are extracted
unchanged. Geometry expectations use independent ancestor walks. This checks the
initialization contract, not collision response or decoding serialized assets.
"""
from pathlib import Path
import os
import re
import subprocess
import tempfile
import unittest

from test_model_animation_lifecycle import PRELUDE
from test_model_instance_layout import function

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = r'''
#include <math.h>
typedef struct { u8 modelCount, cullDistScale; } Definition;
typedef struct {
    void* hostPrefix[3];
    struct { Definition* modelInstance; ObjModel** modelBanks; f32 hitboxScale; } anim;
} GameObject;
static int cases;
static void closeFloat(float actual, double expected) {
    assert(fabs(actual-expected) <= 0.0001 * fmax(1, fabs(expected)));
}
'''
CHECKS = r'''
static void checkBounds(int count, int shape, float scale, int flags, int absent) {
    ModelFileHeader file = {0};
    ObjModel model = {0};
    ModelBone bones[152] = {0};
    float radii[152], multipliers[152], storage[4][154], expected[4][154];
    const float factors[] = {-2, 0, 0.5f, 1, 2, 3};
    ModelJointWork work = {0};
    for (int row=0; row<4; row++) for (int i=0; i<154; i++) storage[row][i] = -12345;
    for (int i=0; i<152; i++) {
        radii[i] = (i+shape)%5 ? (float)((i*13+shape)%9+1) : 0;
        multipliers[i] = factors[(i+shape)%6];
        bones[i].parent = i ? shape%3==0 ? 0 : shape%3==1 ? (i-1)%128 : (i-1)/2 : -1;
        bones[i].head[0] = i%4==0 ? 0 : 3;
        bones[i].head[1] = i%4==0 ? 0 : 4;
        bones[i].head[2] = 0;
    }
    /* A one-joint fixture has a nonzero radius; zero would make retail read
       a second radius outside that table. Zero scale still reads it. */
    if (count==1) radii[0]=7;
    file.jointCount=count; file.flags=flags;
    file.jointData=(u8*)bones;
    file.jointCollisionRadii=absent==1 ? NULL : radii;
    file.jointCollisionLengthScales=multipliers;
    work.jointRadii=storage[0]+1; work.radiiSq=storage[1]+1;
    work.jointLengths=storage[2]+1; work.jointCullDistances=storage[3]+1;
    model.file=&file; model.skeletonJointData=absent==2 ? NULL : &work;
    memcpy(expected, storage, sizeof(storage));
    if (count && !absent) {
        for (int i=0; i<count; i++) {
            double radius=radii[i]*scale;
            if (!i && radius==0) radius=radii[1]*scale;
            expected[0][i+1]=radius; expected[1][i+1]=radius*radius;
            if (!i) expected[2][i+1]=0.01f;
            else {
                double length=hypot(bones[i].head[0], bones[i].head[1])*scale;
                if (length==0) length=0.1f;
                if (multipliers[i]>=1) length*=multipliers[i];
                expected[2][i+1]=length;
            }
        }
        /* Find each bound by walking its ancestors independently. The root
           special length is excluded from every accumulated path. */
        for (int i=0; i<count; i++) {
            double bound=expected[0][1];
            for (int node=i; node>0; node=bones[node].parent) if (radii[node]!=0) {
                double candidate=expected[0][node+1];
                for (int ancestor=node; ancestor>0; ancestor=bones[ancestor].parent)
                    candidate+=expected[2][ancestor+1];
                bound=fmax(bound,candidate);
            }
            expected[3][i+1]=bound;
        }
    }
    ModelFileHeader fileBefore=file; ObjModel modelBefore=model; ModelJointWork workBefore=work;
    ObjModel_InitSkeletonCollisionBounds(scale,&model);
    assert(memcmp(&file,&fileBefore,sizeof(file))==0);
    assert(memcmp(&model,&modelBefore,sizeof(model))==0);
    assert(memcmp(&work,&workBefore,sizeof(work))==0);
    for (int row=0; row<4; row++) for (int i=0; i<154; i++) closeFloat(storage[row][i], expected[row][i]);
    cases++;
}
static void checkCull(int count, int mask, int factor) {
    ModelFileHeader files[6] = {0}; ObjModel models[6] = {0}; ObjModel* banks[6];
    Definition def={count,factor}; GameObject object={0};
    const int distances[]={0,9,10,11,100,65535};
    double greatest=10;
    for (int i=0;i<6;i++) {
        files[i].cullDistance=distances[i]; models[i].file=&files[i];
        banks[i]=(mask & (1<<i)) ? &models[i] : NULL;
        if (i<count && banks[i] && distances[i]>greatest) greatest=distances[i];
    }
    object.anim.modelInstance=&def; object.anim.modelBanks=banks;
    assert((uintptr_t)&models[0]>UINT32_MAX);
    objInitCullScale(&object);
    closeFloat(object.anim.hitboxScale, factor ? greatest*(10.0*factor/255.0) : greatest);
    cases++;
}
int main(void) {
    const int counts[]={0,1,2,3,16,127,128,152};
    const int flags[]={0,1,0x1000,0xffff};
    const float scales[]={-2,0,0.5f,1,2,10};
    for (int n=0;n<8;n++) for (int shape=0;shape<6;shape++)
    for (int s=0;s<6;s++) for (int f=0;f<4;f++) for (int absent=0;absent<3;absent++)
        checkBounds(counts[n],shape,scales[s],flags[f],absent);
    for (int count=0;count<=6;count++) for (int mask=0;mask<64;mask++)
    for (int factor=0;factor<256;factor++) checkCull(count,mask,factor);
    printf("%d skeleton-bound and cull-scale scenarios passed\n",cases);
}
'''


def harness():
    header = (ROOT / "include/main/model.h").read_text()
    source = (ROOT / "src/main/object.c").read_text()
    parts = [PRELUDE, "typedef size_t TextureReference;"]
    for kind, name in (("union", "ModelTextureEntry"), ("struct", "ModelVtxAnimJob"),
                       ("struct", "ModelFuzzScaleDef"), ("struct", "ModelFileHeader"),
                       ("struct", "ModelRenderOpTextureRefs"), ("struct", "ModelJointWork"),
                       ("struct", "ObjModel"), ("struct", "ModelBone")):
        parts.append(re.search(rf"typedef {kind} {name}\s*\{{.*?\}} {name};", header, re.S)[0])
    parts.append(FIXTURE)
    parts.append(function((ROOT / "src/main/model.c").read_text(), "modelFileHeaderGetCullDistance"))
    for name in ("objInitCullScale", "ObjModel_InitSkeletonCollisionBounds"):
        parts.append(function(source, name))
    return "\n".join(parts + [CHECKS])


class ModelCollisionBoundsTests(unittest.TestCase):
    def test_native_initialization(self):
        with tempfile.TemporaryDirectory(prefix="model-collision-bounds-") as directory:
            source = Path(directory) / "bounds.c"
            source.write_text(harness())
            for optimization in ("-O0", "-O2"):
                with self.subTest(optimization=optimization):
                    executable = Path(directory) / "bounds"
                    subprocess.run([
                        "clang", "-std=c11", optimization, "-Wall", "-Wextra", "-Werror",
                        "-Wno-logical-not-parentheses", "-fsanitize=address,undefined",
                        str(source), "-o", str(executable),
                    ], check=True, timeout=30)
                    subprocess.run([str(executable)], check=True, timeout=30,
                                   env={**os.environ, "UBSAN_OPTIONS": "halt_on_error=1"})


if __name__ == "__main__":
    unittest.main()
