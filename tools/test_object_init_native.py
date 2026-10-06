#!/usr/bin/env python3
"""Run object init dispatch with native callbacks and a real texture-scroll initializer.

The interface, placement, shadow and texture-scroll records come from production.
Only the object dependency has a host adapter. A typed bridge invokes the actual
texture-scroll initializer, avoiding unrelated function-type sanitizer warnings
from its object-specific placement prototype.
"""
from pathlib import Path
import os
import re
import subprocess
import tempfile
import unittest

from test_model_instance_layout import function

ROOT = Path(__file__).resolve().parents[1]
PRELUDE = r'''
#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8; typedef int8_t s8; typedef uint16_t u16; typedef int16_t s16;
typedef uint32_t u32; typedef int32_t s32; typedef float f32;
typedef struct { f32 x,y,z; } Vec3f;
typedef struct Texture Texture;
typedef struct ProjectedShadowTexture ProjectedShadowTexture;
typedef struct ObjectShadowMesh ObjectShadowMesh;
typedef struct GameObject GameObject;
'''
SERVICES = r'''
struct GameObject {
    void* hostPrefix[3];
    struct {
        s16 romDefNo;
        ObjectInterfaceHandle dll;
        ObjModelState* modelState;
        float localPosX,localPosY,localPosZ;
        float worldPosX,worldPosY,worldPosZ;
        float previousLocalPosX,previousLocalPosY,previousLocalPosZ;
        float previousWorldPosX,previousWorldPosY,previousWorldPosZ;
    } anim;
    void* extra;
    float externalVelX,externalVelY,externalVelZ;
};
static GameObject object;
static ObjModelState shadows[2];
static TexScrollPlacement placement;
static int expectedFlags, mutation, calls, playerCalls, cases;
static void* expectedPlacement;
static void poison(void) { assert(!"wrong interface slot"); }
static void mutate(GameObject* obj) {
    assert(obj==&object && obj->externalVelX==7 && obj->externalVelY==8 && obj->externalVelZ==9);
    assert(obj->anim.previousLocalPosX==-1 && obj->anim.previousWorldPosZ==-6);
    if (obj->anim.modelState) assert(!(obj->anim.modelState->flags & 8));
    obj->anim.localPosX=71; obj->anim.localPosY=-82; obj->anim.localPosZ=93;
    if (mutation==1) obj->anim.modelState=NULL;
    if (mutation==2) obj->anim.modelState=&shadows[1];
    if (mutation==3 && obj->anim.modelState) obj->anim.modelState->flags=0xa500;
}
static void initSpy(GameObject* obj,void* data,int flags) {
    assert((uintptr_t)obj>UINT32_MAX && data==expectedPlacement && flags==expectedFlags);
    calls++; mutate(obj);
}
static void objLoadPlayerFromSave(GameObject* obj) { playerCalls++; mutate(obj); }
static ObjectInterface table;
static ObjectInterfaceCallback* tablePointer;
static void reset(int id,int handleKind,int shadowKind) {
    memset(&object,0,sizeof(object)); memset(shadows,0xa5,sizeof(shadows));
    shadows[0].flags=0x123400; shadows[1].flags=0x567000;
    object.anim.romDefNo=id;
    object.anim.modelState=shadowKind ? &shadows[shadowKind-1] : NULL;
    object.anim.localPosX=11; object.anim.localPosY=22; object.anim.localPosZ=33;
    object.anim.worldPosX=101; object.anim.worldPosY=102; object.anim.worldPosZ=103;
    object.anim.previousLocalPosX=-1; object.anim.previousLocalPosY=-2; object.anim.previousLocalPosZ=-3;
    object.anim.previousWorldPosX=-4; object.anim.previousWorldPosY=-5; object.anim.previousWorldPosZ=-6;
    object.externalVelX=7; object.externalVelY=8; object.externalVelZ=9;
    table=(ObjectInterface){poison,NULL,poison,poison,poison,poison,poison,NULL};
    table.init=handleKind==2 ? (ObjectInterfaceCallback)(ptrdiff_t)-1 :
        handleKind==3 ? (ObjectInterfaceCallback)initSpy : NULL;
    tablePointer=(ObjectInterfaceCallback*)&table;
    object.anim.dll=handleKind ? &tablePointer : NULL;
    calls=playerCalls=0;
}
static void expectFinish(GameObject* expected) {
    expected->anim.previousLocalPosX=expected->anim.localPosX;
    expected->anim.previousLocalPosY=expected->anim.localPosY;
    expected->anim.previousLocalPosZ=expected->anim.localPosZ;
    expected->anim.previousWorldPosX=expected->anim.localPosX;
    expected->anim.previousWorldPosY=expected->anim.localPosY;
    expected->anim.previousWorldPosZ=expected->anim.localPosZ;
    expected->externalVelX=expected->externalVelY=expected->externalVelZ=0;
}
'''
CHECKS = r'''
static void checkDispatch(int id,int kind,int shadowKind) {
    reset(id,kind,shadowKind);
    GameObject expected=object;
    ObjModelState expectedShadows[2]; memcpy(expectedShadows,shadows,sizeof(shadows));
    ObjectInterface originalTable=table;
    int isPlayer=id==0 || id==31, invoked=isPlayer || kind==3;
    if (invoked) {
        expected.anim.localPosX=71; expected.anim.localPosY=-82; expected.anim.localPosZ=93;
        if (mutation==1) expected.anim.modelState=NULL;
        if (mutation==2) expected.anim.modelState=&shadows[1];
        if (mutation==3 && expected.anim.modelState)
            expectedShadows[expected.anim.modelState-shadows].flags=0xa500;
    }
    if (expected.anim.modelState) expectedShadows[expected.anim.modelState-shadows].flags|=8;
    expectFinish(&expected);
    Obj_RunInitCallback(&object,expectedPlacement,expectedFlags);
    assert(playerCalls==isPlayer && calls==(!isPlayer && kind==3));
    assert(memcmp(&object,&expected,sizeof(object))==0);
    assert(memcmp(shadows,expectedShadows,sizeof(shadows))==0);
    assert(memcmp(&table,&originalTable,sizeof(table))==0);
    cases++;
}
static void textureInit(GameObject* obj,void* data,int flags) {
    assert(data==&placement && flags==expectedFlags); calls++;
    TexScroll_init(obj,data,flags);
}
static void checkTexture(int step,int hasState) {
    reset(309,3,1); table.init=(ObjectInterfaceCallback)textureInit;
    TexScrollState state,expected;
    memset(&state,0xa5,sizeof(state)); expected=state;
    placement.stepX=step; placement.stepY=-step-1; placement.gameBit=step*200;
    object.extra=hasState ? &state : NULL;
    if (hasState) {
        expected.initLock=0; expected.stepX=placement.stepX; expected.stepY=placement.stepY;
        expected.scrollSlot=0; expected.flags=0; expected.gameBit=placement.gameBit;
        if (!expectedFlags) expected.offsetX=expected.offsetY=0;
    }
    TexScrollPlacement originalPlacement=placement;
    Obj_RunInitCallback(&object,&placement,expectedFlags);
    assert(calls==1 && playerCalls==0);
    assert(memcmp(&state,&expected,sizeof(state))==0);
    assert(memcmp(&placement,&originalPlacement,sizeof(placement))==0);
    assert(object.anim.previousLocalPosX==11 && object.anim.previousWorldPosZ==33);
    assert(object.externalVelX==0 && shadows[0].flags==(0x123400|8));
    cases++;
}
int main(void) {
    const int ids[]={-32768,-1,0,1,30,31,32,127,32767};
    const int flags[]={INT_MIN,-1,0,1,7,INT_MAX};
    assert(sizeof(void*)==8 && (uintptr_t)initSpy>UINT32_MAX && (uintptr_t)&placement>UINT32_MAX);
    for (unsigned f=0;f<6;f++) {
        expectedFlags=flags[f];
        for (unsigned i=0;i<9;i++) for (int kind=0;kind<4;kind++) for (int shadow=0;shadow<3;shadow++)
        for (mutation=0;mutation<4;mutation++) for (int p=0;p<2;p++) {
            expectedPlacement=p ? &placement : NULL; checkDispatch(ids[i],kind,shadow);
        }
        for (int step=-128;step<=127;step++) for (int hasState=0;hasState<2;hasState++) checkTexture(step,hasState);
    }
    printf("%d native object-init scenarios passed\n",cases);
}
'''


def harness():
    def read(name):
        return (ROOT / name).read_text()
    interface = read("include/game/objects/object_interface.h")
    interface = re.sub(r'^#include .*|^STATIC_ASSERT\(.*', '', interface, flags=re.M)
    source = read("src/main/object.c")
    anim = read("include/main/objanim_internal.h")
    parts = [PRELUDE, interface]
    for path, name in (("include/main/objanim_internal.h", "ObjModelState"),
                       ("include/game/objects/object_setup.h", "ObjPlacement"),
                       ("include/dlls/objects/texscroll_types.h", "TexScrollPlacement"),
                       ("include/dlls/objects/309_texscroll.h", "TexScrollState")):
        parts.append(re.search(rf'typedef struct {name}\s*\{{.*?\}} {name};', read(path), re.S)[0])
    parts.append(re.search(r'typedef enum ObjModelStateFlag.*?} ObjModelStateFlag;', anim, re.S)[0])
    for name in ("OBJECT_SEQID_SABRE", "OBJECT_SEQID_KRYSTAL"):
        parts.append(re.search(rf'^#define {name}\s+[^\n]+', source, re.M)[0])
    parts += [SERVICES, function(source, "Obj_RunInitCallback"),
              function(read("src/dlls/objects/309_texscroll/texscroll.c"), "TexScroll_init"), CHECKS]
    return "\n".join(parts)


class ObjectInitNativeTests(unittest.TestCase):
    def test_native_dispatch_and_texture_scroll(self):
        with tempfile.TemporaryDirectory(prefix="object-init-native-") as directory:
            source = Path(directory) / "init.c"
            source.write_text(harness())
            for optimization in ("-O0", "-O2"):
                with self.subTest(optimization=optimization):
                    executable = Path(directory) / "init"
                    subprocess.run([
                        "clang", "-std=c11", optimization, "-Wall", "-Wextra", "-Werror",
                        "-fsanitize=address,undefined", str(source), "-o", str(executable),
                    ], check=True, timeout=30)
                    subprocess.run([str(executable)], check=True, timeout=30,
                                   env={**os.environ, "UBSAN_OPTIONS": "halt_on_error=1"})


if __name__ == "__main__":
    unittest.main()
