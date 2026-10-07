#!/usr/bin/env python3
"""Run the production object destructor against native ownership and callback spies."""
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from brute_match import find_function_body

ROOT = Path(__file__).resolve().parents[1]
PRELUDE = r'''
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8; typedef int8_t s8; typedef uint16_t u16; typedef int16_t s16;
typedef uint32_t u32; typedef int32_t s32; typedef float f32;
typedef struct { f32 x,y,z; } Vec3f;
typedef struct ObjTextureSlotDef ObjTextureSlotDef;
typedef struct ObjHitReactMoveEntry ObjHitReactMoveEntry;
typedef struct ObjAttachPoint ObjAttachPoint;
typedef struct ObjDefHitVolume ObjDefHitVolume;
typedef struct ObjJointBinding ObjJointBinding;
typedef struct { u8 bytes[64]; } Texture;
typedef struct ProjectedShadowTexture ProjectedShadowTexture;
typedef struct { u8 bytes[64]; } ObjModel;
typedef void (*ObjAnimSequenceFreeCallback)(void);
typedef void (*ObjAnimSequenceConditionCallback)(void);
typedef struct ObjSeqState ObjSeqState;
typedef struct GameObject GameObject;
'''
SERVICES = r'''
/* Only dependencies outside the recovered records are adapted to a host layout. */
typedef struct { void (*free)(GameObject*,int); } ObjectInterface;
struct GameObject {
    void* hostPrefix[3];
    struct {
        ObjDef* modelInstance; ObjectInterface** dll; GameObject* parent;
        void* placementData; ObjModelState* modelState; ObjModel** modelBanks;
        s16 romDefNo,classId,defId; u16 flags; s8 hostedMapSlot,bankIndex;
    } anim;
    void* extra; void* pendingParentObj; void* msgQueue;
    u8 contactRefCount,colorFadeFlags,fadeCounter; s16 colorFadeFrames,seqIndex;
};
static GameObject owner,children[40],unplaced,unrelated,observers[2];
static ObjSeqState sequences[2];
static ObjDef definition;
static ObjDef* gObjFileBufferTable[4];
static u8 gObjFileRefCount[4];
static GameObject* objectList[44];
static GameObject** gObjList=objectList;
static int gObjCount;
static ObjModelState shadow;
static ObjModel models[3];
static ObjModel* banks[4];
static Texture ownedTexture,sharedTexture;
static ObjectShadowMesh mesh;
static u8 work[64],queue[64],modLines[64],intersections[64],placements[41][24];
static char sObjFreeObjdefError[]="objFreeObjdef: Error!! (%d)\n";
static int onlySelfValue,ownGroup,childCount,cases;
typedef struct { char code; void* pointer; int value; } Event;
static Event actual[128],expected[128];
static int actualCount,expectedCount;
static void event(char code,void* pointer,int value) {
    assert(actualCount<128);actual[actualCount++]=(Event){code,pointer,value};
}
static void expect(char code,void* pointer,int value) {
    assert(expectedCount<128);expected[expectedCount++]=(Event){code,pointer,value};
}
static void ObjContact_RemoveObjectCallbacks(GameObject* p) { assert(p==&owner);event('C',p,0); }
static void playerFree(GameObject* p,int flag) { assert(p==&owner && flag==onlySelfValue);event('P',p,flag); }
static void dllFree(GameObject* p,int flag) { assert(p==&owner && flag==onlySelfValue);event('D',p,flag); }
static ObjectInterface dllTable={dllFree},emptyTable={NULL};
static ObjectInterface* dllPointer=&dllTable,*emptyPointer=&emptyTable;
static void Resource_Release(void* pointer) { event('R',pointer,0); }
static void titleFree(GameObject* p) { assert(p==&owner);event('T',p,0); }
static void effectsFree(GameObject* p) { assert(p==&owner);event('E',p,0); }
static struct { void (*func15)(GameObject*); } titleTable={titleFree};
static struct { typeof(titleTable)* vtable; } titleInterface={&titleTable},*gTitleMenuControlInterface=&titleInterface;
static struct { void (*freeOwner3)(GameObject*); } effectsTable={effectsFree},*effectsPointer=&effectsTable,
    **gExpgfxInterface=&effectsPointer;
static void objFreeObjectType(GameObject* p,int group) { assert(p==&owner);event('G',p,group); }
static void Obj_FreeObject(GameObject* p) {
    assert((uintptr_t)p>UINT32_MAX && p>=children && p<children+childCount && !p->anim.parent);
    /* Destruction mutates the global array; the producer must snapshot its children first. */
    for (int i=0;i<childCount;i++) assert(children[i].anim.parent==NULL);
    int index=0;while (index<gObjCount && objectList[index]!=p) index++;
    assert(index<gObjCount);memmove(objectList+index,objectList+index+1,(gObjCount-index-1)*sizeof(*objectList));
    gObjCount--;event('K',p,0);
}
static void mapUnloadRomListPage(int slot) { assert(slot==7);event('L',NULL,slot); }
static void shadowVolumesSetDirty(int flag) { assert(flag==1);event('V',NULL,flag); }
static void* newshadows_getSmallDiskTexture(void) { return &sharedTexture; }
static void mm_free(void* pointer) {
    assert(pointer && pointer!=&sharedTexture && pointer!=OBJECT_SHADOW_MESH_UNCACHED);
    assert((uintptr_t)pointer>UINT32_MAX);event('M',pointer,0);
}
static void textureFree(Texture* pointer) { assert(pointer==&ownedTexture);event('X',pointer,0); }
static void ObjModel_Release(ObjModel* p) { assert(p>=models && p<models+3);event('B',p,0); }
static void ObjModel_ClearRenderAttachment(ObjModel* p) {
    assert(p==&models[2] && !owner.colorFadeFrames && !owner.fadeCounter);
    assert(!(owner.colorFadeFlags&OBJ_COLOR_FADE_FLAG_FROZEN));event('A',p,0);
}
static void spawnEffect(void* p,int id,void* a,int duration,void* b) {
    assert(p==&owner && !a && !b && duration==(id==0x7fb ? 0x50 : 0x32));event('F',p,id);
}
static struct { BoneParticleEffectSpawnFn spawnEffect; } boneTable={spawnEffect},*bonePointer=&boneTable,
    **gBoneParticleEffectInterface=&bonePointer;
static void Obj_ClearModelColorFadeRecursive(GameObject* p) { assert(p==&owner);event('O',p,0); }
static int objGetObjectType(GameObject* p) { assert(p==&owner);event('Q',p,0);return ownGroup; }
static void debugPrintf(const char* format,...) { assert(format==sObjFreeObjdefError);event('W',NULL,0); }
static void endSequence(int slot) { assert(slot==owner.seqIndex);event('S',NULL,slot); }
static struct { void (*endSequence)(int); } sequenceTable={endSequence},*sequencePointer=&sequenceTable,
    **gObjectTriggerInterface=&sequencePointer;
'''
CHECKS = r'''
static void check(int onlySelf,int behavior,int callbackKind,int shadowKind,int references,int childrenCount) {
    memset(&owner,0,sizeof(owner));memset(children,0,sizeof(children));memset(&definition,0,sizeof(definition));
    memset(&unplaced,0,sizeof(unplaced));memset(&unrelated,0,sizeof(unrelated));memset(observers,0,sizeof(observers));
    memset(&shadow,0,sizeof(shadow));memset(sequences,0xa5,sizeof(sequences));
    onlySelfValue=onlySelf;childCount=childrenCount;actualCount=expectedCount=0;
    owner.anim.modelInstance=&definition;owner.anim.defId=2;owner.anim.hostedMapSlot=7;
    owner.anim.classId=(behavior&2) ? 0x10 : 3;owner.contactRefCount=behavior&1;
    owner.colorFadeFlags=((behavior&4) ? OBJ_COLOR_FADE_FLAG_FROZEN : 0) |
                         ((behavior&8) ? OBJ_COLOR_FADE_FLAG_ACTIVE : 0);
    owner.colorFadeFrames=75;owner.fadeCounter=19;
    const int sequenceIds[]={-2,-1,0,7};owner.seqIndex=sequenceIds[behavior>>2];
    definition.flags=(behavior&1) ? OBJDEF_FLAG_HITBOX_GROUP : 0;
    definition.group8RegistrationCount=(cases&1) ? 1 : 0;ownGroup=cases%3 ? 9 : 0;
    definition.modLines=(cases&2) ? (struct MapHitLine*)modLines : NULL;
    definition.intersectionLines=(cases&4) ? (struct IntersectLine*)intersections : NULL;
    gObjFileBufferTable[2]=&definition;gObjFileRefCount[2]=references;
    owner.anim.romDefNo=callbackKind==3 ? 0 : callbackKind==4 ? 31 : 2;
    owner.anim.dll=callbackKind==0 ? NULL : callbackKind==1 ? &emptyPointer : &dllPointer;
    ObjectInterface** originalDll=owner.anim.dll;
    for (int i=0;i<childrenCount;i++) {
        children[i].anim.parent=&owner;children[i].anim.placementData=placements[i];objectList[i]=&children[i];
    }
    unplaced.anim.parent=&owner;unrelated.anim.parent=&unrelated;
    objectList[childrenCount]=&unplaced;objectList[childrenCount+1]=&unrelated;
    for (int i=0;i<2;i++) {
        observers[i].anim.classId=0x10;observers[i].extra=&sequences[i];
        sequences[i].targetObj=i ? &unrelated : &owner;sequences[i].targetFreed=i ? 29 : 17;
        observers[i].pendingParentObj=i ? &unrelated : &owner;objectList[childrenCount+2+i]=&observers[i];
    }
    gObjCount=childrenCount+4;
    ObjSeqState expectedSequences[2];memcpy(expectedSequences,sequences,sizeof(sequences));
    expectedSequences[0].targetObj=NULL;expectedSequences[0].targetFreed=1;
    owner.anim.modelState=shadowKind ? &shadow : NULL;
    definition.shadowType=(cases&1) ? OBJ_SHADOW_TYPE_BIG_BOX : 0;
    shadow.shadowTexture=shadowKind==2 ? &sharedTexture : shadowKind>=3 ? &ownedTexture : NULL;
    definition.renderFlags=shadowKind==4 ? OBJDEF_RENDERFLAG_PROJECTED_SHADOW : 0;
    shadow.shadowWorkBuffer=(cases&2) ? work : NULL;
    shadow.shadowRenderResource=shadowKind==5 ? OBJECT_SHADOW_MESH_UNCACHED : (cases&4) ? &mesh : NULL;
    owner.msgQueue=(cases&8) ? queue : NULL;
    banks[0]=&models[0];banks[1]=NULL;banks[2]=&models[1];banks[3]=&models[2];
    owner.anim.modelBanks=banks;owner.anim.bankIndex=3;definition.modelCount=4;
    int placementKind=cases%3;
    owner.anim.placementData=placementKind ? placements[40] : NULL;
    owner.anim.flags=placementKind==2 ? OBJANIM_FLAG_OWNS_PLACEMENT_DATA : 0;

    if (behavior&1) expect('C',&owner,0);
    if (callbackKind>=3) expect('P',&owner,onlySelf);
    else if (callbackKind) {
        if (callbackKind==2) expect('D',&owner,onlySelf);
        expect('R',originalDll,0);
    }
    expect('T',&owner,0);expect('E',&owner,0);
    if (behavior&1) {
        expect('G',&owner,OBJECT_OBJGROUP_HITBOX);
        if (!onlySelf) {
            for (int i=0;i<childrenCount;i++) expect('K',&children[i],0);
            expect('L',NULL,7);
        }
    }
    if (cases&1) expect('G',&owner,OBJECT_OBJGROUP_GROUP8);
    if (shadowKind) {
        if (cases&1) expect('V',NULL,1);
        if (shadowKind>=3) expect(shadowKind==4 ? 'M' : 'X',&ownedTexture,0);
        if (cases&2) expect('M',work,0);
        if (shadowKind!=5 && (cases&4)) expect('M',&mesh,0);
    }
    if (cases&8) expect('M',queue,0);
    for (int i=0;i<3;i++) expect('B',&models[i],0);
    if (behavior&4) { expect('A',&models[2],0);expect('F',&owner,0x7fb);expect('F',&owner,0x7fc); }
    if (behavior&8) expect('O',&owner,0);
    expect('Q',&owner,0);if (ownGroup) expect('G',&owner,ownGroup-1);
    if (!references) expect('W',NULL,0);
    if (references==1) {
        if (cases&2) expect('M',modLines,0);
        if (cases&4) expect('M',intersections,0);
        expect('M',&definition,0);
    }
    if (owner.seqIndex>=0 && !onlySelf) expect('S',NULL,owner.seqIndex);
    if (placementKind==2) expect('M',placements[40],0);
    expect('M',&owner,0);

    objFreeObjectInternal(&owner,onlySelf);
    assert(actualCount==expectedCount);
    for (int i=0;i<expectedCount;i++) {
        assert(actual[i].code==expected[i].code && actual[i].pointer==expected[i].pointer && actual[i].value==expected[i].value);
    }
    assert(gObjFileRefCount[2]==(references ? references-1 : 0));
    assert(!owner.msgQueue && owner.anim.dll==(callbackKind>=3 ? originalDll : NULL));
    assert(owner.seqIndex==(sequenceIds[behavior>>2]>=0 ? -1 : sequenceIds[behavior>>2]));
    assert(owner.colorFadeFrames==((behavior&4) ? 0 : 75) && owner.fadeCounter==((behavior&4) ? 0 : 19));
    assert(owner.colorFadeFlags==((behavior&8) ? OBJ_COLOR_FADE_FLAG_ACTIVE : 0));
    assert(memcmp(expectedSequences,sequences,sizeof(sequences))==0);
    assert(observers[0].pendingParentObj==(!onlySelf && (behavior&2) ? NULL : &owner));
    assert(observers[1].pendingParentObj==&unrelated && unrelated.anim.parent==&unrelated);
    int removeChildren=!onlySelf && (behavior&1);
    assert(gObjCount==(removeChildren ? 4 : childrenCount+4));
    assert(unplaced.anim.parent==(removeChildren ? NULL : &owner));
    for (int i=0;i<childrenCount;i++) assert(children[i].anim.parent==(removeChildren ? NULL : &owner));
    cases++;
}
int main(void) {
    assert(sizeof(void*)==8 && (uintptr_t)&owner>UINT32_MAX);
    assert(offsetof(ObjSeqState,targetFreed)!=0x8f);
    const int counts[]={0,1,20,40},refs[]={0,1,2,255};
    for (int onlySelf=0;onlySelf<2;onlySelf++) for (int behavior=0;behavior<16;behavior++)
    for (int callback=0;callback<5;callback++) for (int shadow=0;shadow<6;shadow++)
    for (int ref=0;ref<4;ref++) for (int count=0;count<4;count++) {
        check(onlySelf,behavior,callback,shadow,refs[ref],counts[count]);
    }
    printf("%d object teardown ownership scenarios passed\n",cases);
}
'''


def record(text, name, prefix="typedef struct"):
    return re.search(re.escape(prefix + " " + name) + r"\s*\{.*?\}" +
                     (r"\s*" + name if prefix == "typedef struct" else "") + r";", text, re.S)[0] + "\n"


def source():
    anim = (ROOT / "include/main/objanim_internal.h").read_text()
    seq = (ROOT / "include/main/objseq.h").read_text()
    obj = (ROOT / "src/main/object.c").read_text()
    game = (ROOT / "include/game/objects/object.h").read_text()
    constants = ""
    for text, names in ((anim, ("OBJANIM_ROOT_CURVE_ROTATION_AXIS_COUNT", "OBJANIM_EVENT_TRIGGER_CAPACITY",
                                "OBJECT_SHADOW_MESH_UNCACHED", "OBJDEF_RENDERFLAG_PROJECTED_SHADOW",
                                "OBJANIM_FLAG_OWNS_PLACEMENT_DATA")),
                        (obj, ("OBJECT_OBJGROUP_HITBOX", "OBJECT_OBJGROUP_GROUP8")),
                        (game, ("OBJ_COLOR_FADE_FLAG_FROZEN", "OBJ_COLOR_FADE_FLAG_ACTIVE"))):
        for name in names:
            constants += re.search(r"^#define " + name + r"\s+[^\n]+", text, re.M)[0] + "\n"
    for name in ("OBJDEF_FLAG_HITBOX_GROUP", "OBJ_SHADOW_TYPE_BIG_BOX"):
        constants += "enum { " + re.search(name + r"\s*=\s*(?:0x)?[0-9a-fA-F]+", anim)[0] + " };\n"
    records = "".join(record(anim, n) for n in ("ObjectShadowMesh", "ObjModelState", "ObjDef", "ObjAnimEventList"))
    records += record(seq, "SeqByte136") + record(seq, "ObjSeqState", "struct")
    bone = (ROOT / "include/main/dll/boneparticleeffect_interface.h").read_text()
    records += re.search(r"typedef void \(\*BoneParticleEffectSpawnFn\).*?;", bone, re.S)[0] + "\n"
    start, end = find_function_body(obj, "objFreeObjectInternal")
    body = "static void objFreeObjectInternal(GameObject* obj,int onlySelf) " + obj[start:end + 1]
    return PRELUDE + constants + records + SERVICES + body + CHECKS


class NativeObjectFree(unittest.TestCase):
    def test_teardown(self):
        compiler = shutil.which("clang")
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory(prefix="sfa-object-free-") as work:
            path = Path(work) / "free.c"
            path.write_text(source())
            for level in ("-O0", "-O2"):
                with self.subTest(optimization=level):
                    binary = Path(work) / "free"
                    subprocess.run([compiler, "-std=gnu11", level, "-g", "-fno-common", "-Wall", "-Wextra", "-Werror",
                                    "-fsanitize=address,undefined", "-fno-sanitize-recover=all", str(path), "-o", str(binary)],
                                   check=True, timeout=30)
                    subprocess.run([str(binary)], check=True, timeout=30)


if __name__ == "__main__":
    unittest.main()
