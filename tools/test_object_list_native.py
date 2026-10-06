#!/usr/bin/env python3
"""Exercise the production intrusive list and object-list consumers with 64-bit pointers."""
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PRELUDE = r'''
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8; typedef int8_t s8; typedef int16_t s16;
typedef uint16_t u16; typedef uint32_t u32; typedef float f32;
/* External object dependencies have native layouts; no retail byte offsets. */
typedef struct GameObject GameObject;
typedef struct { void (*hitDetect)(GameObject*); } ObjectInterface;
typedef struct { int flags, mapLoadObjectId, group8RegistrationCount; const char* name; } ModelDef;
typedef struct { int shapeFlags,flags; float localPosX,localPosY,localPosZ,worldPosX,worldPosY,worldPosZ; }
    ObjHitsPriorityState;
typedef struct {
    void* hostPrefix[3]; void* next; GameObject* parent;
    ModelDef* modelInstance; ObjHitsPriorityState* hitReactState; ObjectInterface** dll;
    void* placementData;
    float localPosX,localPosY,localPosZ,worldPosX,worldPosY,worldPosZ;
    float previousWorldPosX,previousWorldPosY,previousWorldPosZ;
    float previousLocalPosX,previousLocalPosY,previousLocalPosZ;
    s8 activeHitboxMode,transformMatrixIndex; s16 romDefNo;
} ObjAnimComponent;
struct GameObject { ObjAnimComponent anim; u16 objectFlags; void* childObjs[5]; u8 unkEA; int id; };
'''
SERVICES = r'''
static ObjLinkedList gObjUpdateList;
static GameObject objects[64],parentObject;
static ModelDef definitions[64];
static ObjHitsPriorityState hitStates[64];
static GameObject* flat[64];
static GameObject** gObjList=flat;
static GameObject* pending[OBJ_PENDING_DEF_FREE_CAPACITY];
static GameObject** gObjPendingDefFreeList=pending;
static GameObject* deferred[OBJ_DEFERRED_FREE_CAPACITY];
static GameObject** gObjDeferredFreeList=deferred;
static int gObjCount,gObjPendingDefFreeCount,gObjDeferredFreeCount,gObjDefCaptureMode,gObjPartitionPivot;
static int gObjUpdateFlags,framesThisStep=3,cases,mutate,groupCount,recordEvents;
static GameObject* group[1];
static GameObject* released;
static int releaseFlag,warningCount,registeredGroups,initCalls,mapLoads;
static char actual[4096],expected[4096];
static void append(char* buffer,const char* code,int id) {
    size_t size=strlen(buffer); snprintf(buffer+size,4096-size,"%s%d;",code,id);
}
static void event(const char* code,int id) { if (recordEvents) append(actual,code,id); }
static void Obj_RemoveFromUpdateList(GameObject*);
static void Sfx_RemoveLoopedObjectSoundForObject(GameObject* p) { assert(p); }
static void Sfx_StopObjectChannel(GameObject* p,int mask) { assert(p && mask==0x7f); }
static void objFreeObjdef(u8* p,int flag) { released=(GameObject*)p; releaseFlag=flag; }
static char sObjFreeNonExistentObjectWarning[]="missing",sObjFreedObjectMessage[]="freed %s";
static void OSReport(const char* format,...) { if (format==sObjFreeNonExistentObjectWarning) warningCount++; }
static void Obj_TransformLocalPointToWorld(float x,float y,float z,float* ox,float* oy,float* oz,GameObject* p) {
    assert(p==&parentObject);*ox=x+10;*oy=y+20;*oz=z+30;
}
static void Obj_RunInitCallback(GameObject* p,void* data,int unused) {
    assert(p && data==p->anim.placementData && unused==0);initCalls++;
}
static void mapLoadForObject(int id,GameObject* p) { assert(id==p->id && p->anim.modelInstance->mapLoadObjectId==id);mapLoads++; }
static void objAddObjectType(GameObject* p,int groupId) {
    assert(p && (groupId==OBJECT_OBJGROUP_HITBOX || groupId==OBJECT_OBJGROUP_GROUP8));registeredGroups++;
}
static void trackTickDynamicSlotCooldowns(void) { event("K",0); }
static void Obj_UpdateModelBlendStates(void) { event("B",0); }
static void ObjHitReact_ResetActiveObjects(int n) { assert(n==gObjCount);event("R",0); }
static void Obj_UpdateObject(GameObject* p) {
    assert((uintptr_t)p>UINT32_MAX);event("U",p->id);
    if (mutate && p->id==2) Obj_RemoveFromUpdateList(&objects[4]);
}
static int Obj_BuildTransformMatrixSlot(GameObject* p) { event("T",p->id);return 17; }
static void ObjHitReact_UpdateResetObjects(void) { event("D",0); }
static GameObject** objGetAllOfType(int groupId,int* count) { assert(groupId==0);*count=groupCount;event("G",0);return group; }
static void ObjHits_Update(int n) { assert(n==gObjCount);event("H",0); }
static void playerDoHitDetection(GameObject* p) { assert((uintptr_t)p>UINT32_MAX);event("P",p->id); }
static void hitCallback(GameObject* p) { assert((uintptr_t)p>UINT32_MAX);event("C",p->id); }
static void Obj_GetWorldPosition(GameObject* p,float* x,float* y,float* z) {
    assert(x==&p->anim.worldPosX && y==&p->anim.worldPosY && z==&p->anim.worldPosZ);event("W",p->id);
}
static void water(int frames) { assert(frames==3);event("F",0); }
static void modgfx(int a,int b,int c) { assert(!a && !b && !c);event("M",0); }
static void expgfx(int a,int frames,int b,int c) { assert(!a && frames==3 && !b && !c);event("E",0); }
static void ObjHits_TickPriorityHitCooldowns(void) { event("Q",0); }
static void trigger(void) { event("S",0); }
static void triggerCamera(void) { event("A",0); }
static void camera(int frames) { assert(frames==3);event("V",0); }
static struct { void (*runFrame)(int); } waterTable={water},*waterPtr=&waterTable,**gWaterfxInterface=&waterPtr;
static struct { void (*updateActiveEffects)(int,int,int); } modTable={modgfx},*modPtr=&modTable,**gModgfxInterface=&modPtr;
static struct { void (*updateFrameState)(int,int,int,int); } expTable={expgfx},*expPtr=&expTable,**gExpgfxInterface=&expPtr;
static struct { void (*run)(void);void (*updateCamera)(void); } triggerTable={trigger,triggerCamera},
    *triggerPtr=&triggerTable,**gObjectTriggerInterface=&triggerPtr;
static struct { void (*update)(int); } cameraTable={camera},*cameraPtr=&cameraTable,**gCameraInterface=&cameraPtr;
static ObjectInterface hitTable={hitCallback},emptyTable={NULL};
static ObjectInterface* hitTablePtr=&hitTable,*emptyTablePtr=&emptyTable;
'''
CHECKS = r'''
static void reset(void) {
    memset(objects,0,sizeof(objects));memset(definitions,0,sizeof(definitions));memset(hitStates,0,sizeof(hitStates));
    memset(flat,0,sizeof(flat));memset(pending,0,sizeof(pending));memset(deferred,0,sizeof(deferred));
    gObjCount=0;gObjPendingDefFreeCount=0;gObjDeferredFreeCount=0;gObjDefCaptureMode=0;gObjPartitionPivot=99;
    gObjUpdateList.count=0;objListInit(&gObjUpdateList,offsetof(GameObject,anim.next));
    released=NULL;warningCount=0;registeredGroups=0;initCalls=0;mapLoads=0;recordEvents=0;
    for (int i=0;i<64;i++) {
        objects[i].id=i;objects[i].anim.modelInstance=&definitions[i];definitions[i].mapLoadObjectId=-1;
        objects[i].anim.romDefNo=2;objects[i].anim.dll=&hitTablePtr;definitions[i].name="object";
        objects[i].anim.localPosX=i+1;objects[i].anim.localPosY=i+2;objects[i].anim.localPosZ=i+3;
    }
}
static void checkList(ObjLinkedList* list,void** order,int count) {
    assert(list->count==count);void* node=list->head;
    for (int i=0;i<count;i++) { assert(node==order[i]);node=*(void**)((u8*)node+list->nextOffset); }
    assert(!node);cases++;
}
static unsigned randomState=1234567;
static unsigned randomValue(void) { randomState=randomState*1664525u+1013904223u;return randomState; }
static void genericLists(void) {
    struct Node { uint64_t left;void* first;uint64_t middle[5];void* second;uint64_t right; } nodes[64];
    const int offsets[]={offsetof(struct Node,first),offsetof(struct Node,second)};
    for (int variant=0;variant<2;variant++) {
        memset(nodes,0,sizeof(nodes));ObjLinkedList list={0};void* order[64];int count=0;
        for (int i=0;i<64;i++) nodes[i].left=nodes[i].right=0xA123456789ABCDEFull;
        objListInit(&list,offsets[variant]);
        for (int step=0;step<6000;step++) {
            int id=(randomValue()>>16)%64;void* item=&nodes[id];int pos=0;
            while (pos<count && order[pos]!=item) pos++;
            if (pos<count) {
                objList_remove(&list,item);memmove(order+pos,order+pos+1,(count-pos-1)*sizeof(void*));count--;
            } else if (randomValue()&4) {
                pos=count ? (randomValue()>>16)%(count+1) : 0;
                *(void**)((u8*)item+offsets[variant])=NULL;
                objListAdd(&list,pos ? order[pos-1] : NULL,item);
                memmove(order+pos+1,order+pos,(count-pos)*sizeof(void*));order[pos]=item;count++;
            } else objList_remove(&list,item);
            checkList(&list,order,count);
            for (int i=0;i<64;i++) assert(nodes[i].left==0xA123456789ABCDEFull && nodes[i].right==0xA123456789ABCDEFull);
        }
        /* Retail init and empty insertion deliberately do not clear these fields. */
        list.count=17;objListInit(&list,offsets[variant]);assert(list.count==17 && !list.head);
        *(void**)((u8*)&nodes[0]+offsets[variant])=&nodes[1];
        objListAdd(&list,NULL,&nodes[0]);assert(list.count==18);
        assert(*(void**)((u8*)&nodes[0]+offsets[variant])==&nodes[1]);cases++;
    }
}
static void objectLists(void) {
    for (int registered=0;registered<2;registered++) {
        reset();void* order[64];int count=0;
        for (int i=0;i<64;i++) {
            GameObject* p=&objects[i];p->anim.activeHitboxMode=(s8)(randomValue()>>24);
            if (!p->anim.activeHitboxMode) p->anim.activeHitboxMode=1;
            p->objectFlags=OBJECT_FLAG_IN_UPDATE_LIST;
            if (registered) {
                p->anim.parent=i&1 ? &parentObject : NULL;p->anim.hitReactState=&hitStates[i];
                definitions[i].mapLoadObjectId=i;definitions[i].flags=i%3==0 ? OBJDEF_FLAG_HITBOX_GROUP : 0;
                definitions[i].group8RegistrationCount=i%2;
                Obj_RegisterObject(p,1);
                assert(flat[i]==p && gObjCount==i+1);
                assert(p->anim.worldPosX==i+1+(i&1 ? 10 : 0));
                assert(p->anim.worldPosY==i+2+(i&1 ? 20 : 0));
                assert(p->anim.worldPosZ==i+3+(i&1 ? 30 : 0));
                assert(p->anim.previousWorldPosX==p->anim.worldPosX && p->anim.previousLocalPosX==i+1);
                assert(hitStates[i].localPosX==i+1 && hitStates[i].worldPosX==i+1);
            } else Obj_InsertIntoUpdateList(p);
            int pos=0;while (pos<count && ((GameObject*)order[pos])->anim.activeHitboxMode>p->anim.activeHitboxMode) pos++;
            memmove(order+pos+1,order+pos,(count-pos)*sizeof(void*));order[pos]=p;count++;
            checkList(&gObjUpdateList,order,count);
        }
        if (registered) assert(initCalls==64 && mapLoads==64 && registeredGroups==22+32);
        while (count) {
            int pos=(randomValue()>>16)%count;GameObject* p=order[pos];Obj_RemoveFromUpdateList(p);
            memmove(order+pos,order+pos+1,(count-pos-1)*sizeof(void*));count--;checkList(&gObjUpdateList,order,count);
            assert(p->objectFlags&OBJECT_FLAG_IN_UPDATE_LIST);
        }
        objects[0].objectFlags=0;Obj_InsertIntoUpdateList(&objects[0]);Obj_RemoveFromUpdateList(&objects[0]);
        checkList(&gObjUpdateList,order,0);
    }
    for (int pos=0;pos<12;pos++) for (int mode=0;mode<3;mode++) for (int wait=0;wait<2;wait++) {
        reset();void* order[12];gObjDefCaptureMode=mode;
        for (int i=0;i<12;i++) { objects[i].anim.activeHitboxMode=100-i;Obj_RegisterObject(&objects[i],1);order[i]=&objects[i]; }
        GameObject* p=&objects[pos];p->unkEA=wait;Obj_FreeObject(p);
        memmove(order+pos,order+pos+1,(11-pos)*sizeof(void*));
        checkList(&gObjUpdateList,order,11);assert(gObjCount==11 && gObjPartitionPivot==0);
        for (int i=0;i<11;i++) assert(flat[i]==order[i]);
        assert(p->objectFlags&OBJECT_FLAG_FREED);
        if (wait) assert(gObjPendingDefFreeCount==1 && pending[0]==p && !released && !gObjDeferredFreeCount);
        else if (mode==2) assert(gObjDeferredFreeCount==1 && deferred[0]==p && !released);
        else assert(released==p && releaseFlag==!mode);
        Obj_FreeObject(p);assert(gObjCount==11 && gObjUpdateList.count==11);cases++;
    }
}
static void frameTraversal(void) {
    for (int flags=0;flags<4;flags++) for (int family=0;family<3;family++)
    for (int childKind=0;childKind<5;childKind++) for (mutate=0;mutate<2;mutate++) {
        reset();
        for (int i=0;i<8;i++) {
            objects[i].objectFlags=OBJECT_FLAG_IN_UPDATE_LIST;objects[i].anim.activeHitboxMode=100-i*10;
            Obj_InsertIntoUpdateList(&objects[i]);
        }
        gObjCount=8;definitions[1].flags=OBJDEF_FLAG_HITBOX_GROUP;
        objects[0].anim.romDefNo=0;objects[4].anim.romDefNo=31;
        objects[3].anim.hitReactState=&hitStates[3];hitStates[3].shapeFlags=8;hitStates[3].flags=1;
        objects[4].anim.hitReactState=&hitStates[4];hitStates[4].shapeFlags=8;
        objects[5].objectFlags|=OBJECT_OBJFLAG_HITDETECT_DISABLED;
        objects[6].anim.dll=NULL;objects[7].anim.dll=&emptyTablePtr;
        group[0]=&objects[9];groupCount=family!=0;objects[9].anim.parent=&parentObject;
        objects[9].childObjs[0]=family==2 ? &objects[8] : NULL;
        if (childKind==0) objects[8].anim.romDefNo=31;
        if (childKind==2) objects[8].anim.dll=NULL;
        if (childKind==3) objects[8].anim.dll=&emptyTablePtr;
        if (childKind==4) objects[8].objectFlags=OBJECT_OBJFLAG_HITDETECT_DISABLED;
        actual[0]=expected[0]=0;recordEvents=1;Obj_UpdateAllObjects(flags);recordEvents=0;
        assert(gObjUpdateFlags==flags && objects[1].anim.transformMatrixIndex==17);
        if (!(flags&1)) append(expected,"K",0);
        strcat(expected,"B0;R0;U0;U1;T1;");
        if (!(flags&1)) append(expected,"D",0);
        append(expected,"U",2);if (!mutate) append(expected,"U",4);
        strcat(expected,"U5;U6;U7;G0;");
        if (family==2) { append(expected,"U",8);assert(objects[8].anim.parent==&parentObject); }
        if (!(flags&1)) {
            strcat(expected,"H0;P0;W0;C1;W1;C2;W2;C3;W3;");
            if (!mutate) strcat(expected,"P4;W4;");
            append(expected,"G",0);
            if (family==2 && childKind<2) { append(expected,childKind ? "C" : "P",8);append(expected,"W",8); }
            append(expected,"F",0);
        }
        if (!(flags&2)) strcat(expected,"M0;E0;");
        if (!(flags&1)) strcat(expected,"Q0;S0;A0;V0;");
        if (strcmp(actual,expected)) { fprintf(stderr,"actual %s\nexpect %s\n",actual,expected);assert(0); }
        cases++;
    }
}
int main(void) {
    assert(sizeof(void*)==8 && sizeof(ptrdiff_t)==sizeof(void*));
    assert((uintptr_t)objects>UINT32_MAX && offsetof(GameObject,anim.next)!=0x38);
    genericLists();objectLists();frameTraversal();
    printf("%d intrusive/object-list checks passed\n",cases);
}
'''


def function(text, name):
    match = re.search(r"^void " + name + r"\([^;{]+?\)\s*\{", text, re.M)
    assert match, name
    depth, end = 1, match.end()
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[match.start():end] + "\n"


def source():
    obj = (ROOT / "src/main/object.c").read_text()
    engine = (ROOT / "src/main/modelEngine.c").read_text()
    header = (ROOT / "include/main/model_engine.h").read_text()
    record = re.search(r"typedef struct ObjLinkedList.*?} ObjLinkedList;", header, re.S)[0]
    constants = ""
    for name in ("OBJECT_FLAG_IN_UPDATE_LIST", "OBJECT_FLAG_FREED", "OBJECT_OBJGROUP_HITBOX", "OBJECT_OBJGROUP_GROUP8"):
        constants += re.search(r"^#define " + name + r"\s+[^\n]+", obj, re.M)[0] + "\n"
    for name in ("OBJ_PENDING_DEF_FREE_CAPACITY", "OBJ_DEFERRED_FREE_CAPACITY"):
        constants += "enum { " + re.search(name + r"\s*=\s*\d+", obj)[0] + " };\n"
    constants += "#define OBJDEF_FLAG_HITBOX_GROUP 0x40\n#define OBJECT_OBJFLAG_HITDETECT_DISABLED 0x2000\n"
    constants += "#define SFX_OBJECT_CHANNEL_MASK_ALL 0x7f\n"
    functions = "".join(function(engine, n) for n in ("objListInit", "objListAdd", "objList_remove"))
    functions += "".join(function(obj, n) for n in ("Obj_InsertIntoUpdateList", "Obj_RemoveFromUpdateList",
                                                   "Obj_RegisterObject", "Obj_FreeObject", "Obj_UpdateAllObjects"))
    return PRELUDE + record + "\n" + constants + SERVICES + functions + CHECKS


class NativeObjectList(unittest.TestCase):
    def test_lists(self):
        compiler = shutil.which("clang")
        self.assertIsNotNone(compiler)
        with tempfile.TemporaryDirectory(prefix="sfa-object-list-") as work:
            path = Path(work) / "list.c"
            path.write_text(source())
            for level in ("-O0", "-O2"):
                with self.subTest(optimization=level):
                    binary = Path(work) / "list"
                    subprocess.run([compiler, "-std=c11", level, "-g", "-fno-common", "-Wall", "-Wextra", "-Werror",
                                    "-fsanitize=address,undefined", "-fno-sanitize-recover=all", str(path), "-o", str(binary)],
                                   check=True, timeout=30)
                    subprocess.run([str(binary)], check=True, timeout=30)


if __name__ == "__main__":
    unittest.main()
