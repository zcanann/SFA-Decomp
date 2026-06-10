#include "main/dll/mmshrine/shrine.h"
#include "main/dll/laser19F.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/objlib.h"
#include "main/objseq.h"

typedef struct MmshWaterspikePlacement {
    u8 pad0[0xC - 0x0];
    f32 unkC;
    u8 pad10[0x14 - 0x10];
    s32 unk14;
} MmshWaterspikePlacement;


typedef struct MmshScalesState {
    u8 pad0[0xC - 0x0];
    f32 unkC;
    u8 pad10[0x14 - 0x10];
    s32 unk14;
    u8 pad18[0x24 - 0x18];
    f32 unk24;
    s32 unk28;
    u8 pad2C[0x6A - 0x2C];
    s16 unk6A;
    u8 pad6C[0x6E - 0x6C];
    s16 unk6E;
    u8 pad70[0x140 - 0x70];
} MmshScalesState;


typedef struct MmshWaterspikeObjectDef {
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    s16 unk1C;
    u8 pad1E[0x24 - 0x1E];
    u8 unk24;
    u8 pad25[0x28 - 0x25];
} MmshWaterspikeObjectDef;



extern undefined8 FUN_80006728();
extern undefined4 FUN_80006770();
extern undefined4 FUN_800067c0();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800175cc();
extern undefined4 FUN_80017620();
extern void* FUN_80017624();
extern undefined4 FUN_80017698();
extern u32 randomGetRange(int min, int max);
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_80017b00();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80042b9c();
extern int FUN_80044404();
extern undefined8 FUN_80080f28();
extern undefined4 FUN_8008111c();
extern undefined4 FUN_8011eb10();
extern void fn_801C4664(void *obj);
extern undefined4 FUN_801c4f4c();
extern undefined4 SH_LevelControl_runBloopEvent();
extern undefined4 FUN_801d8480();
extern int FUN_8028683c();
extern undefined4 FUN_80286888();
extern uint FUN_80294cd0();
extern int objCreateLight(int param_1,int param_2);
extern void GameBit_Set(int eventId,int value);
extern void Obj_FreeObject(void *obj);

extern undefined4 DAT_803dc071;
extern ObjectTriggerInterface **gObjectTriggerInterface;
extern int *gTitleMenuControlInterfaceCopy;
#define gTitleMenuControlInterface gTitleMenuControlInterfaceCopy
extern f64 DOUBLE_803e5bd0;
extern f64 DOUBLE_803e5c08;
extern f32 lbl_803DC074;
extern f32 lbl_803E5BD8;
extern f32 lbl_803E5BE8;

/*
 * --INFO--
 *
 * Function: mmsh_shrine_init
 * EN v1.0 Address: 0x801C52D8
 * EN v1.0 Size: 192b
 * EN v1.1 Address: 0x801C533C
 * EN v1.1 Size: 220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void mmsh_shrine_init(undefined2 *param_1,int param_2)
{
  int iVar1;
  int *piVar2;
  
  piVar2 = ((GameObject *)param_1)->extra;
  *param_1 = 0;
  ((GameObject *)param_1)->animEventCallback = (void *)MMSH_Shrine_SeqFn;
  *(undefined2 *)(piVar2 + 7) = 10;
  *(undefined *)(piVar2 + 9) = 0;
  if (0 < *(short *)(param_2 + 0x1a)) {
    *(short *)(piVar2 + 7) = *(short *)(param_2 + 0x1a) >> 8;
  }
  GameBit_Set(299,0);
  GameBit_Set(0x12d,0);
  *(undefined4 *)(param_1 + 0x7a) = 1;
  if (*(void **)piVar2 == NULL) {
    iVar1 = objCreateLight(0,1);
    *piVar2 = iVar1;
  }
  GameBit_Set(0xf07,1);
  GameBit_Set(0xefa,1);
  return;
}

/*
 * --INFO--
 *
 * Function: mmsh_scales_free
 * EN v1.0 Address: 0x801C53B0
 * EN v1.0 Size: 144b
 * EN v1.1 Address: 0x801C5418
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void mmsh_scales_free(int param_1,int param_2)
{
  void *child;
  (*gObjectTriggerInterface)->freeState(((GameObject *)param_1)->extra);
  (*(code *)(*gTitleMenuControlInterface + 8))(param_1,0xffff,0,0,0);
  child = ((GameObject *)param_1)->seqIdC8;
  if ((child != NULL) && (param_2 == 0)) {
    Obj_FreeObject(child);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: mmsh_scales_update
 * EN v1.0 Address: 0x801C5474
 * EN v1.0 Size: 372b
 */
extern u8 lbl_803DB411;

void mmsh_scales_update(int param_1)
{
  int typeId;
  int *list;
  int obj;
  int found;
  int id;
  int n;
  int i;
  int count;

  if ((((GameObject *)param_1)->anim.placementData != NULL) && (*(short *)(*(int *)&((GameObject *)param_1)->anim.placementData + 0x18) != -1)) {
    i = (*gObjectTriggerInterface)->update((u8 *)param_1, (f32)(u32)lbl_803DB411);
    if ((i != 0) && (((GameObject *)param_1)->classIdB4 == -2)) {
      typeId = *(s8 *)(*(int *)&((GameObject *)param_1)->extra + 0x57);
      found = 0;
      list = (int *)ObjList_GetObjects(&i, &count);
      n = 0;
      for (i = 0, id = typeId; i < count; i++) {
        obj = *list;
        if (((GameObject *)obj)->classIdB4 == typeId) {
          found = obj;
        }
        if (((((GameObject *)obj)->classIdB4 == -2) && (((GameObject *)obj)->anim.classId == 0x10)) &&
           (id == *(char *)(*(int *)&((GameObject *)obj)->extra + 0x57))) {
          n = n + 1;
        }
        list = list + 1;
      }
      if (((n <= 1) && ((u32)found != 0)) && (*(short *)(found + 0xb4) != -1)) {
        *(s16 *)(found + 0xb4) = -1;
        (*gObjectTriggerInterface)->endSequence(id);
      }
      ((GameObject *)param_1)->classIdB4 = -1;
      Obj_FreeObject((void *)param_1);
    }
  }
  return;
}



/* Trivial 4b 0-arg blr leaves. */
void mmsh_shrine_release(void) {}
void mmsh_shrine_initialise(void) {}
void mmsh_scales_hitDetect(void) {}
void mmsh_scales_release(void) {}
void mmsh_scales_initialise(void) {}
void mmsh_waterspike_free(void) {}
void mmsh_waterspike_hitDetect(void) {}
void mmsh_waterspike_release(void) {}
void mmsh_waterspike_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int mmsh_scales_getExtraSize(void) { return 0x140; }
int mmsh_scales_getObjectTypeId(void) { return 0xb; }
int mmsh_waterspike_getExtraSize(void) { return 0x0; }
int mmsh_waterspike_getObjectTypeId(void) { return 0x0; }
void mmsh_waterspike_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4F68;
extern void objRenderFn_8003b8f4(f32);
void mmsh_scales_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E4F68); }

/*
 * --INFO--
 *
 * Function: mmsh_waterspike_update
 * EN v1.0 Address: 0x801C57B0
 * EN v1.0 Size: 380b
 */
extern void *ObjList_FindObjectById(int id);
extern f32 objFn_801948c0(void *obj, int param_2);
extern void fn_80137948(char *fmt, ...);
extern char sWaterSpikeInvalidXyzAnimIdWarning[];
extern int hitDetectFn_80065e50(int obj, f32 x, f32 y, f32 z, int **out, int a, int b);
extern u8 framesThisStep;
extern WaterfxInterface **gWaterfxInterface;
extern f32 lbl_803E4F80;
extern f32 lbl_803E4F84;
extern f32 lbl_803E4F88;

void mmsh_waterspike_update(int param_1)
{
  void *o;
  int *p;
  int obj2;
  int n;
  int i;
  f32 d;
  f32 newY;
  f32 maxY;
  f32 dist;
  int *list;
  int state;

  state = *(int *)&((GameObject *)param_1)->anim.placementData;
  ObjHits_SetHitVolumeSlot(param_1, 9, 1, 0);
  o = ObjList_FindObjectById(((GameObject *)param_1)->moveF8);
  if (o != NULL) {
    dist = objFn_801948c0(o, 3) - ((GameObject *)param_1)->anim.localPosY;
  }
  else {
    fn_80137948(sWaterSpikeInvalidXyzAnimIdWarning, ((MmshWaterspikePlacement *)state)->unk14);
    n = hitDetectFn_80065e50(param_1, ((GameObject *)param_1)->anim.localPosX, ((GameObject *)param_1)->anim.localPosY,
                             ((GameObject *)param_1)->anim.localPosZ, &list, 0, 0);
    if (n != 0) {
      dist = lbl_803E4F80;
      p = list;
      for (i = 0; i < n; i++) {
        obj2 = *p;
        if (*(char *)(obj2 + 0x14) == 0xe) {
          d = *(f32 *)obj2 - ((GameObject *)param_1)->anim.localPosY;
          if (d > dist) {
            dist = d;
          }
        }
        p = p + 1;
      }
    }
  }
  newY = ((GameObject *)param_1)->anim.localPosY + dist;
  maxY = ((MmshWaterspikePlacement *)state)->unkC;
  if (newY > maxY) {
    ((GameObject *)param_1)->anim.localPosY = maxY;
  }
  else {
    ((GameObject *)param_1)->anim.localPosY = newY;
    ((GameObject *)param_1)->countF4 = ((GameObject *)param_1)->countF4 - framesThisStep;
    if (((GameObject *)param_1)->countF4 <= 0) {
      ((GameObject *)param_1)->countF4 = randomGetRange(0x3c, 0xf0);
      if (lbl_803E4F84 == dist) {
        ((void (*)(f32, f32, f32, s16, f32, int))(*gWaterfxInterface)->spawnRipple)(
            ((GameObject *)param_1)->anim.localPosX,
            ((GameObject *)param_1)->anim.localPosY,
            ((GameObject *)param_1)->anim.localPosZ, 0, lbl_803E4F88, 3);
      }
    }
  }
  return;
}

void mmsh_waterspike_init(int obj, s16 *def) {
    register u32 packedEventIds;
    register u32 lowEventId;
    ObjHits_EnableObject(obj);
    ((GameObject *)obj)->countF4 = 0;
    packedEventIds = (u32)(u16)((MmshWaterspikeObjectDef *)def)->unk1C << 16;
    lowEventId = (u32)(u16)((MmshWaterspikeObjectDef *)def)->unk1A;
    packedEventIds |= lowEventId;
    *(u32 *)&((GameObject *)obj)->moveF8 = packedEventIds;
}

extern f32 lbl_803E4F78;
extern u8 Obj_IsLoadingLocked(void);
extern u8 *Obj_AllocObjectSetup(int size, int type);
extern u8 *Obj_SetupObject(u8 *no, int a, int b, int c, int d);
void mmsh_scales_init(int *obj, s16 *def) {
    u8 *state = ((GameObject *)obj)->extra;
    u8 *no;
    int active;
    ((MmshScalesState *)state)->unk6A = def[13];
    ((MmshScalesState *)state)->unk6E = -1;
    ((MmshScalesState *)state)->unk24 = lbl_803E4F68 / (lbl_803E4F68 + (f32)(u32)*(u8 *)((char *)def + 36));
    ((MmshScalesState *)state)->unk28 = -1;
    active = ((GameObject *)obj)->countF4;
    if (active == 0 && def[12] != 1) {
        (*gObjectTriggerInterface)->loadAnimData(state, (u8 *)def);
        ((GameObject *)obj)->countF4 = (int)def[12] + 1;
    } else if (active != 0 && def[12] != active - 1) {
        (*gObjectTriggerInterface)->freeState(state);
        if (def[12] != -1) {
            (*gObjectTriggerInterface)->loadAnimData(state, (u8 *)def);
        }
        ((GameObject *)obj)->countF4 = (int)def[12] + 1;
    }
    if (Obj_IsLoadingLocked() == 0) return;
    no = Obj_AllocObjectSetup(0x24, 0x1b8);
    *(f32 *)(no + 8) = ((GameObject *)obj)->anim.localPosX;
    *(f32 *)(no + 12) = ((GameObject *)obj)->anim.localPosY;
    *(f32 *)(no + 16) = ((GameObject *)obj)->anim.localPosZ;
    no[4] = 32;
    no[5] = 4;
    no[7] = 0xff;
    no = Obj_SetupObject(no, 5, -1, -1, 0);
    ((GameObject *)obj)->seqIdC8 = no;
    *(f32 *)(*(u8 **)&((GameObject *)obj)->seqIdC8 + 8) = *(f32 *)(*(u8 **)&((GameObject *)obj)->seqIdC8 + 8) * lbl_803E4F78;
}
