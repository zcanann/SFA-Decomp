#include "main/dll/groundanimator_state.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/groundAnimator.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/game_object.h"
#include "main/objanim_internal.h"
#include "main/objseq.h"

typedef struct Dll115Placement {
    u8 pad0[0x18 - 0x0];
    u8 unk18;
    s8 unk19;
    u8 pad1A[0x38 - 0x1A];
    u8 unk38;
    u8 unk39;
    u8 unk3A;
    u8 unk3B;
    s16 unk3C;
    u8 pad3E[0x40 - 0x3E];
} Dll115Placement;


typedef struct WmColumnPlacement {
    u8 pad0[0x18 - 0x0];
    u8 unk18;
    u8 unk19;
    u8 pad1A[0x1E - 0x1A];
    s16 unk1E;
    u8 pad20[0x38 - 0x20];
    u8 unk38;
    u8 unk39;
    u8 unk3A;
    u8 unk3B;
    s16 unk3C;
    u8 pad3E[0x40 - 0x3E];
} WmColumnPlacement;


extern undefined8 FUN_80006824();
extern undefined4 FUN_80017710();
extern undefined4 FUN_8001771c();
extern u32 randomGetRange(int min, int max);
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern int FUN_80017b00();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjGroup_FindNearestObject();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 FUN_8003b818();
extern void objRenderFn_8003b8f4(int param_1, int param_2, int param_3, int param_4, int param_5,
                        f32 scale);
extern int FUN_800632d8();
extern undefined4 FUN_80081118();
extern undefined4 FUN_8011e868();
extern int FUN_80286840();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_80294d60();
extern uint FUN_80294db4();
extern uint countLeadingZeros();
extern uint GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
extern int *ObjList_GetObjects(int *startIndex, int *objectCount);
extern f32 Vec_distance(float *posA, float *posB);
extern int Obj_GetPlayerObject(void);
extern uint playerGetStateFlag310(int obj);
extern void setAButtonIcon(int param_1);
extern void dll_115_seqFn(void);

extern ObjectTriggerInterface **gObjectTriggerInterface;
extern undefined4* lbl_803DCAC0;
#define gCarryableInterface lbl_803DCAC0
extern undefined4* DAT_803dd718;
extern undefined4* DAT_803dd740;
extern f32 lbl_803DC074;
extern f32 lbl_803E37B8;
extern f32 lbl_803E37BC;
extern f32 lbl_803E37C0;
extern f32 lbl_803E37C4;
extern f32 lbl_803E4454;
extern f32 lbl_803E4458;
extern f32 lbl_803E445C;
extern f32 lbl_803E4460;
extern f32 lbl_803E446C;
extern f32 lbl_803E4470;
extern f32 lbl_803E4474;
extern f32 lbl_803E4478;
extern f32 lbl_803E447C;
extern f32 lbl_803E4480;
extern f32 lbl_803E4484;
extern f32 lbl_803E4488;
extern f32 lbl_803E448C;
extern f32 lbl_803E4490;
extern f32 lbl_803E4494;
extern f32 lbl_803E4498;

typedef void (*GroundAnimatorFreeFn)(int obj);
typedef int (*GroundAnimatorVisibleFn)(int obj, int visible);
typedef int (*GroundAnimatorAnimStateFn)(int obj, int state);
typedef void (*GroundAnimatorSetVisibleFn)(int state, int visible);
typedef void (*GroundAnimatorInitAnimFn)(void *obj, undefined4 state, int param_3);

/*
 * --INFO--
 *
 * Function: dll_115_update
 * EN v1.0 Address: 0x8017D0D4
 * EN v1.0 Size: 232b
 * EN v1.1 Address: 0x8017D134
 * EN v1.1 Size: 244b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
typedef struct {
    s16 pad0[12];
    s16 ev18;
    s16 pad1a[7];
    s16 ev28;
    u8 pad2a[0x16];
    u8 id40;
} Dll115MapRow;

void dll_115_update(int obj)
{
  u8 *state;
  u8 *mapData;
  int step;
  int eventId;

  state = ((GameObject *)obj)->extra;
  mapData = (u8 *)((GameObject *)obj)->anim.placementData;
  if ((state[1] & 1) != 0) {
    eventId = ((Dll115MapRow *)(mapData + state[0] * 2))->ev18;
    if (eventId != -1) {
      GameBit_Set(eventId, 1);
    }
    state[1] = (u8)(state[1] & ~1);
    state[0]++;
  }
  switch (state[0]) {
  case 9:
    (*gObjectTriggerInterface)->preempt(obj, ((Dll115Placement *)mapData)->unk3C);
    (*gObjectTriggerInterface)->runSequence(((Dll115Placement *)mapData)->unk3A, (void *)obj,
                                            ((Dll115Placement *)mapData)->unk3B);
    break;
  case 8:
  case 10:
    break;
  default:
    eventId = ((Dll115MapRow *)(mapData + state[0] * 2))->ev28;
    if (eventId == -1) {
      state[0] = 8;
    } else if ((u32)GameBit_Get(eventId) != 0) {
      s8 id = (s8)((Dll115MapRow *)(mapData + state[0]))->id40;
      if (id != -1) {
        (*gObjectTriggerInterface)->runSequence(id, (void *)obj, -1);
      }
    }
    break;
  }
  {
    short *p;
    step = state[0] - 1;
    p = (short *)mapData + step;
    while (step >= 0) {
      eventId = p[12];
      if (eventId == -1) break;
      if ((u32)GameBit_Get(eventId) != 0) break;
      state[0]--;
      p--;
      step--;
    }
  }
}

/*
 * --INFO--
 *
 * Function: dll_115_init
 * EN v1.0 Address: 0x8017D1BC
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x8017D228
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_115_init(short *obj, int mapData)
{
  short *p;
  u8 *state;
  int step;

  state = ((GameObject *)obj)->extra;
  *obj = (s16)(*(u8 *)(mapData + 0x38) << 8);
  ((GameObject *)obj)->animEventCallback = dll_115_seqFn;
  ((GameObject *)obj)->objectFlags |= 0x6000;
  ObjGroup_AddObject((int)obj, 0xf);
  step = 0;
  p = (short *)mapData;
  do {
    if (p[12] == -1) break;
    if ((u32)GameBit_Get(p[12]) == 0) break;
    p++;
    step++;
  } while (step < 8);
  if ((step < 8) && (*(s16 *)(mapData + 0x18 + step * 2) == -1)) {
    state[0] = 8;
  } else {
    state[0] = step;
  }
  if ((state[0] == 8) && ((*(u8 *)(mapData + 0x39) & 0x10) != 0)) {
    state[0] = 9;
  }
}

/*
 * --INFO--
 *
 * Function: dll_115_release_nop
 * EN v1.0 Address: 0x8017D1E0
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8017D24C
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_115_release_nop(void)
{
}

/*
 * --INFO--
 *
 * Function: dll_115_initialise_nop
 * EN v1.0 Address: 0x8017D208
 * EN v1.0 Size: 404b
 * EN v1.1 Address: 0x8017D280
 * EN v1.1 Size: 376b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dll_115_initialise_nop(void)
{
}

/*
 * --INFO--
 *
 * Function: wm_column_getExtraSize
 * EN v1.0 Address: 0x8017D39C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8017D3F8
 * EN v1.1 Size: 240b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int wm_column_getExtraSize(void)
{
  return 0xa;
}

/*
 * --INFO--
 *
 * Function: wm_column_getObjectTypeId
 * EN v1.0 Address: 0x8017D3A0
 * EN v1.0 Size: 232b
 * EN v1.1 Address: 0x8017D4E8
 * EN v1.1 Size: 236b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int wm_column_getObjectTypeId(void)
{
  return 0;
}

/*
 * --INFO--
 *
 * Function: wm_column_free
 * EN v1.0 Address: 0x8017D488
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x8017D5D4
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void wm_column_free(int obj)
{
  ObjGroup_RemoveObject(obj, 4);
  (*(GroundAnimatorFreeFn *)(*gCarryableInterface + 0x10))(obj);
}

/*
 * --INFO--
 *
 * Function: wm_column_render
 * EN v1.0 Address: 0x8017D4AC
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8017D5F8
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void wm_column_render(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
  if ((*(GroundAnimatorVisibleFn *)(*gCarryableInterface + 0xc))(param_1, visible) != 0) {
    objRenderFn_8003b8f4(param_1, param_2, param_3, param_4, param_5, lbl_803E37B8);
  }
}

/*
 * --INFO--
 *
 * Function: wm_column_hitDetect
 * EN v1.0 Address: 0x8017D4D4
 * EN v1.0 Size: 424b
 * EN v1.1 Address: 0x8017D62C
 * EN v1.1 Size: 420b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void wm_column_hitDetect(void)
{
}

/*
 * --INFO--
 *
 * Function: wm_column_update
 * EN v1.0 Address: 0x8017D67C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8017D7D0
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void wm_column_update(int obj)
{
  int *objects;
  u32 playerFlags;
  f32 nearest;
  int i;
  int count;
  int other;
  int state;

  state = *(int *)&((GameObject *)obj)->extra;
  nearest = lbl_803E37BC;
  if ((*(GroundAnimatorAnimStateFn *)(*gCarryableInterface + 8))(obj, *(int *)&((GameObject *)obj)->extra) != 0) {
    if ((((GameObject *)obj)->countF4 & 2) != 0) {
      objects = ObjList_GetObjects(&i, &count);
      for (; i < count; i++) {
        other = objects[i];
        if (((u32)other != (u32)obj) && (((GameObject *)other)->anim.seqId == 499) &&
            (Vec_distance((float *)(obj + 0x18), (float *)(other + 0x18)) < lbl_803E37C0)) {
          other = *(s16 *)(*(int *)&((GameObject *)objects[i])->anim.placementData + 0x1e);
          if (other != -1) {
            GameBit_Set(other, 0);
          }
        }
      }
    }
    playerFlags = Obj_GetPlayerObject();
    ObjGroup_FindNearestObject(0x10, obj, &nearest);
    playerFlags = playerGetStateFlag310(playerFlags);
    if (((playerFlags & 0x4000) != 0) && (nearest > lbl_803E37C4)) {
      (*(GroundAnimatorSetVisibleFn *)(*gCarryableInterface + 0x24))(state, 0);
      setAButtonIcon(5);
      *(u32 *)&((GameObject *)obj)->countF4 |= 1;
    } else {
      (*(GroundAnimatorSetVisibleFn *)(*gCarryableInterface + 0x24))(state, 1);
    }
    *(u32 *)&((GameObject *)obj)->countF4 &= ~2;
  } else {
    if ((((GameObject *)obj)->countF4 & 1) != 0) {
      objects = ObjList_GetObjects(&i, &count);
      for (; i < count; i++) {
        other = objects[i];
        if (((u32)other != (u32)obj) && (((GameObject *)other)->anim.seqId == 499) &&
            (Vec_distance((float *)(obj + 0x18), (float *)(other + 0x18)) < lbl_803E37C0)) {
          int mapData = *(int *)&((GameObject *)objects[i])->anim.placementData;
          if (((GameObject *)obj)->anim.seqId == (s8)((WmColumnPlacement *)mapData)->unk19 + 500) {
            if (((WmColumnPlacement *)mapData)->unk1E != -1) {
              GameBit_Set(((WmColumnPlacement *)mapData)->unk1E, 1);
            }
          } else if (((WmColumnPlacement *)mapData)->unk1E != -1) {
            GameBit_Set(((WmColumnPlacement *)mapData)->unk1E, 0);
          }
          ((GameObject *)obj)->anim.localPosX = ((GameObject *)objects[i])->anim.localPosX;
          ((GameObject *)obj)->anim.localPosY = ((GameObject *)objects[i])->anim.localPosY;
          ((GameObject *)obj)->anim.localPosZ = ((GameObject *)objects[i])->anim.localPosZ;
        }
      }
    }
    playerFlags = playerGetStateFlag310(Obj_GetPlayerObject());
    if ((playerFlags & 0x4000) != 0) {
      (*(GroundAnimatorSetVisibleFn *)(*gCarryableInterface + 0x24))(state, 0);
      *(u32 *)&((GameObject *)obj)->countF4 |= 2;
    } else {
      (*(GroundAnimatorSetVisibleFn *)(*gCarryableInterface + 0x24))(state, 1);
      *(u32 *)&((GameObject *)obj)->countF4 &= ~2;
    }
    *(u32 *)&((GameObject *)obj)->countF4 &= ~1;
  }
}

/*
 * --INFO--
 *
 * Function: wm_column_init
 * EN v1.0 Address: 0x8017D680
 * EN v1.0 Size: 76b
 * EN v1.1 Address: 0x8017D8E4
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void wm_column_init(short *obj, int mapData)
{
  ObjAnimComponent *objAnim = (ObjAnimComponent *)obj;
  undefined4 state = *(undefined4 *)&((GameObject *)(int)obj)->extra;
  *obj = (s16)(*(u8 *)(mapData + 0x18) << 8);
  ((GameObject *)(int)obj)->objectFlags |= 0x2000;
  ((GameObject *)(int)obj)->countF4 = 0;
  objAnim->bankIndex = (s8)(int)*(s8 *)(mapData + 0x19);
  if (objAnim->bankIndex >= objAnim->modelInstance->modelCount) {
    objAnim->bankIndex = 0;
  }
  (*(GroundAnimatorInitAnimFn *)(*gCarryableInterface + 4))(obj, state, 0x32);
  ObjGroup_AddObject((int)obj, 4);
}

/*
 * --INFO--
 *
 * Function: wm_column_release
 * EN v1.0 Address: 0x8017D6CC
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x8017D92C
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void wm_column_release(void)
{
}

/*
 * --INFO--
 *
 * Function: wm_column_initialise
 * EN v1.0 Address: 0x8017D730
 * EN v1.0 Size: 880b
 * EN v1.1 Address: 0x8017D9AC
 * EN v1.1 Size: 784b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void wm_column_initialise(void)
{
}

ObjectDescriptor gWM_ColumnObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)wm_column_initialise,
    (ObjectDescriptorCallback)wm_column_release,
    0,
    (ObjectDescriptorCallback)wm_column_init,
    (ObjectDescriptorCallback)wm_column_update,
    (ObjectDescriptorCallback)wm_column_hitDetect,
    (ObjectDescriptorCallback)wm_column_render,
    (ObjectDescriptorCallback)wm_column_free,
    (ObjectDescriptorCallback)wm_column_getObjectTypeId,
    wm_column_getExtraSize,
};

extern void appleontree_init();
extern u8 appleontree_update[];
extern void appleontree_render(int obj, int p1, int p2, int p3, int p4, s8 visible);
extern void appleontree_free(int *obj);
extern int appleontree_getExtraSize(void);
extern void appleontree_setScale(void);
extern u8 appleontree_modelMtxFn(int *obj);

ObjectDescriptor13 gAppleOnTreeObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_13_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)appleontree_init,
    (ObjectDescriptorCallback)appleontree_update,
    0,
    (ObjectDescriptorCallback)appleontree_render,
    (ObjectDescriptorCallback)appleontree_free,
    0,
    appleontree_getExtraSize,
    (ObjectDescriptorCallback)appleontree_setScale,
    (ObjectDescriptorCallback)appleontree_func0B,
    (ObjectDescriptorCallback)appleontree_modelMtxFn,
};

u32 jumptable_803214DC[] = {
    (u32)(appleontree_update + 0x170),
    (u32)(appleontree_update + 0x274),
    (u32)(appleontree_update + 0x3C4),
    (u32)(appleontree_update + 0x4E8),
    (u32)(appleontree_update + 0x554),
    (u32)(appleontree_update + 0x6C8),
    (u32)(appleontree_update + 0x71C),
};

/* appleontree extra block (size 0x64 = appleontree_getExtraSize). */
typedef struct AppleOnTreeState {
    u8 unk00[8];
    f32 unk08;
    f32 unk0C;
    u8 unk10[0x24 - 0x10];
    f32 unk24;
    f32 unk28;
    f32 unk2C;
    f32 unk30;
    f32 unk34;
    u16 unk38;
    u8 unk3A;
    u8 pad3B;
    f32 unk3C;
    f32 unk40;
    f32 unk44;
    s16 unk48;
    s16 unk4A;
    s16 unk4C;
    u8 pad4E[2];
    f32 unk50;
    u8 pad54[6];
    u8 unk5A;
    u8 pad5B;
    s16 unk5C;
    s16 unk5E;
    f32 unk60;
} AppleOnTreeState;

STATIC_ASSERT(offsetof(AppleOnTreeState, unk38) == 0x38);
STATIC_ASSERT(offsetof(AppleOnTreeState, unk50) == 0x50);
STATIC_ASSERT(offsetof(AppleOnTreeState, unk60) == 0x60);
STATIC_ASSERT(sizeof(AppleOnTreeState) == 0x64);

/*
 * --INFO--
 *
 * Function: appleontree_func0B
 * EN v1.0 Address: 0x8017DAA0
 * EN v1.0 Size: 160b
 * EN v1.1 Address: 0x8017DCBC
 * EN v1.1 Size: 240b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void appleontree_func0B(int obj, float *pos)
{
  AppleOnTreeState *state = ((GameObject *)obj)->extra;

  if (state->unk3A == 4) {
    return;
  }
  if (state->unk3A == 5) {
    return;
  }
  if (state->unk3A == 6) {
    return;
  }
  ((GameObject *)obj)->anim.localPosX = pos[0];
  ((GameObject *)obj)->anim.localPosY = pos[1];
  ((GameObject *)obj)->anim.localPosZ = pos[2];
}

/*
 * --INFO--
 *
 * Function: FUN_8017db40
 * EN v1.0 Address: 0x8017DB40
 * EN v1.0 Size: 792b
 * EN v1.1 Address: 0x8017DDAC
 * EN v1.1 Size: 668b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on
void FUN_8017db40(uint param_1,int param_2)
{
  undefined2 uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  undefined8 in_f4;
  double dVar8;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  
  iVar4 = *(int *)&((GameObject *)param_1)->extra;
  if (param_2 == 1) {
    uVar1 = 2;
  }
  else {
    if (param_2 < 1) {
      if (-1 < param_2) {
        uVar1 = 2;
        goto LAB_8017de10;
      }
    }
    else if (param_2 < 3) {
      uVar1 = 2;
      goto LAB_8017de10;
    }
    uVar1 = 0;
  }
LAB_8017de10:
  *(undefined2 *)(iVar4 + 0x38) = uVar1;
  *(undefined *)(iVar4 + 0x3a) = 4;
  *(float *)&((GroundAnimatorState *)iVar4)->linkedObj = lbl_803DC074;
  ((GroundAnimatorState *)iVar4)->sinkDepth = lbl_803DC074;
  uVar2 = randomGetRange(0xffff8000,0x7fff);
  *(short *)(iVar4 + 0x48) = (short)uVar2;
  uVar2 = randomGetRange(0xffff8000,0x7fff);
  *(short *)(iVar4 + 0x4a) = (short)uVar2;
  *(undefined2 *)(iVar4 + 0x4c) = 0x2000;
  dVar5 = (double)((GameObject *)param_1)->anim.localPosX;
  dVar6 = (double)((GameObject *)param_1)->anim.localPosY;
  dVar7 = (double)((GameObject *)param_1)->anim.localPosZ;
  iVar3 = FUN_800632d8(dVar5,dVar6,dVar7,param_1,(float *)(iVar4 + 0x30),0);
  if (iVar3 == 0) {
    iVar4 = *(int *)&((GameObject *)param_1)->extra;
    if ((*(ushort *)&((GameObject *)param_1)->anim.flags & 0x2000) == 0) {
      if (*(int *)&((GameObject *)param_1)->anim.hitReactState != 0) {
        ObjHits_DisableObject(param_1);
      }
      *(byte *)(iVar4 + 0x5a) = *(byte *)(iVar4 + 0x5a) | 2;
    }
    else {
      FUN_80017ac8(dVar5,dVar6,dVar7,in_f4,in_f5,in_f6,in_f7,in_f8,param_1);
    }
  }
  else {
    dVar5 = (double)*(float *)(iVar4 + 0x40);
    dVar6 = FUN_80293900(-(double)((float)((double)lbl_803E4470 * dVar5) *
                                   *(float *)(iVar4 + 0x30) - lbl_803E446C));
    dVar7 = (double)(float)((double)lbl_803E4474 * dVar5);
    dVar5 = dVar7;
    if (dVar7 < (double)lbl_803E446C) {
      dVar5 = -dVar7;
    }
    if ((double)lbl_803E4478 < dVar5) {
      dVar8 = (double)(float)((double)(float)((double)lbl_803E447C - dVar6) / dVar7);
      dVar5 = (double)(float)((double)(float)((double)lbl_803E447C + dVar6) / dVar7);
      if ((double)lbl_803E446C < dVar8) {
        dVar5 = dVar8;
      }
    }
    else {
      dVar5 = (double)lbl_803E4460;
    }
    *(float *)(iVar4 + 0x50) = (float)dVar5;
    if (lbl_803E446C <= *(float *)(iVar4 + 0x28)) {
      dVar6 = (double)lbl_803E4480;
      *(float *)(iVar4 + 0x30) =
           (float)(dVar6 * (double)(lbl_803E4470 * *(float *)(iVar4 + 0x24)) +
                  (double)*(float *)(iVar4 + 0x30));
    }
    else {
      dVar6 = (double)lbl_803E4470;
      *(float *)(iVar4 + 0x30) =
           -(float)(dVar6 * (double)*(float *)(iVar4 + 0x24) - (double)*(float *)(iVar4 + 0x30));
    }
    if ((double)lbl_803E446C < (double)*(float *)(iVar4 + 0x30)) {
      *(undefined4 *)(iVar4 + 0x2c) = *(undefined4 *)(param_1 + 0x10);
      *(float *)(iVar4 + 0x34) = ((GameObject *)param_1)->anim.localPosY - *(float *)(iVar4 + 0x30);
      if (*(int *)&((GameObject *)param_1)->anim.hitReactState != 0) {
        ObjHits_DisableObject(param_1);
      }
      FUN_80006824(param_1,SFXen_bridge_stops);
    }
    else {
      iVar3 = *(int *)&((GameObject *)param_1)->extra;
      if ((*(ushort *)&((GameObject *)param_1)->anim.flags & 0x2000) == 0) {
        if (*(int *)&((GameObject *)param_1)->anim.hitReactState != 0) {
          ObjHits_DisableObject(param_1);
        }
        *(byte *)(iVar3 + 0x5a) = *(byte *)(iVar3 + 0x5a) | 2;
      }
      else {
        FUN_80017ac8((double)*(float *)(iVar4 + 0x30),dVar6,dVar7,dVar5,in_f5,in_f6,in_f7,in_f8,
                     param_1);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017de58
 * EN v1.0 Address: 0x8017DE58
 * EN v1.0 Size: 672b
 * EN v1.1 Address: 0x8017E048
 * EN v1.1 Size: 380b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017de58(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)
{
  int iVar1;
  uint uVar2;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar3;
  double dVar4;
  undefined8 uVar5;
  
  iVar3 = *(int *)&((GameObject *)param_9)->extra;
  iVar1 = FUN_80017a98();
  dVar4 = (double)FUN_80017710((float *)(iVar1 + 0x18),(float *)(param_9 + 0x18));
  if ((dVar4 < (double)lbl_803E4484) &&
     (dVar4 = (double)FUN_8001771c((float *)(iVar1 + 0x18),(float *)(param_9 + 0x18)),
     dVar4 < (double)lbl_803E4488)) {
    uVar2 = GameBit_Get(0x90f);
    if (uVar2 == 0) {
      uVar5 = (*gObjectTriggerInterface)->setObjects(0x444,0,0);
      *(undefined2 *)(iVar3 + 0x5c) = 0xffff;
      *(undefined2 *)(iVar3 + 0x5e) = 0;
      *(float *)(iVar3 + 0x60) = lbl_803E4460;
      ObjMsg_SendToObject(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,0x7000a,
                   param_9,iVar3 + 0x5c,in_r7,in_r8,in_r9,in_r10);
      GameBit_Set(0x90f,1);
      *(byte *)(iVar3 + 0x5a) = *(byte *)(iVar3 + 0x5a) | 4;
    }
    else {
      FUN_80294d60(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,
                   (uint)*(ushort *)(iVar3 + 0x38));
      FUN_80081118((double)lbl_803E4460,param_9,0xff,0x28);
      uVar5 = FUN_80006824(param_9,SFXen_waterblock_stop);
      iVar1 = *(int *)&((GameObject *)param_9)->extra;
      if ((*(ushort *)&((GameObject *)param_9)->anim.flags & 0x2000) == 0) {
        if (*(int *)&((GameObject *)param_9)->anim.hitReactState != 0) {
          ObjHits_DisableObject(param_9);
        }
        *(byte *)(iVar1 + 0x5a) = *(byte *)(iVar1 + 0x5a) | 2;
      }
      else {
        FUN_80017ac8(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
      }
    }
  }
  return;
}

/* appleontree_handleCollectableHit: ground-animator collectable hit handler. When player is in
 * range, either send a trigger event (first contact) or apply healing +
 * particle FX + sfx + free-or-disable. */
extern f32 Vec_xzDistance(float *a, float *b);
extern void playerAddHealth(int player, u16 amount);
extern void itemPickupDoParticleFx(int obj, f32 scale, int p3, int p4);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void Obj_FreeObject(int obj);
extern f32 lbl_803E37C8;
extern f32 lbl_803E37EC;
extern f32 lbl_803E37F0;
#pragma scheduling off
#pragma peephole off
void appleontree_handleCollectableHit(int obj)
{
    int state = *(int *)&((GameObject *)obj)->extra;
    int player = Obj_GetPlayerObject();

    if (!(Vec_xzDistance((float *)(player + 0x18), (float *)(obj + 0x18)) < lbl_803E37EC)) return;
    if (!(Vec_distance((float *)(player + 0x18), (float *)(obj + 0x18)) < lbl_803E37F0)) return;

    if (GameBit_Get(0x90f) == 0) {
        (*gObjectTriggerInterface)->setObjects(0x444, 0, 0);
        ((AppleOnTreeState *)state)->unk5C = -1;
        ((AppleOnTreeState *)state)->unk5E = 0;
        ((AppleOnTreeState *)state)->unk60 = lbl_803E37C8;
        ObjMsg_SendToObject(player, 0x7000a, obj, (int *)(state + 0x5c));
        GameBit_Set(0x90f, 1);
        ((AppleOnTreeState *)state)->unk5A = (u8)(((AppleOnTreeState *)state)->unk5A | 4);
    } else {
        playerAddHealth(player, ((AppleOnTreeState *)state)->unk38);
        itemPickupDoParticleFx(obj, lbl_803E37C8, 0xff, 0x28);
        Sfx_PlayFromObject(obj, SFXen_waterblock_stop);
        state = *(int *)&((GameObject *)obj)->extra;
        if ((((GameObject *)obj)->anim.flags & 0x2000) != 0) {
            Obj_FreeObject(obj);
        } else {
            if (((GameObject *)obj)->anim.hitReactState != NULL) {
                ObjHits_DisableObject(obj);
            }
            ((AppleOnTreeState *)state)->unk5A = (u8)(((AppleOnTreeState *)state)->unk5A | 2);
        }
    }
}


/*
 * --INFO--
 *
 * Function: FUN_8017e12c
 * EN v1.0 Address: 0x8017E12C
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x8017E1F4
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_8017e15c
 * EN v1.0 Address: 0x8017E15C
 * EN v1.0 Size: 612b
 * EN v1.1 Address: 0x8017E22C
 * EN v1.1 Size: 608b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8017e15c(double param_1,undefined2 *param_2,int param_3)
{
  float fVar1;
  float fVar2;
  float fVar3;
  undefined4 uVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  
  fVar1 = lbl_803E446C;
  dVar5 = (double)lbl_803E446C;
  dVar6 = (double)*(float *)(param_3 + 0x40);
  if (dVar5 == dVar6) {
    uVar4 = 1;
  }
  else {
    fVar2 = *(float *)(param_3 + 0x30);
    if (dVar5 <= (double)(fVar2 - (float)((double)*(float *)(param_3 + 0x2c) - param_1))) {
      *(float *)(param_2 + 8) = (float)param_1;
      uVar4 = 1;
    }
    else {
      dVar7 = (double)*(float *)(param_3 + 0x44);
      if (dVar5 == dVar7) {
        dVar5 = FUN_80293900((double)(float)(dVar7 * dVar7 -
                                            (double)((float)((double)lbl_803E4470 * dVar6) * fVar2
                                                    )));
        fVar1 = (float)((double)lbl_803E4474 * dVar6);
        fVar2 = fVar1;
        if (fVar1 < lbl_803E446C) {
          fVar2 = -fVar1;
        }
        fVar3 = lbl_803E4460;
        if (lbl_803E4478 < fVar2) {
          fVar2 = (float)(-dVar7 - dVar5) / fVar1;
          fVar3 = (float)(-dVar7 + dVar5) / fVar1;
          if (lbl_803E446C < fVar2) {
            fVar3 = fVar2;
          }
        }
        *(float *)(param_3 + 0xc) = *(float *)(param_3 + 0xc) - fVar3;
        *(float *)(param_3 + 0x2c) = *(float *)(param_3 + 0x2c) - *(float *)(param_3 + 0x30);
        *(float *)(param_3 + 0x30) = lbl_803E446C;
        *(undefined4 *)(param_2 + 8) = *(undefined4 *)(param_3 + 0x2c);
        *param_2 = *(undefined2 *)(param_3 + 0x48);
        param_2[1] = *(undefined2 *)(param_3 + 0x4a);
        param_2[2] = *(undefined2 *)(param_3 + 0x4c);
        *(float *)(param_3 + 0x44) = -*(float *)(param_3 + 0x28);
        if ((*(byte *)(param_3 + 0x5a) & 8) == 0) {
          FUN_80006824((uint)param_2,0x407);
          *(byte *)(param_3 + 0x5a) = *(byte *)(param_3 + 0x5a) | 8;
        }
        uVar4 = 1;
      }
      else if ((double)lbl_803E448C <= dVar7) {
        dVar6 = (double)(float)(dVar6 + (double)*(float *)(param_3 + 0x3c));
        dVar5 = FUN_80293900((double)(float)(dVar7 * dVar7 -
                                            (double)((float)((double)lbl_803E4470 * dVar6) * fVar2
                                                    )));
        fVar1 = (float)((double)lbl_803E4474 * dVar6);
        fVar2 = fVar1;
        if (fVar1 < lbl_803E446C) {
          fVar2 = -fVar1;
        }
        fVar3 = lbl_803E4460;
        if (lbl_803E4478 < fVar2) {
          fVar2 = (float)(-dVar7 - dVar5) / fVar1;
          fVar3 = (float)(-dVar7 + dVar5) / fVar1;
          if (lbl_803E446C < fVar2) {
            fVar3 = fVar2;
          }
        }
        *(float *)(param_3 + 0xc) = *(float *)(param_3 + 0xc) - fVar3;
        *(undefined4 *)(param_2 + 8) = *(undefined4 *)(param_3 + 0x2c);
        *(float *)(param_3 + 0x44) = *(float *)(param_3 + 0x44) * lbl_803E4490;
        uVar4 = 0;
      }
      else {
        *(float *)(param_2 + 8) = *(float *)(param_3 + 0x2c);
        *(float *)(param_3 + 0x40) = fVar1;
        *(float *)(param_3 + 0x44) = fVar1;
        uVar4 = 1;
      }
    }
  }
  return uVar4;
}

/*
 * --INFO--
 *
 * Function: FUN_8017e3c0
 * EN v1.0 Address: 0x8017E3C0
 * EN v1.0 Size: 624b
 * EN v1.1 Address: 0x8017E48C
 * EN v1.1 Size: 620b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8017e3c0(double param_1,undefined2 *param_2,int param_3)
{
  float fVar1;
  float fVar2;
  float fVar3;
  undefined4 uVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  
  if (lbl_803E446C == *(float *)(param_3 + 0x3c)) {
    if (lbl_803E446C <
        *(float *)(param_3 + 0x30) - (float)((double)*(float *)(param_3 + 0x2c) - param_1)) {
      *(float *)(param_2 + 8) = (float)param_1;
      uVar4 = 1;
    }
    else {
      dVar6 = (double)*(float *)(param_3 + 0x40);
      dVar7 = (double)*(float *)(param_3 + 0x44);
      dVar5 = FUN_80293900((double)(float)(dVar7 * dVar7 -
                                          (double)((float)((double)lbl_803E4470 * dVar6) *
                                                  *(float *)(param_3 + 0x30))));
      fVar1 = (float)((double)lbl_803E4474 * dVar6);
      fVar2 = fVar1;
      if (fVar1 < lbl_803E446C) {
        fVar2 = -fVar1;
      }
      fVar3 = lbl_803E4460;
      if (lbl_803E4478 < fVar2) {
        fVar2 = (float)(-dVar7 - dVar5) / fVar1;
        fVar3 = (float)(-dVar7 + dVar5) / fVar1;
        if (lbl_803E446C < fVar2) {
          fVar3 = fVar2;
        }
      }
      *(float *)(param_3 + 0xc) = *(float *)(param_3 + 0xc) - fVar3;
      *(float *)(param_3 + 0x2c) = *(float *)(param_3 + 0x2c) - *(float *)(param_3 + 0x30);
      *(float *)(param_3 + 0x30) = lbl_803E446C;
      *(undefined4 *)(param_2 + 8) = *(undefined4 *)(param_3 + 0x2c);
      *param_2 = *(undefined2 *)(param_3 + 0x48);
      param_2[1] = *(undefined2 *)(param_3 + 0x4a);
      param_2[2] = *(undefined2 *)(param_3 + 0x4c);
      *(float *)(param_3 + 0x44) =
           lbl_803E4474 * *(float *)(param_3 + 0x40) * fVar3 + *(float *)(param_3 + 0x44);
      *(undefined4 *)(param_3 + 0x3c) = *(undefined4 *)(param_3 + 0x28);
      (**(code **)(*DAT_803dd718 + 0x10))
                ((double)*(float *)(param_2 + 6),(double)*(float *)(param_3 + 0x34),
                 (double)*(float *)(param_2 + 10),param_2);
      uVar4 = 0;
    }
  }
  else if ((float)(param_1 - (double)*(float *)(param_3 + 0x2c)) < lbl_803E446C) {
    *(float *)(param_2 + 8) = (float)param_1;
    uVar4 = 1;
  }
  else {
    dVar7 = (double)(*(float *)(param_3 + 0x40) + *(float *)(param_3 + 0x3c));
    dVar6 = (double)*(float *)(param_3 + 0x44);
    dVar5 = FUN_80293900((double)(float)(dVar6 * dVar6 -
                                        (double)((float)((double)lbl_803E4470 * dVar7) *
                                                *(float *)(param_3 + 0x30))));
    fVar1 = (float)((double)lbl_803E4474 * dVar7);
    fVar2 = fVar1;
    if (fVar1 < lbl_803E446C) {
      fVar2 = -fVar1;
    }
    fVar3 = lbl_803E4460;
    if (lbl_803E4478 < fVar2) {
      fVar2 = (float)(-dVar6 - dVar5) / fVar1;
      fVar3 = (float)(-dVar6 + dVar5) / fVar1;
      if (lbl_803E446C < fVar2) {
        fVar3 = fVar2;
      }
    }
    *(float *)(param_3 + 0xc) = *(float *)(param_3 + 0xc) - fVar3;
    *(undefined4 *)(param_2 + 8) = *(undefined4 *)(param_3 + 0x2c);
    *(float *)(param_3 + 0x3c) = lbl_803E4494;
    *(float *)(param_3 + 0x44) = lbl_803E4498;
    uVar4 = 0;
  }
  return uVar4;
}


/* Trivial 4b 0-arg blr leaves. */
#pragma scheduling off
#pragma peephole off
void appleontree_setScale(void) {}

/* 8b "li r3, N; blr" returners. */
int appleontree_getExtraSize(void) { return 0x64; }

/* Pattern wrappers. */
u8 appleontree_modelMtxFn(int *obj) { return ((AppleOnTreeState *)((int **)obj)[0xb8/4])->unk3A; }

void appleontree_free(int *obj) {
    (*gExpgfxInterface)->freeSource((u32)obj);
}
void appleontree_render(int obj, int p1, int p2, int p3, int p4, s8 visible) {
    AppleOnTreeState *inner = ((GameObject *)obj)->extra;
    if ((inner->unk5A & 2) == 0) {
        objRenderFn_8003b8f4(obj, p1, p2, p3, p4, lbl_803E37C8);
    }
}

/* v1.0 ground-animator drop physics (drift twins of FUN_8017db40/FUN_8017e15c/FUN_8017e3c0). */
extern f32 timeDelta;
extern f32 sqrtf(f32);
extern int fn_80065684(int obj, f32 x, f32 y, f32 z, f32 *out, int flag);
extern WaterfxInterface **gWaterfxInterface;
extern f32 lbl_803E37D4;
extern f32 lbl_803E37D8;
extern f32 lbl_803E37DC;
extern f32 lbl_803E37E0;
extern f32 lbl_803E37E4;
extern f32 lbl_803E37E8;
extern f32 lbl_803E37F4;
extern f32 lbl_803E37F8;
extern f32 lbl_803E37FC;
extern f32 lbl_803E3800;

void fn_8017D854(int obj, int msg)
{
    int state = *(int *)&((GameObject *)obj)->extra;
    int v;

    switch (msg) {
    case 0:
        v = 2;
        break;
    case 1:
        v = 2;
        break;
    case 2:
        v = 2;
        break;
    default:
        v = 0;
        break;
    }
    ((AppleOnTreeState *)state)->unk38 = (u16)v;
    ((AppleOnTreeState *)state)->unk3A = 4;
    ((AppleOnTreeState *)state)->unk08 = timeDelta;
    ((AppleOnTreeState *)state)->unk0C = timeDelta;
    ((AppleOnTreeState *)state)->unk48 = (s16)randomGetRange(-0x8000, 0x7fff);
    ((AppleOnTreeState *)state)->unk4A = (s16)randomGetRange(-0x8000, 0x7fff);
    ((AppleOnTreeState *)state)->unk4C = 0x2000;

    if (fn_80065684(obj, ((GameObject *)obj)->anim.localPosX, ((GameObject *)obj)->anim.localPosY, ((GameObject *)obj)->anim.localPosZ,
                    (f32 *)(state + 0x30), 0) == 0) {
        state = *(int *)&((GameObject *)obj)->extra;
        if ((((GameObject *)obj)->anim.flags & 0x2000) != 0) {
            Obj_FreeObject(obj);
        } else {
            if (((GameObject *)obj)->anim.hitReactState != NULL) {
                ObjHits_DisableObject(obj);
            }
            ((AppleOnTreeState *)state)->unk5A = (u8)(((AppleOnTreeState *)state)->unk5A | 2);
        }
    } else {
        f32 m = ((AppleOnTreeState *)state)->unk40;
        f32 g = lbl_803E37D8 * m;
        f32 q = sqrtf(-(g * ((AppleOnTreeState *)state)->unk30 - lbl_803E37D4));
        f32 t = lbl_803E37DC * m;
        f32 a;
        f32 r;

        if (t >= lbl_803E37D4) {
            a = t;
        } else {
            a = -t;
        }
        if (a <= lbl_803E37E0) {
            r = lbl_803E37C8;
        } else {
            f32 r1 = (lbl_803E37E4 - q) / t;
            f32 r2 = (lbl_803E37E4 + q) / t;
            r = (r1 > 0.0f) ? r1 : r2;
        }
        ((AppleOnTreeState *)state)->unk50 = r;

        if (((AppleOnTreeState *)state)->unk28 < lbl_803E37D4) {
            ((AppleOnTreeState *)state)->unk30 = -(lbl_803E37D8 * ((AppleOnTreeState *)state)->unk24 - ((AppleOnTreeState *)state)->unk30);
        } else {
            ((AppleOnTreeState *)state)->unk30 = lbl_803E37E8 * (lbl_803E37D8 * ((AppleOnTreeState *)state)->unk24) + ((AppleOnTreeState *)state)->unk30;
        }

        if (((AppleOnTreeState *)state)->unk30 <= lbl_803E37D4) {
            state = *(int *)&((GameObject *)obj)->extra;
            if ((((GameObject *)obj)->anim.flags & 0x2000) != 0) {
                Obj_FreeObject(obj);
            } else {
                if (((GameObject *)obj)->anim.hitReactState != NULL) {
                    ObjHits_DisableObject(obj);
                }
                ((AppleOnTreeState *)state)->unk5A = (u8)(((AppleOnTreeState *)state)->unk5A | 2);
            }
        } else {
            ((AppleOnTreeState *)state)->unk2C = ((GameObject *)obj)->anim.localPosY;
            ((AppleOnTreeState *)state)->unk34 = ((GameObject *)obj)->anim.localPosY - ((AppleOnTreeState *)state)->unk30;
            if (((GameObject *)obj)->anim.hitReactState != NULL) {
                ObjHits_DisableObject(obj);
            }
            Sfx_PlayFromObject(obj, SFXen_bridge_stops);
        }
    }
}

int fn_8017DCD4(int p, int state, f32 y)
{
    f32 zero = lbl_803E37D4;
    f32 m = ((AppleOnTreeState *)state)->unk40;

    if (zero != m) {
        if (((AppleOnTreeState *)state)->unk30 - (((AppleOnTreeState *)state)->unk2C - y) < zero) {
            f32 b = ((AppleOnTreeState *)state)->unk44;
            if (zero == b) {
                f32 g = lbl_803E37D8 * m;
                f32 q = sqrtf(b * b - g * ((AppleOnTreeState *)state)->unk30);
                f32 t = lbl_803E37DC * m;
                f32 a;
                f32 r;

                if (t >= lbl_803E37D4) {
                    a = t;
                } else {
                    a = -t;
                }
                if (a <= lbl_803E37E0) {
                    r = lbl_803E37C8;
                } else {
                    f32 r1 = (-b - q) / t;
                    f32 r2 = (-b + q) / t;
                    r = (r1 > 0.0f) ? r1 : r2;
                }
                ((AppleOnTreeState *)state)->unk0C = ((AppleOnTreeState *)state)->unk0C - r;
                ((AppleOnTreeState *)state)->unk2C = ((AppleOnTreeState *)state)->unk2C - ((AppleOnTreeState *)state)->unk30;
                ((AppleOnTreeState *)state)->unk30 = lbl_803E37D4;
                ((GameObject *)p)->anim.localPosY = ((AppleOnTreeState *)state)->unk2C;
                ((GameObject *)p)->anim.rotX = ((AppleOnTreeState *)state)->unk48;
                ((GameObject *)p)->anim.rotY = ((AppleOnTreeState *)state)->unk4A;
                ((GameObject *)p)->anim.rotZ = ((AppleOnTreeState *)state)->unk4C;
                ((AppleOnTreeState *)state)->unk44 = -((AppleOnTreeState *)state)->unk28;
                if ((((AppleOnTreeState *)state)->unk5A & 8) == 0) {
                    Sfx_PlayFromObject(p, 0x407);
                    ((AppleOnTreeState *)state)->unk5A = (u8)(((AppleOnTreeState *)state)->unk5A | 8);
                }
                return 1;
            } else if (b < lbl_803E37F4) {
                ((GameObject *)p)->anim.localPosY = ((AppleOnTreeState *)state)->unk2C;
                ((AppleOnTreeState *)state)->unk40 = zero;
                ((AppleOnTreeState *)state)->unk44 = zero;
                return 1;
            } else {
                f32 g;
                f32 q;
                f32 t;
                f32 a;
                f32 r;
                m = m + ((AppleOnTreeState *)state)->unk3C;
                g = lbl_803E37D8 * m;
                q = sqrtf(b * b - g * ((AppleOnTreeState *)state)->unk30);
                t = lbl_803E37DC * m;

                if (t >= lbl_803E37D4) {
                    a = t;
                } else {
                    a = -t;
                }
                if (a <= lbl_803E37E0) {
                    r = lbl_803E37C8;
                } else {
                    f32 r1 = (-b - q) / t;
                    f32 r2 = (-b + q) / t;
                    r = (r1 > 0.0f) ? r1 : r2;
                }
                ((AppleOnTreeState *)state)->unk0C = ((AppleOnTreeState *)state)->unk0C - r;
                ((GameObject *)p)->anim.localPosY = ((AppleOnTreeState *)state)->unk2C;
                ((AppleOnTreeState *)state)->unk44 = ((AppleOnTreeState *)state)->unk44 * lbl_803E37F8;
                return 0;
            }
        } else {
            ((GameObject *)p)->anim.localPosY = y;
            return 1;
        }
    }
    return 1;
}

int fn_8017DF34(int p, int state, f32 y)
{
    if (lbl_803E37D4 == ((AppleOnTreeState *)state)->unk3C) {
        if (((AppleOnTreeState *)state)->unk30 - (((AppleOnTreeState *)state)->unk2C - y) <= lbl_803E37D4) {
            f32 b;
            f32 m = ((AppleOnTreeState *)state)->unk40;
            f32 g;
            f32 q;
            f32 t;
            f32 a;
            f32 r;
            b = ((AppleOnTreeState *)state)->unk44;
            g = lbl_803E37D8 * m;
            q = sqrtf(b * b - g * ((AppleOnTreeState *)state)->unk30);
            t = lbl_803E37DC * m;

            if (t >= lbl_803E37D4) {
                a = t;
            } else {
                a = -t;
            }
            if (a <= lbl_803E37E0) {
                r = lbl_803E37C8;
            } else {
                f32 r2;
                f32 nb;
                nb = -b;
                r = (nb - q) / t;
                r2 = (nb + q) / t;
                r = (r > *(f32 *)&lbl_803E37D4) ? r : r2;
            }
            ((AppleOnTreeState *)state)->unk0C = ((AppleOnTreeState *)state)->unk0C - r;
            ((AppleOnTreeState *)state)->unk2C = ((AppleOnTreeState *)state)->unk2C - ((AppleOnTreeState *)state)->unk30;
            ((AppleOnTreeState *)state)->unk30 = lbl_803E37D4;
            ((GameObject *)p)->anim.localPosY = ((AppleOnTreeState *)state)->unk2C;
            ((GameObject *)p)->anim.rotX = ((AppleOnTreeState *)state)->unk48;
            ((GameObject *)p)->anim.rotY = ((AppleOnTreeState *)state)->unk4A;
            ((GameObject *)p)->anim.rotZ = ((AppleOnTreeState *)state)->unk4C;
            {
                f32 g2 = lbl_803E37DC * ((AppleOnTreeState *)state)->unk40;
                ((AppleOnTreeState *)state)->unk44 = g2 * r + ((AppleOnTreeState *)state)->unk44;
            }
            ((AppleOnTreeState *)state)->unk3C = ((AppleOnTreeState *)state)->unk28;
            ((WaterfxSpawnSplashBurstAtPointFn)(*gWaterfxInterface)->spawnSplashBurst)(
                (void *)p, ((GameObject *)p)->anim.localPosX, ((AppleOnTreeState *)state)->unk34,
                ((GameObject *)p)->anim.localPosZ);
            return 0;
        } else {
            ((GameObject *)p)->anim.localPosY = y;
            return 1;
        }
    } else if (y - ((AppleOnTreeState *)state)->unk2C >= lbl_803E37D4) {
        f32 b;
        f32 m = ((AppleOnTreeState *)state)->unk40 + ((AppleOnTreeState *)state)->unk3C;
        f32 g;
        f32 q;
        f32 t;
        f32 a;
        f32 r;
        b = ((AppleOnTreeState *)state)->unk44;
        g = lbl_803E37D8 * m;
        q = sqrtf(b * b - g * ((AppleOnTreeState *)state)->unk30);
        t = lbl_803E37DC * m;

        if (t >= lbl_803E37D4) {
            a = t;
        } else {
            a = -t;
        }
        if (a <= lbl_803E37E0) {
            r = lbl_803E37C8;
        } else {
            f32 r2;
            f32 nb;
            nb = -b;
            r = (nb - q) / t;
            r2 = (nb + q) / t;
            r = (r > *(f32 *)&lbl_803E37D4) ? r : r2;
        }
        ((AppleOnTreeState *)state)->unk0C = ((AppleOnTreeState *)state)->unk0C - r;
        ((GameObject *)p)->anim.localPosY = ((AppleOnTreeState *)state)->unk2C;
        ((AppleOnTreeState *)state)->unk3C = lbl_803E37FC;
        ((AppleOnTreeState *)state)->unk44 = lbl_803E3800;
        return 0;
    } else {
        ((GameObject *)p)->anim.localPosY = y;
        return 1;
    }
}
