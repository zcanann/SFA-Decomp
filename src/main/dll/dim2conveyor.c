#include "ghidra_import.h"
#include "main/dll/creator1D4.h"
#include "main/dll/dim2conveyor.h"
#include "main/dll/ped.h"
#include "main/objHitReact.h"
#include "main/objanim.h"

extern undefined4 FUN_80017680();
extern double FUN_80017714();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017a6c();
extern undefined4 FUN_80017a98();
extern int FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 ObjGroup_AddObject();
extern undefined8 ObjGroup_RemoveObject();
extern int ObjTrigger_IsSetById();
extern int ObjTrigger_IsSet();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 FUN_8003a1c4();
extern undefined4 FUN_8003b280();
extern undefined4 FUN_8003b818();
extern undefined4 objAudioFn_8006ef38();
extern int FUN_8012efc4();
extern undefined4 FUN_801ce340();
extern int FUN_801ce424();
extern undefined4 FUN_801ce638();

extern void *Obj_GetPlayerObject(void);
extern f32 vec3f_distanceSquared(f32 *p1, f32 *p2);
extern void fn_8003A168(int obj, void *p);
extern void characterDoEyeAnims(int obj, void *p);
extern int cMenuGetSelectedItem(void);
extern void fn_8002B6D8(int obj, int p2, int p3, int p4, int p5, int p6);
extern void fn_801CDF94(int obj, void *state, int flag);
extern void fn_801CEE0C(int obj, void *state, void *objDef);
extern void fn_801CED2C(int obj, void *state, void *objDef);
extern void fn_801CEA14(int obj, void *state, void *objDef);
extern void fn_801CE2BC(int obj, void *state, void *objDef);
extern u32 GameBit_Get(int eventId);
extern int* getTrickyObject(void);
extern void Sfx_StopObjectChannel(int *p1, int channel);

extern u8 lbl_803267C0[];
extern u8 lbl_803267E8[];
extern u8 lbl_80326818[];
extern ObjHitReactEntry DAT_80327400;
extern ObjHitReactEntry DAT_80327414;
extern undefined4 DAT_80327468;
extern undefined4 DAT_80327498;
extern undefined4 DAT_803274f4;
extern undefined4 DAT_803dcbd8;
extern undefined4 DAT_803dcbdc;
extern undefined4 DAT_803dcbe0;
extern undefined4 DAT_803dcbe4;
extern undefined4 DAT_803dcc1c;
extern undefined4 DAT_803dcc20;
extern undefined4 DAT_803dcc24;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd728;
extern void *gGameUIInterface;
extern void *gObjectTriggerInterface;
extern void *gPathControlInterface;
extern void *gRomCurveInterface;
extern f32 timeDelta;
extern f32 lbl_803DC074;
extern u32 lbl_803E5208;
extern f32 lbl_803E520C;
extern f32 lbl_803E5210;
extern f32 lbl_803E524C;
extern f32 lbl_803E5254;
extern f32 lbl_803E5258;
extern f32 lbl_803E5EA4;
extern f32 lbl_803E5EA8;

#define gNwMammothNormalHitReactEntry DAT_80327400
#define gNwMammothHeavyHitReactEntry DAT_80327414
#define gNwMammothStateMoveIds DAT_80327468
#define gNwMammothStateMoveStepScales DAT_80327498
#define gNwMammothStateFlags DAT_803274f4

#define NW_MAMMOTH_STATE_FLAGS(table) ((u8 *)((table) + 0xf4))
#define NW_MAMMOTH_MOVE_IDS(table) ((s16 *)((table) + 0x68))
#define NW_MAMMOTH_MOVE_STEP_SCALES(table) ((f32 *)((table) + 0x98))

enum NwMammothStateFlag {
  NW_MAMMOTH_STATE_FLAG_PATH_CONTROL = 0x01,
  NW_MAMMOTH_STATE_FLAG_HEAVY_HIT_REACT = 0x02,
  NW_MAMMOTH_STATE_FLAG_TRIGGER_REFRESH = 0x04,
  NW_MAMMOTH_STATE_FLAG_SKIP_HIT_REACT = 0x08,
  NW_MAMMOTH_STATE_FLAG_MENU_ACTION = 0x10,
  NW_MAMMOTH_STATE_FLAG_SOLID = 0x20,
};

enum NwMammothRuntimeFlag {
  NW_MAMMOTH_RUNTIME_PATH_CONTROL = 0x01,
  NW_MAMMOTH_RUNTIME_ANIM_ENDED = 0x02,
  NW_MAMMOTH_RUNTIME_TRIGGER_REFRESH = 0x04,
  NW_MAMMOTH_RUNTIME_MENU_LOCK = 0x10,
  NW_MAMMOTH_RUNTIME_RESET_PATH = 0x20,
  NW_MAMMOTH_RUNTIME_UI_MESSAGE = 0x40,
};

/*
 * --INFO--
 *
 * Function: nw_mammoth_update
 * EN v1.0 Address: 0x801CF0AC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801CF2E0
 * EN v1.1 Size: 224b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void nw_mammoth_update(int obj,int param_2)
{
  u8 *table;
  u8 *state;
  u8 *objDef;
  u8 stateIndex;
  u8 stateFlags;
  ObjHitReactEntry *hitReactEntries;
  int currentMove;
  f32 stepScale;
  int triggerIndex;

  (void)param_2;
  table = lbl_803267C0;
  state = *(u8 **)(obj + 0xb8);
  objDef = *(u8 **)(obj + 0x4c);
  if ((state[0x43c] & NW_MAMMOTH_RUNTIME_RESET_PATH) != 0) {
    state[0x43c] = (u8)(state[0x43c] & ~NW_MAMMOTH_RUNTIME_RESET_PATH);
  }
  *(void **)(state + 0x28) = Obj_GetPlayerObject();
  if (*(void **)(state + 0x28) == NULL) {
    return;
  }
  stateIndex = state[0x408];
  stateFlags = NW_MAMMOTH_STATE_FLAGS(table)[stateIndex];
  if ((stateFlags & NW_MAMMOTH_STATE_FLAG_SOLID) != 0) {
    *(u16 *)(obj + 0xb0) = (u16)(*(u16 *)(obj + 0xb0) | 0x400);
    *(u32 *)(*(int *)(obj + 0x64) + 0x30) =
        *(u32 *)(*(int *)(obj + 0x64) + 0x30) & ~0x4;
  } else {
    *(u16 *)(obj + 0xb0) = (u16)(*(u16 *)(obj + 0xb0) & ~0x400);
    *(u32 *)(*(int *)(obj + 0x64) + 0x30) =
        *(u32 *)(*(int *)(obj + 0x64) + 0x30) | 0x4;
  }
  stateFlags = NW_MAMMOTH_STATE_FLAGS(table)[state[0x408]];
  if ((stateFlags & NW_MAMMOTH_STATE_FLAG_SKIP_HIT_REACT) == 0) {
    if ((stateFlags & NW_MAMMOTH_STATE_FLAG_HEAVY_HIT_REACT) != 0) {
      hitReactEntries = (ObjHitReactEntry *)(table + 0x14);
    } else {
      hitReactEntries = (ObjHitReactEntry *)table;
    }
    state[0x3d4] = objHitReact_update(obj, hitReactEntries, 1, state[0x3d4], (float *)(state + 0x50));
    if (state[0x3d4] != 0) {
      fn_8003A168(obj, state + 0x40c);
      characterDoEyeAnims(obj, state + 0x40c);
      return;
    }
  }
  *(f32 *)(state + 0x18) = vec3f_distanceSquared((f32 *)(obj + 0x18),
                                                 (f32 *)(*(int *)(state + 0x28) + 0x18));
  switch ((s8)objDef[0x1d]) {
    case 0:
      fn_801CEE0C(obj, state, objDef);
      break;
    case 2:
      fn_801CED2C(obj, state, objDef);
      break;
    case 1:
    case 3:
      fn_801CEA14(obj, state, objDef);
      break;
    case 4:
      fn_801CE2BC(obj, state, objDef);
      break;
  }
  stateFlags = NW_MAMMOTH_STATE_FLAGS(table)[state[0x408]];
  if ((stateFlags & NW_MAMMOTH_STATE_FLAG_PATH_CONTROL) != 0) {
    *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) | 0x10);
  } else {
    *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) & ~0x10);
    if (((stateFlags & NW_MAMMOTH_STATE_FLAG_MENU_ACTION) != 0) &&
        (cMenuGetSelectedItem() != -1)) {
      fn_8002B6D8(obj, 0, 0, 0, 0, 4);
    } else {
      fn_8002B6D8(obj, 0, 0, 0, 0, 2);
    }
  }
  stateIndex = state[0x408];
  currentMove = NW_MAMMOTH_MOVE_IDS(table)[stateIndex];
  if (*(s16 *)(obj + 0xa0) != currentMove) {
    stepScale = NW_MAMMOTH_MOVE_STEP_SCALES(table)[stateIndex];
    if (stepScale > lbl_803E520C) {
      ObjAnim_SetCurrentMove(obj, currentMove, lbl_803E520C, 0);
    } else {
      ObjAnim_SetCurrentMove(obj, currentMove, lbl_803E5210, 0);
    }
    *(f32 *)(state + 0x4c) = NW_MAMMOTH_MOVE_STEP_SCALES(table)[state[0x408]];
  }
  if (ObjAnim_AdvanceCurrentMove(*(f32 *)(state + 0x4c), timeDelta, obj,
                                 (ObjAnimEventList *)(state + 0x440)) != 0) {
    state[0x43c] = (u8)(state[0x43c] | NW_MAMMOTH_RUNTIME_ANIM_ENDED);
  } else {
    state[0x43c] = (u8)(state[0x43c] & ~NW_MAMMOTH_RUNTIME_ANIM_ENDED);
  }
  objAudioFn_8006ef38(obj, state + 0x440, 8, state + 0x45c, state + 0x16c,
                      lbl_803E5210, lbl_803E5210);
  fn_801CDF94(obj, state, NW_MAMMOTH_STATE_FLAGS(table)[state[0x408]] & 4);
  state[0x43c] = (u8)(state[0x43c] & ~NW_MAMMOTH_RUNTIME_TRIGGER_REFRESH);
  if (((state[0x43c] & NW_MAMMOTH_RUNTIME_MENU_LOCK) == 0) && (ObjTrigger_IsSet(obj) != 0)) {
    triggerIndex = randomGetRange(1, **(u8 **)(state + 0x48));
    state[0x43c] = (u8)(state[0x43c] | NW_MAMMOTH_RUNTIME_TRIGGER_REFRESH);
    (*(void (**)(int, int, int))(*(int *)gObjectTriggerInterface + 0x48))(
        *(u8 *)(*(int *)(state + 0x48) + triggerIndex), obj, -1);
  }
  if ((state[0x43c] & NW_MAMMOTH_RUNTIME_PATH_CONTROL) != 0) {
    (*(void (**)(int, void *, f32))(*(int *)gPathControlInterface + 0x10))(
        obj, state + 0x16c, timeDelta);
    (*(void (**)(int, void *))(*(int *)gPathControlInterface + 0x14))(obj, state + 0x16c);
    (*(void (**)(int, void *, f32))(*(int *)gPathControlInterface + 0x18))(
        obj, state + 0x16c, timeDelta);
  }
}

/*
 * --INFO--
 *
 * Function: nw_mammoth_init
 * EN v1.0 Address: 0x801CF4F0
 * EN v1.0 Size: 668b
 */
void nw_mammoth_init(int obj, u8 *objDef, int isReload)
{
  u32 pathParam;
  u8 *state;
  int curveParam;

  state = *(u8 **)(obj + 0xb8);
  pathParam = lbl_803E5208;
  *(s16 *)obj = (s16)((s8)objDef[0x1c] << 8);
  *(void **)(obj + 0xbc) = nw_mammoth_SeqFn;
  if (isReload != 0) {
    return;
  }
  *(f32 *)(state + 0x4c) = lbl_803E5258;
  switch ((s8)objDef[0x1d]) {
    case 0:
      state[0x43c] = (u8)(state[0x43c] | NW_MAMMOTH_RUNTIME_PATH_CONTROL);
      break;
    case 2:
      state[0x43c] = (u8)(state[0x43c] | NW_MAMMOTH_RUNTIME_PATH_CONTROL);
      if (GameBit_Get(0x19f) != 0) {
        state[0x408] = 6;
      } else if (GameBit_Get(0x19d) != 0) {
        state[0x408] = 5;
      } else {
        state[0x408] = 4;
      }
      break;
    case 1:
    case 3:
      curveParam = 0x19;
      state[0x43c] = (u8)(state[0x43c] | NW_MAMMOTH_RUNTIME_PATH_CONTROL);
      if ((u8)(*(int (*)(void *, int, f32, void *, int))(*(int *)gRomCurveInterface + 0x8c))(
              state + 0x5c, obj, lbl_803E5254, &curveParam, -1) == 0) {
        *(f32 *)(obj + 0xc) = *(f32 *)(state + 0xc4);
        *(f32 *)(obj + 0x14) = *(f32 *)(state + 0xcc);
        state[0x408] = 8;
        *(f32 *)(state + 0x54) = lbl_803E524C;
      }
      break;
    case 4:
      state[0x43f] = (s8)GameBit_Get(0x48b);
      if (GameBit_Get(0x102) != 0) {
        state[0x408] = 0x10;
      } else if (GameBit_Get(0xce1) != 0) {
        state[0x408] = 0xc;
        if ((s8)state[0x43f] >= 3) {
          (*(void (**)(int, int))(*(int *)gGameUIInterface + 0x58))(0xc8, 0x5d0);
          state[0x43c] = (u8)(state[0x43c] | NW_MAMMOTH_RUNTIME_UI_MESSAGE);
          state[0x408] = 0x11;
        }
      } else {
        state[0x408] = 9;
      }
      break;
  }
  if ((state[0x43c] & NW_MAMMOTH_RUNTIME_PATH_CONTROL) != 0) {
    u8 *pathState = state + 0x16c;
    (*(void (**)(void *, int, int, int))(*(int *)gPathControlInterface + 0x4))(
        pathState, 3, 2, 1);
    (*(void (**)(void *, int, u8 *, u8 *, u32 *))(*(int *)gPathControlInterface + 0xc))(
        pathState, 4, lbl_803267E8, lbl_80326818, &pathParam);
    (*(void (**)(int, void *))(*(int *)gPathControlInterface + 0x20))(obj, pathState);
  }
  ObjGroup_AddObject(obj, 0x4d);
}

/*
 * --INFO--
 *
 * Function: FUN_801cf0b0
 * EN v1.0 Address: 0x801CF0B0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801CF3C0
 * EN v1.1 Size: 432b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801cf0b0(uint param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801cf0b4
 * EN v1.0 Address: 0x801CF0B4
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x801CF570
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801cf0b4(int param_1)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  ObjGroup_RemoveObject(param_1,0x4d);
  if ((*(byte *)(iVar1 + 0x43c) & 0x40) != 0) {
    (**(code **)(*DAT_803dd6e8 + 100))();
  }
  return;
}

/*
 * --INFO--
 *
 * Function: nw_tricky_getExtraSize
 * EN v1.0 Address: 0x801CF7B8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int nw_tricky_getExtraSize(void)
{
  return 8;
}

/*
 * --INFO--
 *
 * Function: fn_801CF78C
 * EN v1.0 Address: 0x801CF78C
 * EN v1.0 Size: 44b
 */
#pragma peephole off
#pragma scheduling off
int fn_801CF78C(void)
{
    Sfx_StopObjectChannel(getTrickyObject(), 16);
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: FUN_801cf108
 * EN v1.0 Address: 0x801CF108
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x801CF5C4
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801cf108(int param_1)
{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  FUN_8003b818(param_1);
  iVar2 = 0;
  iVar3 = iVar1;
  do {
    ObjPath_GetPointWorldPosition(param_1,iVar2,(float *)(iVar3 + 0x45c),(undefined4 *)(iVar3 + 0x460),
                 (float *)(iVar3 + 0x464),0);
    iVar3 = iVar3 + 0xc;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 4);
  ObjPath_GetPointWorldPosition(param_1,4,(float *)(iVar1 + 0xc),(undefined4 *)(iVar1 + 0x10),(float *)(iVar1 + 0x14)
               ,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801cf1a0
 * EN v1.0 Address: 0x801CF1A0
 * EN v1.0 Size: 1436b
 * EN v1.1 Address: 0x801CF660
 * EN v1.1 Size: 1120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801cf1a0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)
{
  char cVar1;
  undefined4 uVar2;
  undefined uVar3;
  uint uVar4;
  float *in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar5;
  int iVar6;
  ObjHitReactEntry *hitReactEntries;
  double dVar8;
  
  hitReactEntries = &gNwMammothNormalHitReactEntry;
  iVar6 = *(int *)(param_9 + 0x5c);
  iVar5 = *(int *)(param_9 + 0x26);
  if ((*(byte *)(iVar6 + 0x43c) & 0x20) != 0) {
    param_1 = (**(code **)(*DAT_803dd728 + 0x20))(param_9,iVar6 + 0x16c);
    *(byte *)(iVar6 + 0x43c) = *(byte *)(iVar6 + 0x43c) & 0xdf;
  }
  uVar2 = FUN_80017a98();
  *(undefined4 *)(iVar6 + 0x28) = uVar2;
  if (*(int *)(iVar6 + 0x28) == 0) {
    return;
  }
  if (((&gNwMammothStateFlags)[*(byte *)(iVar6 + 0x408)] & 0x20) == 0) {
    param_9[0x58] = param_9[0x58] & 0xfbff;
    *(uint *)(*(int *)(param_9 + 0x32) + 0x30) = *(uint *)(*(int *)(param_9 + 0x32) + 0x30) | 4;
  }
  else {
    param_9[0x58] = param_9[0x58] | 0x400;
    *(uint *)(*(int *)(param_9 + 0x32) + 0x30) =
         *(uint *)(*(int *)(param_9 + 0x32) + 0x30) & 0xfffffffb;
  }
  if (((&gNwMammothStateFlags)[*(byte *)(iVar6 + 0x408)] & 8) == 0) {
    if (((&gNwMammothStateFlags)[*(byte *)(iVar6 + 0x408)] & 2) != 0) {
      hitReactEntries = &gNwMammothHeavyHitReactEntry;
    }
    in_r7 = (float *)(iVar6 + 0x50);
    uVar3 = objHitReact_update((int)param_9,hitReactEntries,1,(uint)*(byte *)(iVar6 + 0x3d4),
                               in_r7);
    *(undefined *)(iVar6 + 0x3d4) = uVar3;
    if (*(char *)(iVar6 + 0x3d4) != '\0') {
      FUN_8003a1c4((int)param_9,iVar6 + 0x40c);
      FUN_8003b280((int)param_9,iVar6 + 0x40c);
      return;
    }
  }
  dVar8 = FUN_80017714((float *)(param_9 + 0xc),(float *)(*(int *)(iVar6 + 0x28) + 0x18));
  *(float *)(iVar6 + 0x18) = (float)dVar8;
  cVar1 = *(char *)(iVar5 + 0x1d);
  if (cVar1 == '\x02') {
    nw_mammoth_update((int)param_9,iVar6);
    goto LAB_801cf840;
  }
  if (cVar1 < '\x02') {
    if (cVar1 == '\0') {
      FUN_801cf0b0((uint)param_9,iVar6);
      goto LAB_801cf840;
    }
    if (cVar1 < '\0') goto LAB_801cf840;
  }
  else {
    if (cVar1 == '\x04') {
      FUN_801ce638(dVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar6,iVar5
                  );
      goto LAB_801cf840;
    }
    if ('\x03' < cVar1) goto LAB_801cf840;
  }
  nw_mammoth_free(param_9);
LAB_801cf840:
  if (((&gNwMammothStateFlags)[*(byte *)(iVar6 + 0x408)] & 1) == 0) {
    *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) & 0xef;
    if ((((&gNwMammothStateFlags)[*(byte *)(iVar6 + 0x408)] & 0x10) == 0) ||
       (iVar5 = FUN_8012efc4(), iVar5 == -1)) {
      in_r7 = (float *)0x0;
      in_r8 = 2;
      FUN_80017a6c((int)param_9,0,0,0,'\0','\x02');
    }
    else {
      in_r7 = (float *)0x0;
      in_r8 = 4;
      FUN_80017a6c((int)param_9,0,0,0,'\0','\x04');
    }
  }
  else {
    *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) | 0x10;
  }
  uVar4 = (uint)*(byte *)(iVar6 + 0x408);
  iVar5 = (int)*(short *)(&gNwMammothStateMoveIds + uVar4 * 2);
  if (param_9[0x50] != iVar5) {
    if ((double)*(float *)(&gNwMammothStateMoveStepScales + uVar4 * 4) <= (double)lbl_803E5EA4) {
      FUN_800305f8((double)lbl_803E5EA8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,iVar5,0,uVar4,in_r7,in_r8,in_r9,in_r10);
    }
    else {
      FUN_800305f8((double)lbl_803E5EA4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,iVar5,0,uVar4,in_r7,in_r8,in_r9,in_r10);
    }
    *(undefined4 *)(iVar6 + 0x4c) =
         *(undefined4 *)(&gNwMammothStateMoveStepScales + (uint)*(byte *)(iVar6 + 0x408) * 4);
  }
  iVar5 = FUN_8002fc3c((double)*(float *)(iVar6 + 0x4c),(double)lbl_803DC074);
  if (iVar5 == 0) {
    *(byte *)(iVar6 + 0x43c) = *(byte *)(iVar6 + 0x43c) & 0xfd;
  }
  else {
    *(byte *)(iVar6 + 0x43c) = *(byte *)(iVar6 + 0x43c) | 2;
  }
  objAudioFn_8006ef38((double)lbl_803E5EA8,(double)lbl_803E5EA8,param_9,iVar6 + 0x440,8,iVar6 + 0x45c,
               iVar6 + 0x16c);
  FUN_801ce340(param_9,iVar6,(byte)(&gNwMammothStateFlags)[*(byte *)(iVar6 + 0x408)] & 4);
  *(byte *)(iVar6 + 0x43c) = *(byte *)(iVar6 + 0x43c) & 0xfb;
  if (((*(byte *)(iVar6 + 0x43c) & 0x10) == 0) && (iVar5 = ObjTrigger_IsSet((int)param_9), iVar5 != 0))
  {
    uVar4 = randomGetRange(1,(uint)**(byte **)(iVar6 + 0x48));
    *(byte *)(iVar6 + 0x43c) = *(byte *)(iVar6 + 0x43c) | 4;
    (**(code **)(*DAT_803dd6d4 + 0x48))
              (*(undefined *)(*(int *)(iVar6 + 0x48) + uVar4),param_9,0xffffffff);
  }
  if ((*(byte *)(iVar6 + 0x43c) & 1) != 0) {
    (**(code **)(*DAT_803dd728 + 0x10))((double)lbl_803DC074,param_9,iVar6 + 0x16c);
    (**(code **)(*DAT_803dd728 + 0x14))(param_9,iVar6 + 0x16c);
    (**(code **)(*DAT_803dd728 + 0x18))((double)lbl_803DC074,param_9,iVar6 + 0x16c);
  }
  return;
}

extern void GameBit_Set(int eventId, int value);
#pragma scheduling off
void nw_tricky_free(int obj) {
    (void)obj;
    GameBit_Set(0x4e4, 1);
}
#pragma scheduling reset
