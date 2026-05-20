#include "ghidra_import.h"
#include "main/dll/DB/DBrockfall.h"
#include "main/dll/VF/platform1.h"

extern uint FUN_80006c00();
extern undefined4 FUN_80006c88();
extern undefined8 FUN_80017484();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId,int value);
extern int FUN_80017a98();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800400b0();
extern undefined4 FUN_80080eec();
extern undefined4 FUN_8011e800();
extern int FUN_80286838();
extern undefined4 FUN_80286884();
extern int FUN_80294d20();
extern undefined4 FUN_80294d28();
extern uint countLeadingZeros();

extern undefined4 DAT_80328730;
extern undefined4 DAT_80328734;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd72c;
extern undefined4 DAT_803de890;
extern f32 lbl_803E6310;
extern undefined4 *pDll_expgfx;
extern f32 lbl_803E56B0;
extern f32 lbl_803E56B4;

/*
 * --INFO--
 *
 * Function: paymentkiosk_init
 * EN v1.0 Address: 0x801DF43C
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x801DF458
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void fn_801DF1EC(void);
#pragma scheduling off
#pragma peephole off
void paymentkiosk_init(int obj, u8 *initData)
{
    register int self = obj;
    register int state = *(int *)(self + 0xb8);
    u32 secondaryFlag;

    *(void (**)(void))(self + 0xbc) = fn_801DF1EC;
    *(short *)self = (short)((int)(signed char)initData[0x18] << 8);
    *(u8 *)state = 0;
    *(u16 *)(self + 0xb0) = (u16)((u32)*(u16 *)(self + 0xb0) | 0x6000);
    *(u8 *)(self + 0xaf) = (u8)((u32)*(u8 *)(self + 0xaf) | 0x8);
    secondaryFlag = (*(short *)(self + 0x46) == 0x476) ? 1 : 0;
    *(u8 *)(state + 1) = (u8)secondaryFlag;
}
#pragma peephole reset
#pragma scheduling reset

typedef struct FEseqobjectEffectParams {
  s16 xRot;
  s16 yRot;
  s16 variant;
  s16 pad06;
  f32 scale;
  f32 x;
  f32 y;
  f32 z;
} FEseqobjectEffectParams;

static void FEseqobject_spawnEffect(int obj, FEseqobjectEffectParams *params)
{
  (*(void (**)(int, int, FEseqobjectEffectParams *, int, int, int))(*pDll_expgfx + 0x8))
      (obj, 0x85, params, 1, -1, 0);
}

static int FEseqobject_findControlObject(void)
{
  int count;
  int i;
  int found;
  int *objects;

  objects = (int *)ObjGroup_GetObjects(3, &count);
  found = 0;
  for (i = 0; i < count; i++) {
    int obj = objects[i];
    if (*(s16 *)(obj + 0x46) == 0xf7) {
      found = obj;
      i = count;
    }
  }
  return found;
}

#pragma scheduling off
#pragma peephole off
int fn_801DF4AC(int obj, undefined4 unused, u8 *setup)
{
  FEseqobjectEffectParams effect;
  register int self = obj;
  register u8 *setupData = setup;
  int i;
  int msg;
  uint sender;
  uint param;
  int controlObj;
  f32 zero;
  f32 one;

  zero = lbl_803E56B0;
  one = lbl_803E56B4;
  controlObj = 0;
  for (i = 0; i < setupData[0x8b]; i++) {
    effect.x = zero;
    effect.y = zero;
    effect.z = zero;
    effect.scale = one;
    effect.yRot = 0;
    effect.xRot = 0;
    effect.variant = 0;

    switch (setupData[i + 0x81]) {
      case 1:
        GameBit_Set(0x75, 1);
        break;
      case 2:
        effect.variant = 0;
        FEseqobject_spawnEffect(self, &effect);
        break;
      case 3:
        effect.variant = 1;
        FEseqobject_spawnEffect(self, &effect);
        break;
      case 4:
        effect.variant = 2;
        FEseqobject_spawnEffect(self, &effect);
        break;
      case 5:
        effect.variant = 3;
        FEseqobject_spawnEffect(self, &effect);
        break;
      case 6:
        effect.variant = 4;
        FEseqobject_spawnEffect(self, &effect);
        break;
    }
  }

  while (ObjMsg_Pop((void *)self, (uint *)&msg, &sender, &param) != 0) {
    if ((setupData[0x90] & 0x80) == 0) {
      if (msg == 0xf000b) {
        controlObj = FEseqobject_findControlObject();
        if (controlObj != 0) {
          ObjMsg_SendToObject((void *)controlObj, 0x130001, (void *)self, 0);
        }
      } else if (msg == 0xf000c) {
        controlObj = FEseqobject_findControlObject();
        if (controlObj != 0) {
          ObjMsg_SendToObject((void *)controlObj, 0x130002, (void *)self, 0);
        }
      } else if (msg == 0xf000d) {
        controlObj = FEseqobject_findControlObject();
        if (controlObj != 0) {
          ObjMsg_SendToObject((void *)controlObj, 0x130003, (void *)self, 0);
        }
      }
    }
  }
  setupData[0x56] = 0;
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_801df45c
 * EN v1.0 Address: 0x801DF45C
 * EN v1.0 Size: 576b
 * EN v1.1 Address: 0x801DF480
 * EN v1.1 Size: 640b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801df45c(undefined2 *param_1)
{
  bool bVar1;
  byte bVar2;
  short sVar3;
  float fVar4;
  int iVar5;
  char cVar7;
  undefined4 uVar6;
  Platform1State *state;
  
  state = *(Platform1State **)(param_1 + 0x5c);
  FUN_80017a98();
  GameBit_Set(0xf1d,0);
  cVar7 = (**(code **)(*DAT_803dd72c + 0x40))(0xe);
  if (cVar7 == '\x06') {
    if ((state->flags & PLATFORM1_FLAG_ACTIVE) == 0) {
      if ((state->flags & PLATFORM1_TRIGGER_FLAG_02) != 0) {
        sVar3 = state->transitionStep;
        if (sVar3 == 0) {
          *param_1 = 0xd700;
          state->currentTrackOffset = 0xffffd700;
          state->prevTrackOffset = state->currentTrackOffset;
          fVar4 = lbl_803E6310;
          state->motionValue0 = lbl_803E6310;
          state->offsetVelocity = fVar4;
          state->transitionStep = 1;
          state->flags = state->flags & ~PLATFORM1_TRIGGER_FLAG_01;
        }
        else if (sVar3 == 1) {
          GameBit_Set(0xf1d,1);
          FUN_8011e800(1);
          uVar6 = (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
          state->loopSfxHandle = uVar6;
        }
        else if (sVar3 == 2) {
          state->transitionStep = 0;
        }
        else if (sVar3 == 3) {
          state->transitionStep = 0;
        }
      }
    }
    else {
      if (0 < state->loopSfxHandle) {
        (**(code **)(*DAT_803dd6d4 + 0x4c))();
        FUN_80080eec(state->loopSfxHandle);
      }
      iVar5 = DAT_803de890 + -1;
      bVar1 = DAT_803de890 == 0;
      DAT_803de890 = iVar5;
      if (bVar1) {
        state->flags = state->flags & ~PLATFORM1_FLAG_ACTIVE;
        *(undefined4 *)(param_1 + 6) = state->savedPosXBits;
        *(undefined4 *)(param_1 + 8) = state->savedPosYBits;
        *(undefined4 *)(param_1 + 10) = state->savedPosZBits;
        state->linkedObject = 0;
        *param_1 = 0xd700;
        state->currentTrackOffset = 0xffffd700;
        bVar2 = state->flags;
        if ((bVar2 & PLATFORM1_FLAG_EXIT_NEGATIVE) == 0) {
          if ((bVar2 & PLATFORM1_FLAG_EXIT_POSITIVE) != 0) {
            state->flags = bVar2 & ~PLATFORM1_FLAG_EXIT_POSITIVE;
            state->loopSfxHandle = -1;
            GameBit_Set(0x786,1);
          }
        }
        else {
          GameBit_Set(0x784,1);
          state->loopSfxHandle = -1;
          state->flags = state->flags & ~PLATFORM1_TRIGGER_MASK;
          state->flags = state->flags & ~PLATFORM1_FLAG_EXIT_NEGATIVE;
        }
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801df69c
 * EN v1.0 Address: 0x801DF69C
 * EN v1.0 Size: 232b
 * EN v1.1 Address: 0x801DF700
 * EN v1.1 Size: 220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_801df69c(int param_1,undefined4 param_2,int param_3)
{
  bool bVar1;
  int iVar2;
  uint uVar3;
  int iVar5;
  FEseqobjectState *state;
  
  iVar5 = *(int *)(param_1 + 0x4c);
  state = *(FEseqobjectState **)(param_1 + 0xb8);
  iVar2 = FUN_80017a98();
  uVar3 = FUN_80006c00(0);
  if ((uVar3 & 0x100) == 0) {
    uVar3 = 0;
  }
  else {
    state->promptState = 0;
    iVar2 = FUN_80294d20(iVar2);
    bVar1 = iVar2 < *(short *)(iVar5 + 0x1a);
    if (bVar1) {
      state->promptState = 2;
    }
    else {
      state->promptState = 0;
    }
    uVar3 = (uint)!bVar1;
    if (param_3 == 0x15) {
      uVar3 = countLeadingZeros(uVar3);
      uVar3 = uVar3 >> 5;
    }
    else if ((param_3 < 0x15) && (0x13 < param_3)) {
      uVar3 = countLeadingZeros(1 - uVar3);
      uVar3 = uVar3 >> 5;
    }
    else {
      uVar3 = 0;
    }
  }
  return uVar3;
}

/*
 * --INFO--
 *
 * Function: FUN_801df784
 * EN v1.0 Address: 0x801DF784
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801DF7DC
 * EN v1.1 Size: 316b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801df784(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801df788
 * EN v1.0 Address: 0x801DF788
 * EN v1.0 Size: 252b
 * EN v1.1 Address: 0x801DF918
 * EN v1.1 Size: 276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801df788(int param_1)
{
  byte bVar1;
  uint uVar2;
  FEseqobjectState *state;
  
  state = *(FEseqobjectState **)(param_1 + 0xb8);
  bVar1 = state->state;
  if (bVar1 == 1) {
    if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
    }
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
  }
  else if (bVar1 == 0) {
    uVar2 = (uint)*(short *)(*(int *)(param_1 + 0x4c) + 0x1e);
    if ((uVar2 == 0xffffffff) || (uVar2 = GameBit_Get(uVar2), uVar2 == 0)) {
      state->state = 1;
    }
    else {
      state->state = 2;
    }
  }
  else if (bVar1 < 3) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  }
  state->promptState = 0;
  if (((*(uint *)(*(int *)(param_1 + 0x50) + 0x44) & 1) != 0) && (*(int *)(param_1 + 0x74) != 0)) {
    FUN_800400b0();
  }
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void paymentkiosk_release(void) {}
void paymentkiosk_initialise(void) {}
void FEseqobject_free(void) {}
void FEseqobject_hitDetect(void) {}
void FEseqobject_release(void) {}
void FEseqobject_initialise(void) {}
void FElevControl_free(void) {}
void FElevControl_hitDetect(void) {}
void FElevControl_update(void) {}
void FElevControl_release(void) {}
void FElevControl_initialise(void) {}
void fn_801DF9CC(void) {}
void fn_801DFA00(void) {}
void fn_801DFA04(void) {}
void fn_801DFA20(void) {}
void fn_801DFA24(void) {}

/* 8b "li r3, N; blr" returners. */
int FEseqobject_getExtraSize(void) { return 0x1; }
int FEseqobject_func08(void) { return 0x0; }
int FElevControl_getExtraSize(void) { return 0x0; }
int FElevControl_func08(void) { return 0x0; }
int fn_801DF9BC(void) { return 0x0; }
int fn_801DF9C4(void) { return 0x0; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E56B8;
extern f32 lbl_803E56C0;
#pragma peephole off
void FEseqobject_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E56B4); }
void FElevControl_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E56B8); }
void fn_801DF9D0(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E56C0); }
#pragma peephole reset

/* call(x, N) wrappers. */
#pragma scheduling off
#pragma peephole off
void FElevControl_init(int x) { ObjMsg_AllocQueue(x, 0x2); }
#pragma peephole reset
#pragma scheduling reset

extern undefined4 *lbl_803DCA54;

/*
 * Function: FEseqobject_init
 * EN v1.0 Address: 0x801DF8F4
 * EN v1.0 Size: 56b
 */
#pragma scheduling off
#pragma peephole off
void FEseqobject_init(int obj)
{
    *(short *)obj = 0;
    *(void (**)(void))(obj + 0xbc) = (void (*)(void))fn_801DF4AC;
    ObjMsg_AllocQueue((void *)obj, 0xa);
}
#pragma peephole reset
#pragma scheduling reset

/*
 * Function: FEseqobject_update
 * EN v1.0 Address: 0x801DF894
 * EN v1.0 Size: 96b
 */
#pragma scheduling off
#pragma peephole off
void FEseqobject_update(int obj)
{
    register int self = obj;
    *(short *)self = 0x2000;
    if (GameBit_Get(0x75) == 0) {
        (*(void (**)(int, int, int))((char *)*(int *)lbl_803DCA54 + 0x48))(0, self, -1);
    }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * Function: fn_801DF9AC
 * EN v1.0 Address: 0x801DF9AC
 * EN v1.0 Size: 16b
 */
#pragma scheduling off
#pragma peephole off
int fn_801DF9AC(void *p1, void *p2, u8 *p3)
{
    p3[0x56] = 0;
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * Function: fn_801DFA08
 * EN v1.0 Address: 0x801DFA08
 * EN v1.0 Size: 24b
 */
#pragma scheduling off
#pragma peephole off
void fn_801DFA08(int obj)
{
    *(short *)obj = 0;
    *(int (**)(void *, void *, u8 *))(obj + 0xbc) = fn_801DF9AC;
}
#pragma peephole reset
#pragma scheduling reset

ObjectDescriptor gFElevControlObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)FElevControl_initialise,
    (ObjectDescriptorCallback)FElevControl_release,
    0,
    (ObjectDescriptorCallback)FElevControl_init,
    (ObjectDescriptorCallback)FElevControl_update,
    (ObjectDescriptorCallback)FElevControl_hitDetect,
    (ObjectDescriptorCallback)FElevControl_render,
    (ObjectDescriptorCallback)FElevControl_free,
    (ObjectDescriptorCallback)FElevControl_func08,
    FElevControl_getExtraSize,
};
