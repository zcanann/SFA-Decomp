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

/*
 * --INFO--
 *
 * Function: FUN_801df43c
 * EN v1.0 Address: 0x801DF43C
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x801DF458
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801df43c(int param_1)
{
  FUN_8003b818(param_1);
  return;
}

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
  int iVar4;
  int iVar5;
  
  iVar5 = *(int *)(param_1 + 0x4c);
  iVar4 = *(int *)(param_1 + 0xb8);
  iVar2 = FUN_80017a98();
  uVar3 = FUN_80006c00(0);
  if ((uVar3 & 0x100) == 0) {
    uVar3 = 0;
  }
  else {
    *(undefined *)(iVar4 + 2) = 0;
    iVar2 = FUN_80294d20(iVar2);
    bVar1 = iVar2 < *(short *)(iVar5 + 0x1a);
    if (bVar1) {
      *(undefined *)(iVar4 + 2) = 2;
    }
    else {
      *(undefined *)(iVar4 + 2) = 0;
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
  byte *pbVar3;
  
  pbVar3 = *(byte **)(param_1 + 0xb8);
  bVar1 = *pbVar3;
  if (bVar1 == 1) {
    if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
    }
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
  }
  else if (bVar1 == 0) {
    uVar2 = (uint)*(short *)(*(int *)(param_1 + 0x4c) + 0x1e);
    if ((uVar2 == 0xffffffff) || (uVar2 = GameBit_Get(uVar2), uVar2 == 0)) {
      *pbVar3 = 1;
    }
    else {
      *pbVar3 = 2;
    }
  }
  else if (bVar1 < 3) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  }
  pbVar3[2] = 0;
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
int fn_801DF854(void) { return 0x0; }
int FElevControl_getExtraSize(void) { return 0x0; }
int fn_801DF93C(void) { return 0x0; }
int fn_801DF9BC(void) { return 0x0; }
int fn_801DF9C4(void) { return 0x0; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E56B4;
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
