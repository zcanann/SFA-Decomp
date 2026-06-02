#include "ghidra_import.h"
#include "main/dll/dim_tricky.h"

#define SFXmn_eggylaugh216 114
#define SFXmn_sml_trex_snap1 128

extern void *Resource_Acquire(int id, int mode);
extern void Resource_Release(void *handle);
extern void Sfx_PlayFromObject(void *obj, int sfxId);
extern void Sfx_StopObjectChannel(void *obj, int channel);
extern void objUpdateOpacity(void *obj);
extern int ObjHits_GetPriorityHit(void *obj, int a, int b, int c);
extern u32 GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);

extern u8 framesThisStep;
extern int *gExpgfxInterface;
extern int *gModgfxInterface;
extern int *gPartfxInterface;
extern s8 lbl_803DDBE8;
extern undefined4 lbl_802C23D8[4];
extern f32 lbl_803E51E0;
extern f32 lbl_803E51E4;
extern f32 lbl_803E51E8;
extern f64 lbl_803E51F0;

typedef struct Dll19EState {
  s32 gameBitId;
  s16 delayTimer;
  s16 resetTimer;
  s16 settleTimer;
  u8 pad0A;
  u8 mode;
  u8 active;
  u8 needsOpenSfx;
  u8 previousActive;
  u8 sequenceIndex;
} Dll19EState;

/*
 * --INFO--
 *
 * Function: dll_19E_update
 * EN v1.0 Address: 0x801CD258
 * EN v1.0 Size: 1056b
 */
#pragma scheduling off
#pragma peephole off
void dll_19E_update(void *obj)
{
  Dll19EState *state;
  void *resource;
  volatile f32 localScale;
  undefined effectArgs[16];
  undefined4 resourceArgs[4];
  int i;

  state = *(Dll19EState **)((u8 *)obj + 0xb8);
  resourceArgs[0] = lbl_802C23D8[0];
  resourceArgs[1] = lbl_802C23D8[1];
  resourceArgs[2] = lbl_802C23D8[2];
  resourceArgs[3] = lbl_802C23D8[3];

  Sfx_PlayFromObject(obj, SFXmn_eggylaugh216);
  objUpdateOpacity(obj);
  if (state->settleTimer > 0) {
    *(u16 *)&state->settleTimer = state->settleTimer - (u16)framesThisStep;
  }

  if (state->mode == 1) {
    localScale = lbl_803E51E0;
    state->previousActive = state->active;
    if ((ObjHits_GetPriorityHit(obj, 0, 0, 0) != 0) ||
        ((state->settleTimer != 0) && (state->settleTimer <= 0x14))) {
      state->active = (u8)(1 - state->active);
      if (state->active != 0) {
        state->resetTimer = 1000;
      }
      if (state->settleTimer != 0) {
        state->settleTimer = 0;
        lbl_803DDBE8 = 3;
        state->resetTimer = 300;
        if (state->sequenceIndex == 2) {
          GameBit_Set(0x1d1, 1);
        }
      }
    }

    if ((state->active != 0) && (state->resetTimer != 0)) {
      *(u16 *)&state->resetTimer = state->resetTimer - (u16)framesThisStep;
      if (state->resetTimer <= 0) {
        state->resetTimer = 0;
        state->active = 0;
      }
    }

    if ((state->active != 0) && (state->delayTimer <= 0) && (state->needsOpenSfx != 0)) {
      state->needsOpenSfx = 0;
      Sfx_PlayFromObject(obj, SFXmn_sml_trex_snap1);
    }

    if (state->active != state->previousActive) {
      if (state->active != 0) {
        resource = Resource_Acquire(0x69, 1);
        resourceArgs[1] = (u32)state->sequenceIndex * 2 + 0x19d;
        resourceArgs[2] = (u32)state->sequenceIndex * 2 + 0x19e;
        (*(void (*)(void *, int, undefined *, int, int, undefined4 *))(*(int *)(*(int *)resource + 4)))(
            obj, 1, effectArgs, 0x10004, -1, resourceArgs);
        Resource_Release(resource);

        i = 0;
        do {
          (*(void (*)(void *, int, int, int, int, int))(*(int *)(*gPartfxInterface + 8)))(
              obj, 0x1a3, 0, 0, -1, 0);
          i++;
        } while (i < 100);

        if ((state->gameBitId != -1) && (GameBit_Get(state->gameBitId) == 0)) {
          GameBit_Set(state->gameBitId, 1);
        }
        if ((lbl_803DDBE8 == 0) && (state->sequenceIndex == 0) &&
            (GameBit_Get(state->gameBitId) != 0)) {
          lbl_803DDBE8 = 1;
        }
        if ((lbl_803DDBE8 == 1) && (state->sequenceIndex == 1) &&
            (GameBit_Get(state->gameBitId) != 0)) {
          lbl_803DDBE8 = 2;
        }
        if ((lbl_803DDBE8 == 2) && (state->sequenceIndex == 2) &&
            (GameBit_Get(state->gameBitId) != 0)) {
          GameBit_Set(0x1d1, 1);
          lbl_803DDBE8 = 3;
        }
        state->needsOpenSfx = 1;
        state->delayTimer = 1;
      } else {
        Sfx_StopObjectChannel(obj, 0x40);
        (*(void (*)(void *))(*(int *)(*gModgfxInterface + 0x18)))(obj);
        (*(void (*)(void *))(*(int *)(*gExpgfxInterface + 0x14)))(obj);
        if ((state->gameBitId != -1) && (GameBit_Get(state->gameBitId) != 0)) {
          GameBit_Set(state->gameBitId, 0);
        }
        if ((lbl_803DDBE8 == 1) && (state->sequenceIndex == 0)) {
          lbl_803DDBE8 = 0;
        }
        if ((lbl_803DDBE8 == 2) && (state->sequenceIndex == 1)) {
          lbl_803DDBE8 = 0;
        }
        if ((lbl_803DDBE8 == 3) && (state->sequenceIndex == 2) &&
            (GameBit_Get(0x1d5) == 0)) {
          GameBit_Set(0x1d1, 0);
          lbl_803DDBE8 = 0;
        }
      }
    }
  }
}
#pragma peephole reset
#pragma scheduling reset


/*
 * --INFO--
 *
 * Function: dll_19E_init
 * EN v1.0 Address: 0x801CD678
 * EN v1.0 Size: 348b
 */
#pragma scheduling off
#pragma peephole off
void dll_19E_init(undefined2 *obj, int def)
{
  int *state;
  int *resource;
  undefined stackArg[16];
  float localScale;
  undefined4 doubleHigh;
  uint doubleLow;

  state = *(int **)(obj + 0x5c);
  *obj = (short)(((int)*(char *)(def + 0x18) & 0x3fU) << 10);
  if (*(short *)(def + 0x1a) > 0) {
    doubleLow = (int)*(short *)(def + 0x1a) ^ 0x80000000;
    doubleHigh = 0x43300000;
    *(float *)(obj + 4) =
        (float)((double)CONCAT44(doubleHigh, doubleLow) - lbl_803E51F0) / lbl_803E51E4;
  }
  else {
    *(float *)(obj + 4) = lbl_803E51E8;
  }

  *(undefined *)((int)state + 0xb) = *(undefined *)(def + 0x19);
  *(undefined *)(state + 3) = 0;
  *(undefined *)((int)state + 0xf) = 0;
  *state = (int)*(short *)(def + 0x1e);
  localScale = lbl_803E51E0;

  if (*(char *)((int)state + 0xb) == 1) {
    *(char *)((int)state + 0xf) = (char)*(undefined2 *)(def + 0x1c);
    *(undefined *)((int)state + 0xd) = 0;
    *(ushort *)(state + 2) = (ushort)*(byte *)((int)state + 0xf) * 0x28 + 0x398;
    *(undefined *)((int)state + 0xe) = 0;
  }
  else if (*(char *)((int)state + 0xb) == 0) {
    *(undefined *)(state + 3) = 1;
    resource = (int *)Resource_Acquire(0x69, 1);
    if (*(short *)(def + 0x1c) == 0) {
      (*(void (**)(undefined2 *, int, undefined *, int, int, int))(*resource + 4))(
          obj, 0, stackArg, 0x10004, -1, 0);
    }
  }
  *(undefined2 *)(state + 1) = 0;
}
#pragma peephole reset
#pragma scheduling reset


/* Trivial 4b 0-arg blr leaves. */
void dll_19E_release(void) {}
void dll_19E_initialise(void) {}
