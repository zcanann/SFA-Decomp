#include "main/audio/sfx_ids.h"
#include "main/expgfx.h"
#include "main/game_object.h"
#include "main/dll/dim_tricky.h"
#include "main/effect_interfaces.h"
#include "main/gameplay_runtime.h"
#include "main/obj_placement.h"
#include "main/resource.h"


extern void Sfx_PlayFromObject(void *obj, int sfxId);
extern void Sfx_StopObjectChannel(void *obj, int channel);
extern void objUpdateOpacity(void *obj);
extern int ObjHits_GetPriorityHit(void *obj, int a, int b, int c);

extern u8 framesThisStep;
extern ModgfxInterface **gModgfxInterface;
extern EffectInterface **gPartfxInterface;
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

typedef struct Dll19ESetup {
  ObjPlacement base;
  s8 objectType;
  u8 mode;
  s16 scaleTimer;
  s16 sequenceIndex;
  s16 gameBitId;
} Dll19ESetup;

STATIC_ASSERT(sizeof(Dll19ESetup) == 0x20);
STATIC_ASSERT(offsetof(Dll19ESetup, objectType) == 0x18);
STATIC_ASSERT(offsetof(Dll19ESetup, mode) == 0x19);
STATIC_ASSERT(offsetof(Dll19ESetup, scaleTimer) == 0x1A);
STATIC_ASSERT(offsetof(Dll19ESetup, sequenceIndex) == 0x1C);
STATIC_ASSERT(offsetof(Dll19ESetup, gameBitId) == 0x1E);

/*
 * --INFO--
 *
 * Function: dll_19E_update
 * EN v1.0 Address: 0x801CD258
 * EN v1.0 Size: 1056b
 */
void dll_19E_update(void *obj)
{
  Dll19EState *state;
  void *resource;
  volatile f32 localScale;
  undefined effectArgs[16];
  undefined4 resourceArgs[4];
  int i;

  state = ((GameObject *)obj)->extra;
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
          (*gPartfxInterface)->spawnObject(obj, 0x1a3, NULL, 0, -1, NULL);
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
        (*gModgfxInterface)->detachSource(obj);
        (*gExpgfxInterface)->freeSource((u32)obj);
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


/*
 * --INFO--
 *
 * Function: dll_19E_init
 * EN v1.0 Address: 0x801CD678
 * EN v1.0 Size: 348b
 */
void dll_19E_init(u8 *obj, Dll19ESetup *setup)
{
  Dll19EState *state;
  void *resource;
  undefined stackArg[16];
  volatile f32 localScale;

  state = ((GameObject *)obj)->extra;
  *(s16 *)obj = (s16)(((s32)setup->objectType & 0x3f) << 10);
  if (setup->scaleTimer > 0) {
    ((GameObject *)obj)->anim.rootMotionScale = (f32)setup->scaleTimer / lbl_803E51E4;
  }
  else {
    ((GameObject *)obj)->anim.rootMotionScale = lbl_803E51E8;
  }

  state->mode = setup->mode;
  state->active = 0;
  state->sequenceIndex = 0;
  state->gameBitId = setup->gameBitId;
  localScale = lbl_803E51E0;

  if (state->mode == 1) {
    state->sequenceIndex = (u8)setup->sequenceIndex;
    state->needsOpenSfx = 0;
    state->settleTimer = state->sequenceIndex * 0x28 + 0x398;
    state->previousActive = 0;
  }
  else if (state->mode == 0) {
    state->active = 1;
    resource = Resource_Acquire(0x69, 1);
    if (setup->sequenceIndex == 0) {
      (*(void (**)(u8 *, int, undefined *, int, int, int))(*(int *)resource + 4))(
          obj, 0, stackArg, 0x10004, -1, 0);
    }
  }
  state->delayTimer = 0;
}


/* Trivial 4b 0-arg blr leaves. */
void dll_19E_release(void) {}
void dll_19E_initialise(void) {}
