#include "ghidra_import.h"

extern int Sfx_PlayFromObjectLimited(u8 *obj,int sfxId,int maxCount);
extern u32 GameBit_Get(int eventId);
extern u32 fn_800221A0(int min,int max);
extern void fn_80023800(u32 handle);
extern u8 *Obj_GetPlayerObject(void);
extern int ObjHits_GetPriorityHit(u8 *obj,int *out,int param_3,int param_4);
extern void fn_8008F904(u32 handle);
extern int fn_8008FB20(double radiusX,double radiusY,float *start,float *end,int param_5,int param_6,int param_7);

extern undefined4 *lbl_803DCA88;
extern f32 lbl_803DB414;
extern f32 lbl_803E64E0;
extern f32 lbl_803E64E4;
extern f32 lbl_803E64E8;
extern f64 lbl_803E64F0;
extern f32 lbl_803E64F8;
extern f32 lbl_803E64FC;
extern f32 lbl_803E6500;
extern f32 lbl_803E6504;
extern f32 lbl_803E6508;
extern f32 lbl_803E650C;

typedef struct DfpLightniState {
  u32 effectHandle;
  f32 timer;
  f32 triggerTime;
  f32 radiusX;
  f32 radiusY;
  s16 angleIndex;
  s16 delayFrames;
  s32 eventId;
} DfpLightniState;

typedef void (*DfpPowerSlSpawnFn)(u8 *obj,int objectId,int param_3,int param_4,int param_5,int param_6);

static inline DfpLightniState *dfplightni_getState(u8 *obj)
{
  return *(DfpLightniState **)(obj + 0xb8);
}

static inline f64 dfplightni_u32AsDouble(u32 value)
{
  u64 bits = CONCAT44(0x43300000,value);
  return *(f64 *)&bits;
}

int dfplightni_getExtraSize(void)
{
  return sizeof(DfpLightniState);
}

#pragma scheduling off
#pragma peephole off
void dfplightni_free(u8 *obj)
{
  DfpLightniState *state;

  if (obj != 0) {
    state = dfplightni_getState(obj);
    if (state->effectHandle != 0) {
      fn_80023800(state->effectHandle);
      state->effectHandle = 0;
    }
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void dfplightni_render(u8 *obj)
{
  DfpLightniState *state;
  int eventActive;

  if (obj != 0) {
    state = dfplightni_getState(obj);
    if (state->timer >= lbl_803E64E0) {
      eventActive = GameBit_Get(0x5e5);
      if (state->effectHandle != 0) {
        fn_8008F904(state->effectHandle);
      }
      if (eventActive != 0) {
        if (state->timer >= lbl_803E64E0 + (f32)(s32)state->delayFrames) {
          state->timer = lbl_803E64E4;
        }
      }
      else if (state->timer >= lbl_803E64E8) {
        state->timer = lbl_803E64E4;
      }
    }
  }
  return;
}

#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void dfplightni_update(u8 *obj)
{
  u8 *playerObj;
  int eventActive;
  u32 eventBlocked;
  DfpLightniState *state;
  double radiusX;
  double radiusY;
  float start[3];
  float end[3];
  u32 randomZ;
  u32 randomY;
  u32 randomX;

  if (obj != 0) {
    state = dfplightni_getState(obj);
    playerObj = Obj_GetPlayerObject();
    if (playerObj != 0) {
      state->timer += lbl_803DB414;
      eventActive = GameBit_Get(state->eventId);
      if ((eventActive != 0) && (state->timer < lbl_803E64E0)) {
        state->timer = lbl_803E64F8;
      }
      if ((state->timer > state->triggerTime) && (state->timer < lbl_803E64E0)) {
        start[0] = *(f32 *)(obj + 0xc);
        start[1] = *(f32 *)(obj + 0x10);
        start[2] = *(f32 *)(obj + 0x14);
        if (eventActive != 0) {
          randomZ = fn_800221A0(-200,200);
          end[0] = (f32)(s32)randomZ * lbl_803E64FC + *(f32 *)(playerObj + 0xc);
          randomY = fn_800221A0(100,300);
          end[1] = (f32)(s32)randomY * lbl_803E64FC + *(f32 *)(playerObj + 0x10);
          randomX = fn_800221A0(-200,200);
          end[2] = (f32)(s32)randomX * lbl_803E64FC + *(f32 *)(playerObj + 0x14);
        }
        else {
          randomX = fn_800221A0(-200,200);
          end[0] = (f32)(s32)randomX * lbl_803E64FC + start[0];
          randomY = fn_800221A0(100,300);
          end[1] = (f32)(s32)randomY * lbl_803E64FC + *(f32 *)(obj + 0x10);
          randomZ = fn_800221A0(-200,200);
          end[2] = (f32)(s32)randomZ * lbl_803E64FC + start[2];
        }
        if (state->effectHandle != 0) {
          fn_80023800(state->effectHandle);
          state->effectHandle = 0;
        }
        radiusX = (double)state->radiusX;
        radiusY = (double)state->radiusY;
        eventBlocked = GameBit_Get(0xe57);
        if (eventBlocked == 0) {
          double clampX;
          double clampY;
          Sfx_PlayFromObjectLimited(obj,0x4c3,2);
          if (eventActive == 0) {
            clampY = (radiusY < (double)lbl_803E6500) ? (double)lbl_803E6500
                       : ((double)lbl_803E6504 < radiusY) ? (double)lbl_803E6504 : radiusY;
            clampX = (radiusX < (double)lbl_803E6500) ? (double)lbl_803E6500
                       : ((double)lbl_803E6504 < radiusX) ? (double)lbl_803E6504 : radiusX;
            state->effectHandle =
                fn_8008FB20(clampX,clampY,start,end,state->delayFrames,
                            state->angleIndex * 0xc & 0xff,0);
          }
          else {
            clampY = (radiusY < (double)lbl_803E6500) ? (double)lbl_803E6500
                       : ((double)lbl_803E6504 < radiusY) ? (double)lbl_803E6504 : radiusY;
            clampX = (radiusX < (double)lbl_803E6500) ? (double)lbl_803E6500
                       : ((double)lbl_803E6504 < radiusX) ? (double)lbl_803E6504 : radiusX;
            state->effectHandle =
                fn_8008FB20(clampX,clampY,start,end,10,state->angleIndex * 0xc & 0xff,0);
          }
        }
        state->timer = lbl_803E64E0;
      }
    }
  }
  return;
}

#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void dfplightni_init(u8 *obj,u8 *params)
{
  DfpLightniState *state;
  u32 randomValue;

  if (obj != 0) {
    state = dfplightni_getState(obj);
    randomValue = fn_800221A0(0,100);
    state->timer = (f32)(s32)randomValue;
    state->effectHandle = 0;
    if (*(s16 *)(params + 0x1a) <= 0) {
      *(s16 *)(params + 0x1a) = 1;
    }
    if (*(s16 *)(params + 0x1c) <= 0) {
      *(s16 *)(params + 0x1c) = 1;
    }
    randomValue = fn_800221A0(0,100);
    state->triggerTime = (f32)(s32)randomValue + lbl_803E6508;
    state->radiusX = ((f32)(s32)*(s16 *)(params + 0x1a) / lbl_803E650C) *
                     lbl_803E6504;
    state->radiusY = ((f32)(s32)*(s16 *)(params + 0x1c) / lbl_803E650C) *
                     lbl_803E6504;
    state->angleIndex = *(s8 *)(params + 0x18);
    state->delayFrames = *(s8 *)(params + 0x19) * 10;
    state->eventId = *(s16 *)(params + 0x20);
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
undefined4 dfppowersl_spawnSeqObjectsOnHit(u8 *obj)
{
  int i;
  int outObj;

  outObj = 0;
  if (obj == 0) {
    return 0;
  }
  i = ObjHits_GetPriorityHit(obj,&outObj,0,0);
  if (((u32)outObj != 0) && (i != 0)) {
    i = 1;
    do {
      ((DfpPowerSlSpawnFn)(*(u32 *)(*lbl_803DCA88 + 8)))(obj,0x39e,0,1,0xffffffff,0);
    } while (i++ < 0x14);
  }
  return 0;
}
#pragma peephole reset
#pragma scheduling reset
