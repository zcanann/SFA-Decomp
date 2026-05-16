#include "ghidra_import.h"

extern int Sfx_PlayFromObjectLimited(u8 *obj,int sfxId,int maxCount);
extern u32 GameBit_Get(int eventId);
extern u32 randomGetRange(int min,int max);
extern void mm_free(u32 handle);
extern u8 *Obj_GetPlayerObject(void);
extern int ObjHits_GetPriorityHit(u8 *obj,int *out,int param_3,int param_4);
extern void renderFn_8008f904(u32 handle);
extern int fn_8008FB20(double radiusX,double radiusY,float *start,float *end,int param_5,int param_6,int param_7);

extern undefined4 *pDll_expgfx;
extern f32 timeDelta;
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

#define DFPLIGHTNI_EVENT_TIMER_GAMEBIT 0x5e5
#define DFPLIGHTNI_BLOCKED_GAMEBIT 0xe57
#define DFPLIGHTNI_SFX_ID 0x4c3
#define DFPLIGHTNI_SFX_MAX_COUNT 2

#define DFPLIGHTNI_RANDOM_TIMER_MIN 0
#define DFPLIGHTNI_RANDOM_TIMER_MAX 100
#define DFPLIGHTNI_RANDOM_XZ_MIN -200
#define DFPLIGHTNI_RANDOM_XZ_MAX 200
#define DFPLIGHTNI_RANDOM_Y_MIN 100
#define DFPLIGHTNI_RANDOM_Y_MAX 300

#define DFPLIGHTNI_EVENT_ACTIVE_EFFECT_FRAMES 10
#define DFPLIGHTNI_ANGLE_STEP 0xc
#define DFPLIGHTNI_EFFECT_ANGLE_MASK 0xff

#define DFPLIGHTNI_OBJECT_POS_X_OFFSET 0xc
#define DFPLIGHTNI_OBJECT_POS_Y_OFFSET 0x10
#define DFPLIGHTNI_OBJECT_POS_Z_OFFSET 0x14
#define DFPLIGHTNI_OBJECT_STATE_OFFSET 0xb8

#define DFPPOWERSL_SPAWN_OBJECT_ID 0x39e
#define DFPPOWERSL_SPAWN_COUNT 0x14

typedef struct DfpLightniMapData {
  u8 pad00[0x18];
  s8 angleIndex;
  s8 delayTicks;
  s16 radiusX;
  s16 radiusY;
  u8 pad1E[0x20 - 0x1E];
  s16 eventId;
  u8 pad22[0x24 - 0x22];
} DfpLightniMapData;

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
  return *(DfpLightniState **)(obj + DFPLIGHTNI_OBJECT_STATE_OFFSET);
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
      mm_free(state->effectHandle);
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
      eventActive = GameBit_Get(DFPLIGHTNI_EVENT_TIMER_GAMEBIT);
      if (state->effectHandle != 0) {
        renderFn_8008f904(state->effectHandle);
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
  float *effectStart;
  float *effectEnd;
  float start[3];
  float end[3];
  u32 randomZ;
  u32 randomY;
  u32 randomX;

  if (obj != 0) {
    state = dfplightni_getState(obj);
    playerObj = Obj_GetPlayerObject();
    if (playerObj != 0) {
      state->timer += timeDelta;
      eventActive = GameBit_Get(state->eventId);
      if ((eventActive != 0) && (state->timer < lbl_803E64E0)) {
        state->timer = lbl_803E64F8;
      }
      if ((state->timer > state->triggerTime) && (state->timer < lbl_803E64E0)) {
        start[0] = *(f32 *)(obj + DFPLIGHTNI_OBJECT_POS_X_OFFSET);
        start[1] = *(f32 *)(obj + DFPLIGHTNI_OBJECT_POS_Y_OFFSET);
        start[2] = *(f32 *)(obj + DFPLIGHTNI_OBJECT_POS_Z_OFFSET);
        if (eventActive != 0) {
          randomZ = randomGetRange(DFPLIGHTNI_RANDOM_XZ_MIN,DFPLIGHTNI_RANDOM_XZ_MAX);
          end[0] = (f32)(s32)randomZ * lbl_803E64FC +
                   *(f32 *)(playerObj + DFPLIGHTNI_OBJECT_POS_X_OFFSET);
          randomY = randomGetRange(DFPLIGHTNI_RANDOM_Y_MIN,DFPLIGHTNI_RANDOM_Y_MAX);
          end[1] = (f32)(s32)randomY * lbl_803E64FC +
                   *(f32 *)(playerObj + DFPLIGHTNI_OBJECT_POS_Y_OFFSET);
          randomX = randomGetRange(DFPLIGHTNI_RANDOM_XZ_MIN,DFPLIGHTNI_RANDOM_XZ_MAX);
          end[2] = (f32)(s32)randomX * lbl_803E64FC +
                   *(f32 *)(playerObj + DFPLIGHTNI_OBJECT_POS_Z_OFFSET);
        }
        else {
          randomX = randomGetRange(DFPLIGHTNI_RANDOM_XZ_MIN,DFPLIGHTNI_RANDOM_XZ_MAX);
          end[0] = (f32)(s32)randomX * lbl_803E64FC + start[0];
          randomY = randomGetRange(DFPLIGHTNI_RANDOM_Y_MIN,DFPLIGHTNI_RANDOM_Y_MAX);
          end[1] = (f32)(s32)randomY * lbl_803E64FC +
                   *(f32 *)(obj + DFPLIGHTNI_OBJECT_POS_Y_OFFSET);
          randomZ = randomGetRange(DFPLIGHTNI_RANDOM_XZ_MIN,DFPLIGHTNI_RANDOM_XZ_MAX);
          end[2] = (f32)(s32)randomZ * lbl_803E64FC + start[2];
        }
        if (state->effectHandle != 0) {
          mm_free(state->effectHandle);
          state->effectHandle = 0;
        }
        radiusX = (double)state->radiusX;
        radiusY = (double)state->radiusY;
        eventBlocked = GameBit_Get(DFPLIGHTNI_BLOCKED_GAMEBIT);
        if (eventBlocked == 0) {
          double clampX;
          double clampY;
          Sfx_PlayFromObjectLimited(obj,DFPLIGHTNI_SFX_ID,DFPLIGHTNI_SFX_MAX_COUNT);
          if (eventActive != 0) {
            clampY = (radiusY < (double)lbl_803E6500) ? (double)lbl_803E6500
                       : (radiusY > (double)lbl_803E6504) ? (double)lbl_803E6504 : radiusY;
            effectStart = start;
            effectEnd = end;
            clampX = (radiusX < (double)lbl_803E6500) ? (double)lbl_803E6500
                       : (radiusX > (double)lbl_803E6504) ? (double)lbl_803E6504 : radiusX;
            state->effectHandle =
                fn_8008FB20(clampX,clampY,effectStart,effectEnd,
                            DFPLIGHTNI_EVENT_ACTIVE_EFFECT_FRAMES,
                            state->angleIndex * DFPLIGHTNI_ANGLE_STEP &
                                DFPLIGHTNI_EFFECT_ANGLE_MASK,0);
          }
          else {
            clampY = (radiusY < (double)lbl_803E6500) ? (double)lbl_803E6500
                       : (radiusY > (double)lbl_803E6504) ? (double)lbl_803E6504 : radiusY;
            effectStart = start;
            effectEnd = end;
            clampX = (radiusX < (double)lbl_803E6500) ? (double)lbl_803E6500
                       : (radiusX > (double)lbl_803E6504) ? (double)lbl_803E6504 : radiusX;
            state->effectHandle =
                fn_8008FB20(clampX,clampY,effectStart,effectEnd,(u16)state->delayFrames,
                            state->angleIndex * DFPLIGHTNI_ANGLE_STEP &
                                DFPLIGHTNI_EFFECT_ANGLE_MASK,0);
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
void dfplightni_init(u8 *obj,DfpLightniMapData *mapData)
{
  DfpLightniState *state;
  f32 radiusMax;
  f32 radiusParamScale;
  u32 randomValue;

  if (obj != 0) {
    state = dfplightni_getState(obj);
    randomValue = randomGetRange(DFPLIGHTNI_RANDOM_TIMER_MIN,DFPLIGHTNI_RANDOM_TIMER_MAX);
    state->timer = (f32)(s32)randomValue;
    state->effectHandle = 0;
    if (mapData->radiusX <= 0) {
      mapData->radiusX = 1;
    }
    if (mapData->radiusY <= 0) {
      mapData->radiusY = 1;
    }
    randomValue = randomGetRange(DFPLIGHTNI_RANDOM_TIMER_MIN,DFPLIGHTNI_RANDOM_TIMER_MAX);
    state->triggerTime = (f32)(s32)randomValue + lbl_803E6508;
    radiusMax = lbl_803E6504;
    radiusParamScale = lbl_803E650C;
    state->radiusX = ((f32)(s32)mapData->radiusX / radiusParamScale) * radiusMax;
    state->radiusY = ((f32)(s32)mapData->radiusY / radiusParamScale) * radiusMax;
    state->angleIndex = mapData->angleIndex;
    state->delayFrames = mapData->delayTicks * DFPLIGHTNI_EVENT_ACTIVE_EFFECT_FRAMES;
    state->eventId = mapData->eventId;
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
      ((DfpPowerSlSpawnFn)(*(u32 *)(*pDll_expgfx + 8)))(obj,DFPPOWERSL_SPAWN_OBJECT_ID,0,1,
                                                        0xffffffff,0);
    } while (i++ < DFPPOWERSL_SPAWN_COUNT);
  }
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

u32 gDfplightniObjDescriptor[] = {
  0,
  0,
  0,
  0x00090000,
  0,
  0,
  0,
  (u32)dfplightni_init,
  (u32)dfplightni_update,
  0,
  (u32)dfplightni_render,
  (u32)dfplightni_free,
  0,
  (u32)dfplightni_getExtraSize,
};
