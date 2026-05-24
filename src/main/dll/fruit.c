#include "ghidra_import.h"
#include "main/dll/door.h"
#include "main/dll/fruit.h"

#pragma peephole off
#pragma scheduling off

typedef struct DfpTargetBlockPartfxArgs {
  s16 rotX;
  s16 rotY;
  s16 rotZ;
  s16 pad06;
  f32 scale;
  f32 x;
  f32 y;
  f32 z;
} DfpTargetBlockPartfxArgs;

typedef u8 (*MapEventGetModeFn)(s32 mapId);
typedef void (*PartfxSpawnObjectFn)(DfpTargetBlockObject *obj, int id, DfpTargetBlockPartfxArgs *args,
                                    int mode, int arg5, int arg6);

extern int ObjHits_GetPriorityHit(DfpTargetBlockObject *obj, DfpTargetBlockObject **hitObj,
                                  int *priority, int flags);
extern void Sfx_PlayFromObject(DfpTargetBlockObject *obj, u16 sfxId);
extern void Sfx_KeepAliveLoopedObjectSound(DfpTargetBlockObject *obj, u16 sfxId);
extern f32 sqrtf(f32 value);

extern int *gMapEventInterface;
extern int *gPartfxInterface;
extern f32 timeDelta;
extern f32 lbl_803DDCF8;
extern f32 lbl_803DDCFC;
extern f32 lbl_803E648C;
extern f32 lbl_803E6490;
extern f32 lbl_803E6494;
extern f32 lbl_803E6498;
extern f32 lbl_803E649C;
extern f32 lbl_803E64A0;
extern f32 lbl_803E64A4;
extern f32 lbl_803E64A8;
extern f32 lbl_803E64AC;
extern f32 lbl_803E64B0;
extern f32 lbl_803E64B4;
extern f32 lbl_803E64B8;
extern f32 lbl_803E64BC;
extern f32 lbl_803E64C0;

static void dfptargetblock_resetToHome(DfpTargetBlockObject *obj, DfpTargetBlockObject *home,
                                       DfpTargetBlockAudioState *state)
{
  f32 zero;

  obj->x = *(f32 *)((u8 *)home + 0x08);
  obj->z = *(f32 *)((u8 *)home + 0x10);
  zero = lbl_803E648C;
  obj->velX = zero;
  obj->velZ = zero;
  state->mode = DFPTARGETBLOCK_AUDIO_MODE_RESETTING;
  obj->y = *(f32 *)((u8 *)home + 0x0c) - lbl_803E64AC;
  Sfx_PlayFromObject(obj, 0x1d3);
}

static void dfptargetblock_checkSettled(DfpTargetBlockObject *obj, DfpTargetBlockAudioState *state,
                                        f32 threshold)
{
  f32 dx;
  f32 dz;

  dx = obj->x - lbl_803DDCF8;
  dz = obj->z - lbl_803DDCFC;
  if ((lbl_803E648C == dx) && (lbl_803E648C == dz)) {
    state->mode = DFPTARGETBLOCK_AUDIO_MODE_LOWERING;
  } else if (sqrtf(dx * dx + dz * dz) < threshold) {
    state->mode = DFPTARGETBLOCK_AUDIO_MODE_LOWERING;
  }
}

/*
 * --INFO--
 *
 * Function: dfptargetblock_hitDetect
 * EN v1.0 Address: 0x802086C4
 * EN v1.0 Size: 1196b
 * EN v1.1 Address: 0x802086D0
 * EN v1.1 Size: 348b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dfptargetblock_hitDetect(DfpTargetBlockObject *obj)
{
  DfpTargetBlockAudioState *state;
  DfpTargetBlockObject *home;
  DfpTargetBlockObject *hitObj;
  DfpTargetBlockPartfxArgs effect;
  int priority;
  int hitType;
  int mode;
  f32 velX;
  f32 velZ;
  f32 dx;
  f32 dz;
  int i;

  priority = -1;
  state = *(DfpTargetBlockAudioState **)((u8 *)obj + 0xb8);
  home = *(DfpTargetBlockObject **)((u8 *)obj + 0x4c);

  if (*(s16 *)((u8 *)obj + 0x46) == 0x4e0) {
    lbl_803DDCF8 = obj->x;
    lbl_803DDCFC = obj->z;
    return;
  }

  if ((state->completionSfxReady != 0) || (state->stateSfxReady == 0) ||
      (state->mode == DFPTARGETBLOCK_AUDIO_MODE_SETTLED) ||
      (state->mode == DFPTARGETBLOCK_AUDIO_MODE_LOWERING)) {
    return;
  }

  *(f32 *)((u8 *)obj + 0x80) = obj->x;
  *(f32 *)((u8 *)obj + 0x84) = obj->y;
  *(f32 *)((u8 *)obj + 0x88) = obj->z;

  hitObj = NULL;
  hitType = ObjHits_GetPriorityHit(obj, &hitObj, &priority, 0);
  if ((hitType != 0) && (hitObj != NULL) && (hitType == 0xe) && (hitType == 0xe)) {
    Sfx_PlayFromObject(obj, 0x44d);
    velX = hitObj->velX;
    velZ = hitObj->velZ;
    if (velX < lbl_803E648C) {
      velX *= lbl_803E6494;
    }
    if (velZ < lbl_803E648C) {
      velZ *= lbl_803E6494;
    }
    if (velX <= velZ) {
      hitObj->velX = lbl_803E648C;
    } else {
      hitObj->velZ = lbl_803E648C;
    }
    obj->velX = hitObj->velX * lbl_803E6498;
    obj->velZ = hitObj->velZ * lbl_803E6498;
  }

  obj->x = obj->velX * timeDelta + obj->x;
  obj->z = obj->velZ * timeDelta + obj->z;

  if (lbl_803E648C != obj->velX) {
    Sfx_KeepAliveLoopedObjectSound(obj, 0x3bd);
    velX = obj->velX;
    if (velX < lbl_803E648C) {
      if (velX >= lbl_803E648C) {
        obj->velX = lbl_803E648C;
      }
    } else if ((velX > lbl_803E648C) && (velX <= lbl_803E648C)) {
      obj->velX = lbl_803E648C;
    }
  }

  if (lbl_803E648C != obj->velZ) {
    Sfx_KeepAliveLoopedObjectSound(obj, 0x3bd);
    velZ = obj->velZ;
    if (velZ < lbl_803E648C) {
      if (velZ >= lbl_803E648C) {
        obj->velZ = lbl_803E648C;
      }
    } else if ((velZ > lbl_803E648C) && (velZ <= lbl_803E648C)) {
      obj->velZ = lbl_803E648C;
    }
  }

  dfptargetblock_resolveCollisionPoints(obj, (DfpTargetBlockCollisionPoints *)state);

  dx = *(f32 *)((u8 *)home + 0x08) - obj->x;
  dz = *(f32 *)((u8 *)home + 0x10) - obj->z;
  mode = ((MapEventGetModeFn)(*(u32 *)(*gMapEventInterface + 0x40)))((s8)*(u8 *)((u8 *)obj + 0xac));

  if (mode == 1) {
    if ((lbl_803E649C < dx) || (dx < lbl_803E64A0) || (dz < lbl_803E64A4) ||
        (lbl_803E64A8 < dz)) {
      dfptargetblock_resetToHome(obj, home, state);
    }
    dfptargetblock_checkSettled(obj, state, lbl_803E64B0);
  } else if (mode == 2) {
    if ((lbl_803E64B4 < dx) || (dx < lbl_803E64B8) || (dz < lbl_803E64A4) ||
        (lbl_803E64BC < dz)) {
      dfptargetblock_resetToHome(obj, home, state);

      effect.x = obj->x;
      effect.y = obj->y;
      effect.z = obj->z;
      effect.scale = lbl_803E6490;
      effect.rotZ = 0;
      effect.rotY = 0;
      effect.rotX = 0;

      for (i = 0; i < 0x14; i++) {
        ((PartfxSpawnObjectFn)(*(u32 *)(*gPartfxInterface + 0x8)))(obj, 0x5f5, &effect, 0x200001, -1,
                                                                  0);
      }
    }
    dfptargetblock_checkSettled(obj, state, lbl_803E64C0);
  }
}

#pragma peephole reset
#pragma scheduling reset
