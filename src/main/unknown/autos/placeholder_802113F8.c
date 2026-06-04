#include "ghidra_import.h"
#include "main/proximitymine.h"

extern void lightFn_8001d6b0(void *light);
extern int fn_80080150(void *timer);
extern int timerCountDown(void *timer);
extern int objUpdateOpacity(void *obj);
extern int ObjPath_GetPointWorldPosition(void *obj, int idx, f32 *x, f32 *y, f32 *z, int p6);
extern int hitDetectFn_800658a4(void *obj, f32 x, f32 y, f32 z, f32 *out, int flag);
extern void Sfx_PlayFromObject(void *obj, u16 sfxId);
extern void Sfx_StopObjectChannel(void *obj, int channel);
extern ProximityMineEffect *fn_8001CC9C(void *obj, int r, int g, int b, int a);
extern int *objFindTexture(void *obj, int a, int b);
extern void fn_8001D730(void *light, int a, int b, int c, int d, u8 e, f32 f);
extern void lightVecFn_8001dd88(void *light, f32 x, f32 y, f32 z);
extern void *Obj_GetPlayerObject(void);
extern f32 Vec_distance(f32 *a, f32 *b);
extern f32 Vec_xzDistance(f32 *a, f32 *b);
extern f32 sqrtf(f32 x);
extern void mathFn_80021ac8(void *params, f32 *vec);
extern void Obj_FreeObject(void *obj);
extern void ObjHits_EnableObject(void *obj);
extern void ObjHits_SetHitVolumeSlot(void *obj, int p2, int p3, int p4);
extern void storeZeroToFloatParam(void *timer);
extern void s16toFloat(void *timer, int duration);
extern int objPosToMapBlockIdx(double x, double y, double z);
extern int *gPartfxInterface;

extern f32 timeDelta;
extern u8 framesThisStep;
extern f32 lbl_803DC234;
extern u8 lbl_803DC238;
extern f32 lbl_803DC23C;
extern u8 lbl_803DC240;
extern f32 lbl_803DC244;
extern f32 lbl_803DC248;
extern f32 lbl_803E6768;
extern f32 lbl_803E6778;
extern f32 lbl_803E677C;
extern f32 lbl_803E6780;
extern f32 lbl_803E6784;
extern f32 lbl_803E6788;

typedef struct MineLaunchParams {
  s16 angle;
  s16 unk2;
  s16 unk4;
  f32 scale;
  f32 x;
  f32 y;
  f32 z;
} MineLaunchParams;

#pragma scheduling off
#pragma peephole off
void proximitymine_update(ProximityMineObject *obj)
{
  f32 groundY;
  MineLaunchParams params;
  ProximityMineState *state;

  state = obj->state;
  if (state->effectHandle != NULL) {
    lightFn_8001d6b0(state->effectHandle);
  }
  if (obj->pendingTarget != NULL) {
    state->targetObj = obj->pendingTarget;
    obj->pendingTarget = NULL;
  }
  if (fn_80080150(state->lifespanTimer) != 0) {
    obj->height += state->verticalStep * timeDelta;
    if (state->targetObj != NULL) {
      if (objUpdateOpacity(state->targetObj) != 0) {
        ObjPath_GetPointWorldPosition(state->targetObj, obj->pathIndex, &obj->posX, &obj->posY,
                                      &obj->posZ, 0);
      } else {
        obj->posX = ((ProximityMineObject *)state->targetObj)->posX;
        obj->posY = ((ProximityMineObject *)state->targetObj)->posY;
        obj->posZ = ((ProximityMineObject *)state->targetObj)->posZ;
      }
    }
    if (timerCountDown(state->lifespanTimer) != 0) {
      if (state->mode == 2) {
        hitDetectFn_800658a4(obj, obj->posX, obj->posY, obj->posZ, &groundY, 0);
        obj->posY -= groundY;
        Sfx_PlayFromObject(obj, 0x2e6);
        Sfx_PlayFromObject(obj, 0x2e8);
      } else {
        Sfx_PlayFromObject(obj, 0x2e7);
        Sfx_PlayFromObject(obj, 0x2e9);
      }
    }
    if (state->effectHandle == NULL) {
      int brightness;
      int *tex;

      state->effectHandle = fn_8001CC9C(obj, 0xff, 0, 0, 0);
      tex = objFindTexture(obj, 0, 0);
      if (tex != NULL) {
        *tex = (*tex + 0x10) % 512;
        brightness = *tex >> 8;
      } else {
        brightness = 0;
      }
      if (state->effectHandle != NULL) {
        state->effectHandle->visible = brightness;
        fn_8001D730(state->effectHandle, 0, 0xff, 0, 0, lbl_803DC238, lbl_803DC234);
        {
          ProximityMineEffect *fx = state->effectHandle;
          lightVecFn_8001dd88(fx, lbl_803E6768, obj->unkA8, lbl_803E6768);
        }
      }
    }
  } else {
    if (fn_80080150(state->resetTimer) != 0) {
      Sfx_PlayFromObject(obj, 0xef);
      if (state->effectHandle == NULL) {
        state->effectHandle = fn_8001CC9C(obj, 0xff, 0, 0, 0);
        if (state->effectHandle != NULL) {
          fn_8001D730(state->effectHandle, 0, 0xff, 0, 0, lbl_803DC240, lbl_803DC23C);
          {
            ProximityMineEffect *fx = state->effectHandle;
            lightVecFn_8001dd88(fx, lbl_803E6768, obj->unkA8, lbl_803E6768);
          }
        }
      }
      if (timerCountDown(state->resetTimer) != 0) {
        proximitymine_resetToIdle(obj);
        return;
      }
    }
    switch (state->mode) {
    case 3: {
      f32 trigger;
      ProximityMineObject *player;

      trigger = (f32)obj->def->parameter;
      player = Obj_GetPlayerObject();
      if (Vec_distance(&obj->prevX, &player->prevX) < trigger) {
        state->mode = 2;
        s16toFloat(state->resetTimer, 0x78);
      }
      break;
    }
    case 0:
      Sfx_StopObjectChannel(obj, 0x40);
      if (timerCountDown(state->renderTimer) != 0) {
        Obj_FreeObject(obj);
        return;
      }
      break;
    case -1: {
      f32 dist;
      f32 zero;
      ProximityMineObject *player;

      player = Obj_GetPlayerObject();
      dist = Vec_xzDistance(&obj->prevX, &player->prevX);
      state->mode = 1;
      obj->velocityX = lbl_803E6768;
      obj->velocityY = sqrtf(dist) / lbl_803DC244 + lbl_803E677C * lbl_803DC248;
      obj->velocityZ = lbl_803E6780 * lbl_803DC248 - sqrtf(dist) / lbl_803DC244;
      zero = lbl_803E6768;
      params.x = zero;
      params.y = zero;
      params.z = zero;
      params.scale = lbl_803E6778;
      params.unk4 = 0;
      params.unk2 = 0;
      params.angle = obj->angle;
      mathFn_80021ac8(&params, &obj->velocityX);
      Sfx_PlayFromObject(obj, 0xf0);
    }
    case 1:
      if (timerCountDown(state->launchTimer) != 0) {
        f32 zero;

        state = obj->state;
        zero = lbl_803E6768;
        obj->velocityY = zero;
        obj->velocityX = zero;
        obj->velocityZ = zero;
        state->mode = 0;
        storeZeroToFloatParam(state->resetTimer);
        s16toFloat(state->resetTimer, 1);
        s16toFloat(state->renderTimer, 10);
        return;
      }
      if (obj->velocityY > lbl_803E6784) {
        obj->velocityY += lbl_803E6788 * timeDelta;
      }
      obj->angle += framesThisStep << 10;
      obj->angle2 += framesThisStep * 0x700;
      obj->posX += obj->velocityX * timeDelta;
      obj->posY += obj->velocityY * timeDelta;
      obj->posZ += obj->velocityZ * timeDelta;
      obj->prevX = obj->posX;
      obj->prevY = obj->posY;
      obj->prevZ = obj->posZ;
    case 2:
      (*(void (*)(int *, int, int, int, int, int))(*(int *)(*gPartfxInterface + 0x8)))(
          (int *)obj, 0x51c, 0, 1, -1, 0);
      if (timerCountDown(state->bounceTimer) != 0) {
        ObjHits_EnableObject(obj);
      }
      ObjHits_SetHitVolumeSlot(obj, 13, 1, 0);
      if (state->effectHandle != NULL) {
        if ((state->effectHandle->visible != 0) && (state->effectVisible == 0)) {
          Sfx_PlayFromObject(obj, 0x42e);
        }
        state->effectVisible = state->effectHandle->visible;
      } else {
        state->effectVisible = 0;
      }
      break;
    }
    if (fn_80080150(state->renderTimer) == 0) {
      if (objPosToMapBlockIdx((double)obj->posX, (double)obj->posY, (double)obj->posZ) == -1) {
        f32 zero;

        state = obj->state;
        zero = lbl_803E6768;
        obj->velocityY = zero;
        obj->velocityX = zero;
        obj->velocityZ = zero;
        state->mode = 0;
        storeZeroToFloatParam(state->resetTimer);
        s16toFloat(state->resetTimer, 1);
        s16toFloat(state->renderTimer, 10);
      }
    }
  }
}
#pragma peephole reset
#pragma scheduling reset
