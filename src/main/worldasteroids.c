#include "ghidra_import.h"

extern u32 randomGetRange(int min,int max);
extern u8 *ObjList_FindObjectById(int objectId);
extern void objRenderFn_8003b8f4(double scale);
extern f32 fsin16Approx(int angle);
extern f32 fcos16Approx(int angle);

extern f32 lbl_803E65D0;
extern f64 lbl_803E65D8;
extern f32 lbl_803E65E0;
extern f32 lbl_803E65E4;
extern f32 lbl_803E65E8;
extern f32 lbl_803E65EC;
extern f32 lbl_803E65F0;

typedef struct WorldAsteroidsState {
  s16 velocityZ;
  s16 velocityY;
  s16 velocityX;
  s16 orbitAngle;
  s16 orbitRadius;
  s16 heightOffset;
} WorldAsteroidsState;

static inline WorldAsteroidsState *worldasteroids_getState(u8 *obj)
{
  return *(WorldAsteroidsState **)(obj + 0xb8);
}

static inline f32 worldasteroids_s32AsFloat(s32 value)
{
  return (f32)(s32)value;
}

int worldasteroids_getExtraSize(void)
{
  return sizeof(WorldAsteroidsState);
}

int worldasteroids_func08(void)
{
  return 0;
}

void worldasteroids_free(void)
{
  return;
}

#pragma peephole off
void worldasteroids_render(undefined4 param_1,undefined4 param_2,undefined4 param_3,
                           undefined4 param_4,undefined4 param_5,s8 visible)
{
  s32 v = visible;
  if (v != 0) {
    objRenderFn_8003b8f4(lbl_803E65D0);
  }
}
#pragma peephole reset

void worldasteroids_hitDetect(void)
{
  return;
}

#pragma scheduling off
#pragma peephole off
void worldasteroids_update(s16 *obj)
{
  u8 *anchor;
  WorldAsteroidsState *state;
  f32 orbitScale;
  f32 orbitSin;
  f32 orbitCos;
  f32 radius;

  state = *(WorldAsteroidsState **)(obj + 0x5c);
  anchor = ObjList_FindObjectById(0x42fe7);
  obj[0] += state->velocityX;
  obj[1] += state->velocityY;
  obj[2] += state->velocityZ;
  state->orbitAngle += 0x9c4 / state->orbitRadius;
  orbitCos = fcos16Approx(3000);
  orbitSin = fsin16Approx((u16)state->orbitAngle);
  radius = worldasteroids_s32AsFloat(state->orbitRadius);
  orbitScale = radius * orbitSin;
  *(f32 *)(obj + 6) = orbitScale * orbitCos + *(f32 *)(anchor + 0xc);
  orbitSin = fsin16Approx(3000);
  orbitScale = fsin16Approx((u16)state->orbitAngle);
  orbitScale = worldasteroids_s32AsFloat(state->orbitRadius) * orbitScale;
  *(f32 *)(obj + 8) =
      orbitScale * orbitSin + (*(f32 *)(anchor + 0x10) +
                               worldasteroids_s32AsFloat(state->heightOffset));
  orbitCos = fcos16Approx((u16)state->orbitAngle);
  *(f32 *)(obj + 10) =
      worldasteroids_s32AsFloat(state->orbitRadius) * orbitCos + *(f32 *)(anchor + 0x14);
  return;
}

#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void worldasteroids_init(u8 *obj)
{
  int baseAngle;
  s16 randomValue;
  WorldAsteroidsState *state;
  f32 orbitShape;
  int radiusSeed;

  state = worldasteroids_getState(obj);
  baseAngle = randomGetRange(-0x7fff,0x7fff);
  orbitShape = fsin16Approx((u16)baseAngle);
  if (orbitShape < lbl_803E65E0) {
    orbitShape = -fsin16Approx((u16)baseAngle);
  }
  else {
    orbitShape = fsin16Approx((u16)baseAngle);
  }
  randomGetRange(0,(int)(lbl_803E65E8 * orbitShape + lbl_803E65E4));
  orbitShape = fsin16Approx((u16)baseAngle);
  if (orbitShape < lbl_803E65E0) {
    orbitShape = -fsin16Approx((u16)baseAngle);
  }
  else {
    orbitShape = fsin16Approx((u16)baseAngle);
  }
  radiusSeed = (int)(lbl_803E65EC * orbitShape);
  randomValue = randomGetRange(-300,300);
  state->velocityZ = randomValue;
  randomValue = randomGetRange(-300,300);
  state->velocityY = randomValue;
  randomValue = randomGetRange(-300,300);
  state->velocityX = randomValue;
  randomValue = randomGetRange(-0x7fff,0x7fff);
  state->orbitAngle = randomValue;
  state->orbitRadius =
      worldasteroids_s32AsFloat(radiusSeed) * fsin16Approx((u16)baseAngle) + lbl_803E65F0;
  state->heightOffset =
      worldasteroids_s32AsFloat(radiusSeed) * fcos16Approx((u16)baseAngle);
  return;
}
#pragma peephole reset
#pragma scheduling reset

void worldasteroids_release(void)
{
  return;
}

void worldasteroids_initialise(void)
{
  return;
}
