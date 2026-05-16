#include "ghidra_import.h"

typedef struct WorldAsteroidsObject WorldAsteroidsObject;

extern u32 randomGetRange(int min,int max);
extern WorldAsteroidsObject *ObjList_FindObjectById(int objectId);
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

#define WORLD_ASTEROIDS_CENTER_OBJECT_ID 0x42fe7
#define WORLD_ASTEROIDS_ORBIT_TILT_ANGLE 3000
#define WORLD_ASTEROIDS_ORBIT_STEP_SCALE 0x9c4
#define WORLD_ASTEROIDS_ROTATION_SPEED_MIN -300
#define WORLD_ASTEROIDS_ROTATION_SPEED_MAX 300

typedef struct WorldAsteroidsState {
  s16 rotStepZ;
  s16 rotStepY;
  s16 rotStepX;
  s16 orbitAngle;
  s16 orbitRadius;
  s16 heightOffset;
} WorldAsteroidsState;

struct WorldAsteroidsObject {
  s16 rotX;
  s16 rotY;
  s16 rotZ;
  u8 pad006[6];
  f32 posX;
  f32 posY;
  f32 posZ;
  u8 pad018[0xb8 - 0x18];
  WorldAsteroidsState *state;
};

static inline WorldAsteroidsState *worldasteroids_getState(WorldAsteroidsObject *obj)
{
  return obj->state;
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
void worldasteroids_update(WorldAsteroidsObject *obj)
{
  WorldAsteroidsObject *anchor;
  WorldAsteroidsState *state;
  f32 orbitScale;
  f32 orbitSin;
  f32 orbitCos;
  f32 radius;

  state = obj->state;
  anchor = ObjList_FindObjectById(WORLD_ASTEROIDS_CENTER_OBJECT_ID);
  obj->rotX += state->rotStepX;
  obj->rotY += state->rotStepY;
  obj->rotZ += state->rotStepZ;
  state->orbitAngle += WORLD_ASTEROIDS_ORBIT_STEP_SCALE / state->orbitRadius;
  orbitCos = fcos16Approx(WORLD_ASTEROIDS_ORBIT_TILT_ANGLE);
  orbitSin = fsin16Approx((u16)state->orbitAngle);
  radius = worldasteroids_s32AsFloat(state->orbitRadius);
  orbitScale = radius * orbitSin;
  obj->posX = orbitScale * orbitCos + anchor->posX;
  orbitSin = fsin16Approx(WORLD_ASTEROIDS_ORBIT_TILT_ANGLE);
  orbitScale = fsin16Approx((u16)state->orbitAngle);
  radius = worldasteroids_s32AsFloat(state->orbitRadius);
  orbitScale = radius * orbitScale;
  obj->posY = orbitScale * orbitSin + (anchor->posY +
                                       worldasteroids_s32AsFloat(state->heightOffset));
  orbitCos = fcos16Approx((u16)state->orbitAngle);
  radius = worldasteroids_s32AsFloat(state->orbitRadius);
  obj->posZ = radius * orbitCos + anchor->posZ;
  return;
}

#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void worldasteroids_init(WorldAsteroidsObject *obj)
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
  randomValue = randomGetRange(WORLD_ASTEROIDS_ROTATION_SPEED_MIN,WORLD_ASTEROIDS_ROTATION_SPEED_MAX);
  state->rotStepZ = randomValue;
  randomValue = randomGetRange(WORLD_ASTEROIDS_ROTATION_SPEED_MIN,WORLD_ASTEROIDS_ROTATION_SPEED_MAX);
  state->rotStepY = randomValue;
  randomValue = randomGetRange(WORLD_ASTEROIDS_ROTATION_SPEED_MIN,WORLD_ASTEROIDS_ROTATION_SPEED_MAX);
  state->rotStepX = randomValue;
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

u32 gWorldAsteroidsObjDescriptor[] = {
    0,
    0,
    0,
    0x00090000,
    (u32)worldasteroids_initialise,
    (u32)worldasteroids_release,
    0,
    (u32)worldasteroids_init,
    (u32)worldasteroids_update,
    (u32)worldasteroids_hitDetect,
    (u32)worldasteroids_render,
    (u32)worldasteroids_free,
    (u32)worldasteroids_func08,
    (u32)worldasteroids_getExtraSize,
};
