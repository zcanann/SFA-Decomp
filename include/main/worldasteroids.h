#ifndef MAIN_WORLDASTEROIDS_H_
#define MAIN_WORLDASTEROIDS_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

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

typedef struct WorldAsteroidsObject {
  s16 rotX;
  s16 rotY;
  s16 rotZ;
  u8 pad006[6];
  f32 posX;
  f32 posY;
  f32 posZ;
  u8 pad018[0xb8 - 0x18];
  WorldAsteroidsState *state;
} WorldAsteroidsObject;

extern ObjectDescriptor gWorldAsteroidsObjDescriptor;

int worldasteroids_getExtraSize(void);
int worldasteroids_func08(void);
void worldasteroids_free(void);
void worldasteroids_render(undefined4 param_1,undefined4 param_2,undefined4 param_3,
                           undefined4 param_4,undefined4 param_5,s8 visible);
void worldasteroids_hitDetect(void);
void worldasteroids_update(WorldAsteroidsObject *obj);
void worldasteroids_init(WorldAsteroidsObject *obj);
void worldasteroids_release(void);
void worldasteroids_initialise(void);

#endif /* MAIN_WORLDASTEROIDS_H_ */
