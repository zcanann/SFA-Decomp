#ifndef MAIN_WORLDASTEROIDS_H_
#define MAIN_WORLDASTEROIDS_H_

#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"

#define WORLD_ASTEROIDS_CENTER_OBJECT_ID 0x42fe7
#define WORLD_ASTEROIDS_ORBIT_TILT_ANGLE 3000
#define WORLD_ASTEROIDS_ORBIT_STEP_SCALE 0x9c4
#define WORLD_ASTEROIDS_ROTATION_SPEED_MIN -300
#define WORLD_ASTEROIDS_ROTATION_SPEED_MAX 300

typedef struct WorldAsteroidsState
{
    s16 rotStepZ;
    s16 rotStepY;
    s16 rotStepX;
    s16 orbitAngle;
    s16 orbitRadius;
    s16 heightOffset;
} WorldAsteroidsState;

STATIC_ASSERT(sizeof(WorldAsteroidsState) == 0xC);
STATIC_ASSERT(offsetof(WorldAsteroidsState, rotStepZ) == 0x0);
STATIC_ASSERT(offsetof(WorldAsteroidsState, orbitAngle) == 0x6);
STATIC_ASSERT(offsetof(WorldAsteroidsState, orbitRadius) == 0x8);
STATIC_ASSERT(offsetof(WorldAsteroidsState, heightOffset) == 0xA);

extern ObjectDescriptor gWorldAsteroidsObjDescriptor;

int worldasteroids_getExtraSize(void);
int worldasteroids_getObjectTypeId(void);
void worldasteroids_free(void);
void worldasteroids_render(GameObject* obj, u32 param_2, u32 param_3, u32 param_4, u32 param_5, s8 visible);
void worldasteroids_hitDetect(void);
void worldasteroids_update(GameObject* obj);
void worldasteroids_init(GameObject* obj);
void worldasteroids_release(void);
void worldasteroids_initialise(void);

#endif /* MAIN_WORLDASTEROIDS_H_ */
