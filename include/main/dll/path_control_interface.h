#ifndef MAIN_DLL_PATH_CONTROL_INTERFACE_H_
#define MAIN_DLL_PATH_CONTROL_INTERFACE_H_

#include "global.h"

typedef void (*PathControlInitFn)(void *pathState, int mode, int flags, int arg);
typedef void (*PathControlSetLocalPointCollisionFn)(void *pathState, int pointCount,
                                                    void *points, void *params, int stride);
typedef void (*PathControlSetupFn)(void *pathState, int pointCount, void *pathDataA, void *pathDataB,
                                   void *pathParam);
typedef void (*PathControlStepFn)(void *obj, void *pathState, f32 delta);
typedef void (*PathControlApplyFn)(void *obj, void *pathState);
typedef f32 (*PathControlSampleHeightFn)(void *obj, f32 x, f32 y, f32 z, f32 radius);

typedef struct PathControlInterface {
  void *slot00;
  PathControlInitFn init;
  PathControlSetLocalPointCollisionFn setLocalPointCollision;
  PathControlSetupFn setup;
  PathControlStepFn update;
  PathControlApplyFn apply;
  PathControlStepFn advance;
  void *slot1C;
  PathControlApplyFn attachObject;
  PathControlSampleHeightFn sampleHeight;
} PathControlInterface;

extern PathControlInterface **gPathControlInterface;

STATIC_ASSERT(offsetof(PathControlInterface, init) == 0x04);
STATIC_ASSERT(offsetof(PathControlInterface, setLocalPointCollision) == 0x08);
STATIC_ASSERT(offsetof(PathControlInterface, setup) == 0x0C);
STATIC_ASSERT(offsetof(PathControlInterface, update) == 0x10);
STATIC_ASSERT(offsetof(PathControlInterface, apply) == 0x14);
STATIC_ASSERT(offsetof(PathControlInterface, advance) == 0x18);
STATIC_ASSERT(offsetof(PathControlInterface, attachObject) == 0x20);
STATIC_ASSERT(offsetof(PathControlInterface, sampleHeight) == 0x24);


/* extern-cleanup: consolidated prototypes */
void walkPath_writeU16LE(int pathId, u8* out);
int fn_8004B218(void* search, int timeout);

#endif /* MAIN_DLL_PATH_CONTROL_INTERFACE_H_ */
