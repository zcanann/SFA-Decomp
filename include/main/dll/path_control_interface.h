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
} PathControlInterface;

extern PathControlInterface **gPathControlInterface;

STATIC_ASSERT(offsetof(PathControlInterface, init) == 0x04);
STATIC_ASSERT(offsetof(PathControlInterface, setLocalPointCollision) == 0x08);
STATIC_ASSERT(offsetof(PathControlInterface, setup) == 0x0C);
STATIC_ASSERT(offsetof(PathControlInterface, update) == 0x10);
STATIC_ASSERT(offsetof(PathControlInterface, apply) == 0x14);
STATIC_ASSERT(offsetof(PathControlInterface, advance) == 0x18);
STATIC_ASSERT(offsetof(PathControlInterface, attachObject) == 0x20);

#endif /* MAIN_DLL_PATH_CONTROL_INTERFACE_H_ */
