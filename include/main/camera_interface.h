#ifndef MAIN_CAMERA_INTERFACE_H_
#define MAIN_CAMERA_INTERFACE_H_

#include "global.h"

typedef int (*CameraGetModeFn)(void);
typedef void (*CameraSetModeFn)(int mode, int arg1, int arg2, int flags, void *params,
                                int blendFrames, int priority);

typedef struct CameraInterface {
    u8 pad00[0x10];
    CameraGetModeFn getMode;
    u8 pad14[0x1C - 0x14];
    CameraSetModeFn setMode;
} CameraInterface;

STATIC_ASSERT(offsetof(CameraInterface, getMode) == 0x10);
STATIC_ASSERT(offsetof(CameraInterface, setMode) == 0x1C);

extern CameraInterface **gCameraInterface;

#endif /* MAIN_CAMERA_INTERFACE_H_ */
