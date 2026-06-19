#ifndef MAIN_CAMERA_INTERFACE_H_
#define MAIN_CAMERA_INTERFACE_H_

#include "global.h"

typedef int (*CameraGetModeFn)(void);
typedef void *(*CameraGetFn)(void);
typedef void (*CameraSetModeFn)(int mode, int arg1, int arg2, int flags, void *params,
                                int blendFrames, int priority);
typedef void (*CameraUpdateFn)(u8 framesThisStep);
typedef void (*CameraLoadTriggeredActionFn)(int triggerType, int actionNo, int triggerMode);
typedef void (*CameraSetFocusFn)(void *target, int unused);
typedef void (*CameraOverridePosFn)(f32 x, f32 y, f32 z);
typedef void (*CameraMoveByFn)(f32 x, f32 y, f32 z);
typedef void (*CameraSetTargetReticleOverrideFn)(int target);
typedef void (*CameraInitialiseFn)(f32 *dst, f32 numerator, f32 denominator, f32 minValue,
                                   f32 y, f32 z);
typedef void (*CameraGetRelativePositionFn)(f32 heightOffset, int targetObj, f32 *outX,
                                            f32 *outY, f32 *outZ, f32 *outDistanceXZ,
                                            int useLocalPosition);
typedef int (*CameraGetTargetFn)(void);
typedef void (*CameraSetTargetFn)(int target);
typedef void (*CameraUpdateTargetFeedbackFn)(void);
typedef void (*CameraSetLetterboxFn)(int mode, int enabled);
typedef void (*CameraReleaseActionFn)(void *camAction, int recordSize);
typedef void (*CameraFunc1DFn)(u8 value);

typedef struct CameraInterface {
    u8 pad00[0x04];
    void (*init)(void *focus, f32 x, f32 y, f32 z);
    CameraUpdateFn update;
    CameraGetFn getCamera;
    CameraGetModeFn getMode;
    void *(*getCurrentHandler)(void);
    void *(*getDefaultHandlerEntry)(void);
    CameraSetModeFn setMode;
    void *(*getCamActionsBinEntry)(int actionNo);
    CameraLoadTriggeredActionFn loadTriggeredCamAction;
    CameraSetFocusFn setFocus;
    CameraOverridePosFn overridePos;
    CameraMoveByFn moveBy;
    CameraInitialiseFn initialise;
    CameraGetRelativePositionFn getRelativePosition;
    CameraGetTargetFn getOverrideTarget;
    CameraGetTargetFn getTarget;
    void (*func13)(void);
    CameraSetTargetFn setTarget;
    CameraSetTargetReticleOverrideFn setTargetReticleOverride;
    int (*isZooming)(void);
    CameraUpdateTargetFeedbackFn updateTargetFeedback;
    void (*minimapShowHelpTextForTarget)(int textId, int arg1, int arg2, int arg3);
    CameraSetLetterboxFn setLetterbox;
    CameraReleaseActionFn releaseAction;
    int (*getMinimapInfoText)(void);
    void (*func1C)(void);
    CameraFunc1DFn func1D;
} CameraInterface;

STATIC_ASSERT(offsetof(CameraInterface, getCamera) == 0x0C);
STATIC_ASSERT(offsetof(CameraInterface, getMode) == 0x10);
STATIC_ASSERT(offsetof(CameraInterface, setMode) == 0x1C);
STATIC_ASSERT(offsetof(CameraInterface, loadTriggeredCamAction) == 0x24);
STATIC_ASSERT(offsetof(CameraInterface, setFocus) == 0x28);
STATIC_ASSERT(offsetof(CameraInterface, getRelativePosition) == 0x38);
STATIC_ASSERT(offsetof(CameraInterface, setTarget) == 0x48);
STATIC_ASSERT(offsetof(CameraInterface, setTargetReticleOverride) == 0x4C);
STATIC_ASSERT(offsetof(CameraInterface, updateTargetFeedback) == 0x54);
STATIC_ASSERT(offsetof(CameraInterface, setLetterbox) == 0x5C);
STATIC_ASSERT(offsetof(CameraInterface, releaseAction) == 0x60);
STATIC_ASSERT(offsetof(CameraInterface, func1D) == 0x6C);

extern CameraInterface **gCameraInterface;


/* extern-cleanup: consolidated prototypes */
void Pause_ResetMenuFrameCounter(void);
void setShadowFlag_803db658(int v);
void Obj_ResetObjectSystem(void);

#endif /* MAIN_CAMERA_INTERFACE_H_ */
