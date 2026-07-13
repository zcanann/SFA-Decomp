#ifndef MAIN_DLL_CLOUDACTION_INTERFACE_H_
#define MAIN_DLL_CLOUDACTION_INTERFACE_H_

#include "global.h"

struct GameObject;

typedef void (*CloudActionUpdateFn)(struct GameObject* source, struct GameObject* target,
                                    void* entry, int flags, u16 idx);
typedef void (*CloudActionOnMapSetupFn)(void);
typedef void (*CloudActionScrollTextureFn)(void);
typedef void (*CloudActionRenderFn)(int a, int b, int c, int d);
typedef void (*CloudActionFreeFn)(void);
typedef void (*CloudActionFunc08NopFn)(f32 x, f32 y, f32 z, int intensity);
typedef void (*CloudActionFunc09NopFn)(int enabled);
typedef void (*CloudActionFunc10NopFn)(int value);
typedef void (*CloudActionFunc11NopFn)(int value);
typedef void (*CloudActionFunc12NopFn)(f32 a, f32 b);

typedef struct CloudActionInterface {
    u8 pad00[0x04];
    CloudActionUpdateFn updateEnvfxAct;
    CloudActionOnMapSetupFn onMapSetup;
    CloudActionScrollTextureFn scrollTexture;
    CloudActionRenderFn renderClouds;
    CloudActionFreeFn freeCloudObjects;
    CloudActionFunc08NopFn func08Nop;
    CloudActionFunc09NopFn func09Nop;
    CloudActionFunc10NopFn func10Nop;
    CloudActionFunc11NopFn func11Nop;
    CloudActionFunc12NopFn func12Nop;
} CloudActionInterface;

STATIC_ASSERT(offsetof(CloudActionInterface, updateEnvfxAct) == 0x04);
STATIC_ASSERT(offsetof(CloudActionInterface, onMapSetup) == 0x08);
STATIC_ASSERT(offsetof(CloudActionInterface, scrollTexture) == 0x0C);
STATIC_ASSERT(offsetof(CloudActionInterface, renderClouds) == 0x10);
STATIC_ASSERT(offsetof(CloudActionInterface, freeCloudObjects) == 0x14);
STATIC_ASSERT(offsetof(CloudActionInterface, func08Nop) == 0x18);
STATIC_ASSERT(offsetof(CloudActionInterface, func09Nop) == 0x1C);
STATIC_ASSERT(offsetof(CloudActionInterface, func10Nop) == 0x20);
STATIC_ASSERT(offsetof(CloudActionInterface, func11Nop) == 0x24);
STATIC_ASSERT(offsetof(CloudActionInterface, func12Nop) == 0x28);

extern CloudActionInterface** gCloudActionInterface;

#endif /* MAIN_DLL_CLOUDACTION_INTERFACE_H_ */
