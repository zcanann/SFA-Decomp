#ifndef MAIN_NEWCLOUDS_H_
#define MAIN_NEWCLOUDS_H_

#include "ghidra_import.h"
#include "main/lightningeffect.h"
#include "main/vec_types.h"

struct GameObject;

typedef void (*NewCloudsUpdateEnvfxActFn)(struct GameObject* sourceObj, struct GameObject* targetObj, void* entry,
                                          int flags);
typedef void (*NewCloudsOnMapSetupFn)(void);
typedef void (*NewCloudsKillSnowCloudFn)(int cloudId, int flag);
typedef void (*NewCloudsRunFn)(void);
typedef void (*NewCloudsRenderSnowCloudsFn)(int renderPass);
typedef int (*NewCloudsIsSnowCloudActiveFn)(void);
typedef void (*NewCloudsFunc09Fn)(void);
typedef void (*NewCloudsFunc0ANopFn)(int unused);

typedef struct NewCloudsInterface {
    void *unused00;
    NewCloudsUpdateEnvfxActFn updateEnvfxAct;
    NewCloudsOnMapSetupFn onMapSetup;
    NewCloudsKillSnowCloudFn killSnowCloud;
    NewCloudsRunFn run;
    NewCloudsRenderSnowCloudsFn renderSnowClouds;
    NewCloudsIsSnowCloudActiveFn isSnowCloudActive;
    NewCloudsFunc09Fn func09;
    NewCloudsFunc0ANopFn func0ANop;
} NewCloudsInterface;

STATIC_ASSERT(offsetof(NewCloudsInterface, updateEnvfxAct) == 0x04);
STATIC_ASSERT(offsetof(NewCloudsInterface, onMapSetup) == 0x08);
STATIC_ASSERT(offsetof(NewCloudsInterface, killSnowCloud) == 0x0C);
STATIC_ASSERT(offsetof(NewCloudsInterface, run) == 0x10);
STATIC_ASSERT(offsetof(NewCloudsInterface, renderSnowClouds) == 0x14);
STATIC_ASSERT(offsetof(NewCloudsInterface, isSnowCloudActive) == 0x18);
STATIC_ASSERT(offsetof(NewCloudsInterface, func09) == 0x1C);
STATIC_ASSERT(offsetof(NewCloudsInterface, func0ANop) == 0x20);

extern NewCloudsInterface **gNewCloudsInterface;


/* extern-cleanup: defining-file public prototypes */
void mm_free_(void* ptr);
LightningEffect* lightningCreate(const Vec3f* start, const Vec3f* end, f32 radiusX, f32 radiusY, s16 lifetime,
                                 u8 width, u8 flags);
void lightningRender(LightningEffect* effect);

/* Compiler-sensitive call views retained for TUs that originally called without the narrow parameter prototype. */
#define lightningCreatePromoted(start, end, radiusX, radiusY, lifetime, width, flags) \
    (((LightningEffect* (*)(const Vec3f*, const Vec3f*, f32, f32, int, int, int))lightningCreate)( \
        (start), (end), (radiusX), (radiusY), (lifetime), (width), (flags)))
#define lightningCreateU16Promoted(start, end, radiusX, radiusY, lifetime, width, flags) \
    (((LightningEffect* (*)(const Vec3f*, const Vec3f*, f32, f32, u16, int, int))lightningCreate)( \
        (start), (end), (radiusX), (radiusY), (lifetime), (width), (flags)))
#define lightningRenderLegacy(effect) (((void (*)(void*))lightningRender)((void*)(effect)))
void titleScreenDrawFn_80093db4(void);
void drawSkyStars(void);
void cloudClearOverridePosition(void);
void cloudSetOverridePosition(f32 x, f32 y, f32 z);

#endif /* MAIN_NEWCLOUDS_H_ */
