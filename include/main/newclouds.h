#ifndef MAIN_NEWCLOUDS_H_
#define MAIN_NEWCLOUDS_H_

#include "ghidra_import.h"
#include "main/lightningeffect.h"
#include "main/vec_types.h"

struct GameObject;

typedef void (*NewCloudsUpdateEnvfxActFn)(void* sourceObj, void* targetObj, void* entry, int flags);
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
LightningEffect* lightningCreate(const Vec3f* start, const Vec3f* end, f32 radiusX, f32 radiusY, u16 lifetime,
                                 u8 width, u8 flags);
void lightningRender(LightningEffect* effect);
void initSkyStars(void);
void drawSkyStars(void);
void cloudClearOverridePosition(void);
void cloudSetOverridePosition(f32 x, f32 y, f32 z);
void lightningRenderActive(void);

#endif /* MAIN_NEWCLOUDS_H_ */
