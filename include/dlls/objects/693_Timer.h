#ifndef DLLS_OBJECTS_693_TIMER_H_
#define DLLS_OBJECTS_693_TIMER_H_

#include "global.h"
#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"

struct ModelLightStruct;

#define TIMER_OBJECT_GROUP 0x4C

typedef struct TimerFlags {
    u8 ended : 1;                /* Latched by cancellation or natural expiry. */
    u8 startOverride : 1;        /* Starts the timer and bypasses start-bit cancellation. */
    u8 previousGlowPhaseBit : 1; /* Low bit of the previous textureId >> 8 phase. */
    u8 unknown : 5;
} TimerFlags;

/* Reader prefix through +0x21. EN serialized extent is not established;
 * secondary EN rev1 / JP records are 0x24 bytes. Never use this reader's
 * sizeof for placement allocation or copying. */
typedef struct TimerPlacementPrefix {
    ObjPlacement base;
    u8 unknown18;
    u8 mode;
    s16 durationSeconds;
    u8 unknown1C[2];
    s16 expiredGameBit;
    s16 startGameBit;
} TimerPlacementPrefix;

/* timer_getExtraSize requests 0x20 bytes. */
typedef struct TimerState {
    f32 remainingFrames;
    struct ModelLightStruct* lightSlot;
    f32 initialized08;
    u8 mode;
    TimerFlags flags;
    u8 unknown0E[0x20 - 0x0E];
} TimerState;

STATIC_ASSERT(offsetof(TimerPlacementPrefix, mode) == 0x19);
STATIC_ASSERT(offsetof(TimerPlacementPrefix, durationSeconds) == 0x1A);
STATIC_ASSERT(offsetof(TimerPlacementPrefix, expiredGameBit) == 0x1E);
STATIC_ASSERT(offsetof(TimerPlacementPrefix, startGameBit) == 0x20);
STATIC_ASSERT(offsetof(TimerPlacementPrefix, base) == 0x00);
STATIC_ASSERT(offsetof(TimerPlacementPrefix, unknown18) == 0x18);
STATIC_ASSERT(offsetof(TimerPlacementPrefix, unknown1C) == 0x1C);
STATIC_ASSERT(offsetof(TimerState, remainingFrames) == 0x00);
STATIC_ASSERT(offsetof(TimerState, lightSlot) == 0x04);
STATIC_ASSERT(offsetof(TimerState, initialized08) == 0x08);
STATIC_ASSERT(offsetof(TimerState, mode) == 0x0C);
STATIC_ASSERT(offsetof(TimerState, flags) == 0x0D);
STATIC_ASSERT(offsetof(TimerState, unknown0E) == 0x0E);
STATIC_ASSERT(sizeof(TimerFlags) == 1);
STATIC_ASSERT(sizeof(TimerState) == 0x20);

extern ObjectDescriptor gTimerObjDescriptor;
extern f32 gTimerGlowScale;
extern f32 gTimerTextureScrollScale;

int timer_getExtraSize(void);
void timer_free(GameObject* obj);
/* Includes cancellation; remains latched across subsequent starts. */
int timer_hasEnded(GameObject* obj);
int timer_isEffectMode(GameObject* obj);
/* Clears the start override and ended latch without stopping the countdown. */
void timer_clearStartAndEndFlags(GameObject* obj);
void timer_forceStart(GameObject* obj);
/* Adds nominal frames to a nonzero timer; the global display truncates to seconds. */
void timer_addDuration(GameObject* obj, int durationFrames);
void timer_render(GameObject* obj, int p2, int p3, int p4, int p5, f32 scale);
void timer_init(GameObject* obj, TimerPlacementPrefix* setup);
void timer_update(GameObject* obj);

#endif
