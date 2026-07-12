#ifndef MAIN_DLL_DLL_02B5_TIMER_H
#define MAIN_DLL_DLL_02B5_TIMER_H

#include "global.h"
#include "main/game_object.h"
#include "main/obj_placement.h"

struct ModelLightStruct;

typedef struct TimerFlags
{
    u8 expired : 1;
    u8 manual : 1;
    u8 flag20 : 1;
    u8 pad : 5;
} TimerFlags;

typedef struct TimerSetup
{
    ObjPlacement base;
    u8 pad18;
    u8 mode;
    s16 durationMinutes;
    s16 pad1C;
    s16 expiredGameBit;
    s16 startGameBit;
} TimerSetup;

typedef struct TimerState
{
    f32 countdownTimer;
    struct ModelLightStruct* lightSlot;
    f32 lightScale;
    u8 mode;
    TimerFlags flags;
    u8 pad0E[0x20 - 0xE];
} TimerState;

STATIC_ASSERT(offsetof(TimerSetup, mode) == 0x19);
STATIC_ASSERT(offsetof(TimerSetup, durationMinutes) == 0x1A);
STATIC_ASSERT(offsetof(TimerSetup, expiredGameBit) == 0x1E);
STATIC_ASSERT(offsetof(TimerSetup, startGameBit) == 0x20);
STATIC_ASSERT(sizeof(TimerSetup) == 0x24);
STATIC_ASSERT(offsetof(TimerState, lightSlot) == 0x04);
STATIC_ASSERT(offsetof(TimerState, lightScale) == 0x08);
STATIC_ASSERT(offsetof(TimerState, mode) == 0x0C);
STATIC_ASSERT(offsetof(TimerState, flags) == 0x0D);
STATIC_ASSERT(sizeof(TimerState) == 0x20);

extern f32 lbl_803E7408;
extern f32 lbl_803E7418;
extern f32 lbl_803E7424;
extern f32 lbl_803DC418;
extern f32 lbl_803DC41C;
extern f32 lbl_803E741C;
extern f32 lbl_803E7420;

int timer_getExtraSize(void);
void timer_free(GameObject* obj);
int timer_hasExpired(GameObject* obj);
int timer_isEffectMode(GameObject* obj);
void timer_clearManualFlags(GameObject* obj);
void timer_forceStart(GameObject* obj);
void timer_addDuration(GameObject* obj, int duration);
void timer_render(GameObject* obj, int p2, int p3, int p4, int p5, f32 scale);
void timer_init(GameObject* obj, int setup);
void timer_update(GameObject* obj);

#endif
