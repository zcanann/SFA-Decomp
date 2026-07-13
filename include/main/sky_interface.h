#ifndef MAIN_SKY_INTERFACE_H_
#define MAIN_SKY_INTERFACE_H_

#include "global.h"

struct GameObject;

typedef void (*SkyUpdateEnvfxActFn)(struct GameObject* sourceObj, struct GameObject* targetObj, void* entry, int flags);
typedef void (*SkyLoadLightsFn)(void);
typedef void (*SkyUpdateTimeOfDayFn)(void);
typedef void (*SkyRenderFn)(int a, int b, int c, int d, int e);
typedef void (*SkyGetTimeOfDayFn)(f32 *outTime);
typedef void (*SkyGetClockTimeFn)(f32 *outTime);
typedef void (*SkyGetTransitionTimerFn)(int *outTimer);
typedef int (*SkyGetSunPositionFn)(f32 *outTime);
typedef void (*SkySetTimeOfDayFn)(f32 time);
typedef void (*SkyTimeToDayHourMinuteFn)(f32 time, s16 *days, s16 *hours, s16 *minutes);
typedef int (*SkyGetBlendStateBit20Fn)(int slot);
typedef void (*SkyRenderTimeOfDayBackdropFn)(int unused0, int unused1);
typedef void (*SkyGetCurrentTextureColorFn)(u8 *red, u8 *green, u8 *blue);
typedef void (*SkyGetCurrentAmbientAndLightColorsFn)(u8 *ambientRed, u8 *ambientGreen,
                                                     u8 *ambientBlue, u8 *lightRed,
                                                     u8 *lightGreen, u8 *lightBlue);
typedef void (*SkySetEnvFxGameBitFn)(int value);
typedef int (*SkyGetEnvFxGameBitFn)(void);

typedef struct SkyInterface {
    void *unused00;
    SkyUpdateEnvfxActFn updateEnvfxAct;
    SkyLoadLightsFn loadLights;
    SkyUpdateTimeOfDayFn updateTimeOfDay;
    SkyRenderFn render;
    SkyGetTimeOfDayFn getTimeOfDay;
    SkyGetClockTimeFn getClockTime;
    void (*nop1)(void);
    SkyGetTransitionTimerFn getTransitionTimer;
    SkyGetSunPositionFn getSunPosition;
    SkySetTimeOfDayFn setTimeOfDay;
    int (*return0)(void);
    SkyTimeToDayHourMinuteFn timeToDayHourMinute;
    SkyGetBlendStateBit20Fn getBlendStateBit20;
    SkyRenderTimeOfDayBackdropFn renderTimeOfDayBackdrop;
    SkyGetCurrentTextureColorFn getCurrentTextureColor;
    SkyGetCurrentAmbientAndLightColorsFn getCurrentAmbientAndLightColors;
    void (*nop2)(void);
    void (*nop3)(void);
    SkySetEnvFxGameBitFn setEnvFxGameBit;
    SkyGetEnvFxGameBitFn getEnvFxGameBit;
    int (*return0b)(void);
} SkyInterface;

STATIC_ASSERT(offsetof(SkyInterface, updateEnvfxAct) == 0x04);
STATIC_ASSERT(offsetof(SkyInterface, loadLights) == 0x08);
STATIC_ASSERT(offsetof(SkyInterface, updateTimeOfDay) == 0x0C);
STATIC_ASSERT(offsetof(SkyInterface, render) == 0x10);
STATIC_ASSERT(offsetof(SkyInterface, getTimeOfDay) == 0x14);
STATIC_ASSERT(offsetof(SkyInterface, getClockTime) == 0x18);
STATIC_ASSERT(offsetof(SkyInterface, getTransitionTimer) == 0x20);
STATIC_ASSERT(offsetof(SkyInterface, getSunPosition) == 0x24);
STATIC_ASSERT(offsetof(SkyInterface, setTimeOfDay) == 0x28);
STATIC_ASSERT(offsetof(SkyInterface, return0) == 0x2C);
STATIC_ASSERT(offsetof(SkyInterface, timeToDayHourMinute) == 0x30);
STATIC_ASSERT(offsetof(SkyInterface, getBlendStateBit20) == 0x34);
STATIC_ASSERT(offsetof(SkyInterface, renderTimeOfDayBackdrop) == 0x38);
STATIC_ASSERT(offsetof(SkyInterface, getCurrentTextureColor) == 0x3C);
STATIC_ASSERT(offsetof(SkyInterface, getCurrentAmbientAndLightColors) == 0x40);
STATIC_ASSERT(offsetof(SkyInterface, setEnvFxGameBit) == 0x4C);
STATIC_ASSERT(offsetof(SkyInterface, getEnvFxGameBit) == 0x50);
STATIC_ASSERT(offsetof(SkyInterface, return0b) == 0x54);

extern SkyInterface **gSkyInterface;

typedef void (*Sky2UpdateEnvfxActFn)(struct GameObject* source, struct GameObject* target,
                                     void* entry, int flags, u16 idx);
typedef void (*Sky2OnMapSetupFn)(void);
typedef void (*Sky2RunFn)(void);
typedef void (*Sky2ApplyFogColorFn)(int slot);
typedef int (*Sky2Ret0Fn)(void);
typedef void (*Sky2ApplyTextColorFn)(int slot);

typedef struct Sky2Interface {
    u8 pad00[0x04];
    Sky2UpdateEnvfxActFn updateEnvfxAct;
    Sky2OnMapSetupFn onMapSetup;
    Sky2RunFn run;
    Sky2ApplyFogColorFn applyFogColor;
    Sky2Ret0Fn ret0;
    Sky2ApplyTextColorFn applyTextColor;
} Sky2Interface;

STATIC_ASSERT(offsetof(Sky2Interface, updateEnvfxAct) == 0x04);
STATIC_ASSERT(offsetof(Sky2Interface, onMapSetup) == 0x08);
STATIC_ASSERT(offsetof(Sky2Interface, run) == 0x0C);
STATIC_ASSERT(offsetof(Sky2Interface, applyFogColor) == 0x10);
STATIC_ASSERT(offsetof(Sky2Interface, ret0) == 0x14);
STATIC_ASSERT(offsetof(Sky2Interface, applyTextColor) == 0x18);

extern Sky2Interface** gSky2Interface;

#endif /* MAIN_SKY_INTERFACE_H_ */
