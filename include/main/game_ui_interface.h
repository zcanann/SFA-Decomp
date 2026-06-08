#ifndef MAIN_GAME_UI_INTERFACE_H_
#define MAIN_GAME_UI_INTERFACE_H_

#include "global.h"

typedef struct GameUIInterface {
    u8 pad00[0x04];
    void (*frameStart)(void);
    void (*frameEnd)(void);
    void (*render)(void *context, int arg1, int arg2);
    u8 pad10[0x1C - 0x10];
    int (*isCurrentTriggerClear)(void);
    int (*isEventReady)(int eventId);
    int (*isOneOfItemsBeingUsed)(s32 *items, int count);
    u8 pad28[0x38 - 0x28];
    void (*showNpcDialogue)(s32 id, s32 unusedA, s32 unusedB, s32 disableInput);
    u8 pad3C[0x40 - 0x3C];
    void (*setShowWorldMapHud)(u8 visible);
    void (*setHudFields)(s32 a, s32 b, s32 c);
    u8 pad48[0x50 - 0x48];
    void (*setUnusedHudSetting)(u8 value);
    u8 pad54[0x58 - 0x54];
    void (*initAirMeter)(s32 maxValue, s32 textureId);
    void (*runAirMeter)(s32 value);
    void (*airMeterSetShutdown)(void);
    void (*airMeterShutdown)(void);
    void (*airMeterSetRatio)(f32 value);
} GameUIInterface;

STATIC_ASSERT(offsetof(GameUIInterface, frameStart) == 0x04);
STATIC_ASSERT(offsetof(GameUIInterface, frameEnd) == 0x08);
STATIC_ASSERT(offsetof(GameUIInterface, render) == 0x0C);
STATIC_ASSERT(offsetof(GameUIInterface, isCurrentTriggerClear) == 0x1C);
STATIC_ASSERT(offsetof(GameUIInterface, isEventReady) == 0x20);
STATIC_ASSERT(offsetof(GameUIInterface, isOneOfItemsBeingUsed) == 0x24);
STATIC_ASSERT(offsetof(GameUIInterface, showNpcDialogue) == 0x38);
STATIC_ASSERT(offsetof(GameUIInterface, setShowWorldMapHud) == 0x40);
STATIC_ASSERT(offsetof(GameUIInterface, setHudFields) == 0x44);
STATIC_ASSERT(offsetof(GameUIInterface, setUnusedHudSetting) == 0x50);
STATIC_ASSERT(offsetof(GameUIInterface, initAirMeter) == 0x58);
STATIC_ASSERT(offsetof(GameUIInterface, runAirMeter) == 0x5C);
STATIC_ASSERT(offsetof(GameUIInterface, airMeterSetShutdown) == 0x60);
STATIC_ASSERT(offsetof(GameUIInterface, airMeterShutdown) == 0x64);
STATIC_ASSERT(offsetof(GameUIInterface, airMeterSetRatio) == 0x68);

extern GameUIInterface **gGameUIInterface;

#endif /* MAIN_GAME_UI_INTERFACE_H_ */
