#ifndef MAIN_DLL_MCUPGRADE_STATE_H_
#define MAIN_DLL_MCUPGRADE_STATE_H_

#include "global.h"

typedef enum McUpgradeMaEvent {
    MCUPGRADEMA_EVENT_SHOW_HUD = 0,
    MCUPGRADEMA_EVENT_SHOW_DIALOGUE = 1,
    MCUPGRADEMA_EVENT_HIDE_HUD = 2,
} McUpgradeMaEvent;

typedef enum McStaffEffectEvent {
    MCSTAFFEFFECT_EVENT_FORCE_GLOW = 1,
    MCSTAFFEFFECT_EVENT_RESTORE_GLOW = 2,
    MCSTAFFEFFECT_EVENT_CLEAR_GLOW = 3,
} McStaffEffectEvent;

typedef struct McUpgradeSetup {
    u8 pad00[0x1A];
    s16 dialogueTextId;
    u8 pad1C[2];
    s16 collectedGameBit;
} McUpgradeSetup;

typedef struct McUpgradeMaSetup {
    u8 pad00[0x1A];
    s16 collectedGameBit;
} McUpgradeMaSetup;

STATIC_ASSERT(offsetof(McUpgradeSetup, dialogueTextId) == 0x1A);
STATIC_ASSERT(offsetof(McUpgradeSetup, collectedGameBit) == 0x1E);
STATIC_ASSERT(offsetof(McUpgradeMaSetup, collectedGameBit) == 0x1A);

#endif /* MAIN_DLL_MCUPGRADE_STATE_H_ */
