#ifndef MAIN_DLL_DR_DRLASERTURRET_H_
#define MAIN_DLL_DR_DRLASERTURRET_H_

#include "ghidra_import.h"

#define DR_LASERTURRET_FLAG_ACTION_ACTIVE 0x08
#define DR_LASERTURRET_FLAG_START_SEQUENCE 0x02
#define DR_LASERTURRET_FLAG_CONFIRM_PROMPT 0x10

#define DR_LASERTURRET_GAMEBIT_SHOP_OPEN 0x617
#define DR_LASERTURRET_GAMEBIT_HAS_MONEY 0x61D
#define DR_LASERTURRET_GAMEBIT_LINK_READY 0xCEF
#define DR_LASERTURRET_GAMEBIT_LINK_STARTED 0xAD3
#define DR_LASERTURRET_GAMEBIT_TIMER_STARTED 0x626

#define DR_LASERTURRET_ANIM_IDLE 0
#define DR_LASERTURRET_ANIM_TRACKING 0x11
#define DR_LASERTURRET_ANIM_ALERT 0x12

#define DR_LASERTURRET_STATE_PUSH_IDLE 1
#define DR_LASERTURRET_STATE_PUSH_TRACKING 4
#define DR_LASERTURRET_STATE_CONTINUE 7
#define DR_LASERTURRET_STATE_LINKED_TARGET 2

#define DR_LASERTURRET_SFX_ACTION 0x40D
#define DR_LASERTURRET_SFX_PROMPT_TICK 0xF3

#define DR_LASERTURRET_BUTTON_ACCEPT 0x100
#define DR_LASERTURRET_BUTTON_CANCEL 0x200

#define DR_LASERTURRET_PROMPT_COUNT 0x14
#define DR_LASERTURRET_PROMPT_NUDGE 0x15
#define DR_LASERTURRET_PROMPT_MAX_NUDGE 0x16
#define DR_LASERTURRET_PROMPT_DIGIT_COUNT 0x17

#define DR_LASERTURRET_ONES_TEXTURE_SLOT 8
#define DR_LASERTURRET_TENS_TEXTURE_SLOT 7
#define DR_LASERTURRET_HUNDREDS_TEXTURE_SLOT 6
#define DR_LASERTURRET_DIGIT_TEXTURE_SHIFT 8
#define DR_LASERTURRET_MAX_DIGIT 9
#define DR_LASERTURRET_MAX_DIGIT_COUNT 10
#define DR_LASERTURRET_MIN_DIGIT_COUNT 1
#define DR_LASERTURRET_MAX_NUDGE_COUNT 2

typedef struct DRLaserTurretState {
    u8 pad000[0x9b0];
    void *stateStack;
    void *linkedTarget;
    f32 bobAmplitude;
    f32 bobBaseY;
    f32 actionTimer;
    u8 pad9c4[0x9c8 - 0x9c4];
    s16 maxCount;
    u16 bobPhase;
    s16 countScale;
    s16 countTarget;
    s16 countValue;
    u8 nudgeCount;
    u8 pad9d3;
    u8 flags;
    u8 digitCount;
    u8 promptState;
} DRLaserTurretState;

typedef struct DRLaserTurretObject {
    u8 pad000[0x0c];
    f32 x;
    f32 y;
    f32 z;
    u8 pad014[0xa0 - 0x14];
    s16 currentMove;
    u8 pad0a2[0xaf - 0xa2];
    u8 hitFlags;
    u8 pad0b0[0xb8 - 0xb0];
    DRLaserTurretState *state;
} DRLaserTurretObject;

typedef struct DRLaserTurretAnimState {
    u8 pad000[0x27a];
    s8 stateEntered;
    u8 pad27b[0x280 - 0x27b];
    f32 aimBlend;
    u8 pad284[0x2a0 - 0x284];
    f32 animStepScale;
    u8 pad2a4[0x346 - 0x2a4];
    s8 moveComplete;
} DRLaserTurretAnimState;

int DRlaserturret_updateIdle(DRLaserTurretObject *obj, DRLaserTurretAnimState *animState);
int DRlaserturret_updateTracking(DRLaserTurretObject *obj, DRLaserTurretAnimState *animState);
int DRlaserturret_startLinkedTarget(void *obj);
int DRlaserturret_handlePromptChoice(void *obj, void *param2, int dispatch);
void DRlaserturret_startTimedChallenge(void *obj);

#endif /* MAIN_DLL_DR_DRLASERTURRET_H_ */
