#ifndef MAIN_SCREEN_TRANSITION_H_
#define MAIN_SCREEN_TRANSITION_H_

#include "global.h"

typedef enum ScreenTransitionType {
    SCREEN_TRANSITION_BLACK = 1,      /* solid black rectangle */
    SCREEN_TRANSITION_WHITE = 2,      /* solid white rectangle */
    SCREEN_TRANSITION_WHITE_WIPE = 3, /* white edge wipe */
    SCREEN_TRANSITION_RED = 4,        /* solid red rectangle */
    SCREEN_TRANSITION_HUD = 5,        /* no rectangle; drives HUD opacity */
} ScreenTransitionType;

typedef void (*ScreenTransitionInitFn)(int transitionId, int value, int flags);
typedef void (*ScreenTransitionStepFn)(int duration, ScreenTransitionType type);
typedef void (*ScreenTransitionBlendFn)(int duration, ScreenTransitionType type, f32 blend);
typedef int (*ScreenTransitionFinishedFn)(void);
typedef f32 (*ScreenTransitionProgressFn)(void);

typedef struct ScreenTransitionInterface {
    void* unused00;
    ScreenTransitionInitFn init;
    ScreenTransitionStepFn start;
    ScreenTransitionStepFn step;
    ScreenTransitionBlendFn stepWithBlend;
    ScreenTransitionFinishedFn isFinished;
    ScreenTransitionProgressFn getProgress;
} ScreenTransitionInterface;

STATIC_ASSERT(offsetof(ScreenTransitionInterface, init) == 0x04);
STATIC_ASSERT(offsetof(ScreenTransitionInterface, start) == 0x08);
STATIC_ASSERT(offsetof(ScreenTransitionInterface, step) == 0x0C);
STATIC_ASSERT(offsetof(ScreenTransitionInterface, stepWithBlend) == 0x10);
STATIC_ASSERT(offsetof(ScreenTransitionInterface, isFinished) == 0x14);
STATIC_ASSERT(offsetof(ScreenTransitionInterface, getProgress) == 0x18);

extern ScreenTransitionInterface** gScreenTransitionInterface;

void setScreenTransitionPause(u32 pause);
int isScreenTransitionActive(void);

#endif
