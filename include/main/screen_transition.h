#ifndef MAIN_SCREEN_TRANSITION_H_
#define MAIN_SCREEN_TRANSITION_H_

#include "global.h"

typedef void (*ScreenTransitionInitFn)(int transitionId, int value, int flags);
typedef void (*ScreenTransitionStepFn)(int transitionId, int value);
typedef void (*ScreenTransitionBlendFn)(int transitionId, int value, f32 blend);
typedef int (*ScreenTransitionFinishedFn)(void);
typedef f32 (*ScreenTransitionProgressFn)(void);

typedef struct ScreenTransitionInterface {
    void *unused00;
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

extern ScreenTransitionInterface **gScreenTransitionInterface;


/* extern-cleanup: consolidated prototypes */
void doNothing_onSaveSelectScreenExit(void);
void titleScreenFn_801368d4(void);

#endif
