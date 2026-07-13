#ifndef MAIN_DLL_CF_DLL_014E_CFPRISONGUARD_H_
#define MAIN_DLL_CF_DLL_014E_CFPRISONGUARD_H_

#include "types.h"
#include "main/objanim_update.h"

typedef struct CfPrisonGuardState
{
    u8 pad00[0x30];
    f32 alarmRamp; /* particle ramp advanced while above threshold */
    s16 stateTimer;
    s8 capturedLatch; /* last GameBit 0x50 value */
    s8 guardState; /* 0 idle .. 7 forced-chase */
    u8 flags; /* 1 spawn-pulse pending, 2 freed-check, 4 alarm raised */
    u8 flags39; /* 0x80 cleared every update */
    u8 pad3A[2];
} CfPrisonGuardState;

int CFPrisonGuard_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate);
int CFPrisonGuard_getExtraSize(void);
int CFPrisonGuard_getObjectTypeId(void);
void CFPrisonGuard_free(void);
void CFPrisonGuard_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);
void CFPrisonGuard_hitDetect(int* obj);
void CFPrisonGuard_update(int* obj);
void CFPrisonGuard_init(int* obj, u8* params);
void CFPrisonGuard_release(void);
void CFPrisonGuard_initialise(void);

#endif /* MAIN_DLL_CF_DLL_014E_CFPRISONGUARD_H_ */
