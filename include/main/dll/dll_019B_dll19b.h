#ifndef MAIN_DLL_DLL_019B_DLL19B_H_
#define MAIN_DLL_DLL_019B_DLL19B_H_

#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/objanim_update.h"

enum Dll19BPhase
{
    DLL19B_PHASE_IDLE = 0,       /* wait for player proximity, then arm shrine */
    DLL19B_PHASE_WAIT_EVENT = 1, /* wait for pendingEvent, then start countdown */
    DLL19B_PHASE_COUNTDOWN = 2,  /* shrine timer ticking; success or timeout */
    DLL19B_PHASE_RESOLVE = 3,    /* branch on unlock bit: success vs fail path */
    DLL19B_PHASE_COMPLETE = 4,   /* set completion bits, finish */
    DLL19B_PHASE_DONE = 5,       /* terminal, no per-tick handling */
    DLL19B_PHASE_RESET = 6       /* tear down and return to idle */
};

typedef struct Dll19BState
{
    s16 activationDist; /* 0x00: proximity trigger distance */
    s16 timer;          /* 0x02: frame countdown */
    s16 brightnessA;    /* 0x04 */
    s16 brightnessAVel; /* 0x06 */
    s16 brightnessB;    /* 0x08: flame/UI frame */
    s16 brightnessBVel; /* 0x0A */
    s16 gfxHandle;      /* 0x0C: modgfx source handle */
    s16 countdown;      /* 0x0E: shrine timer */
    s16 unk10;          /* 0x10: init=0xc8 */
    u8 unlockCount;     /* 0x12 */
    u8 phase;           /* 0x13 */
    u8 pendingEvent;    /* 0x14 */
    u8 pad15[0x16 - 0x15];
    u8 displayedFlag; /* 0x16 */
    u8 pad17[0x18 - 0x17];
} Dll19BState;

int dll_19B_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);
int dll_19B_getExtraSize(void);
int dll_19B_getObjectTypeId(void);
void dll_19B_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dll_19B_hitDetect(void);
void dll_19B_free(int* obj);
void dll_19B_update(int obj);
void dll_19B_release(void);
void dll_19B_initialise(void);
void dll_19B_init(GameObject* obj, u8* params);

#endif /* MAIN_DLL_DLL_019B_DLL19B_H_ */
