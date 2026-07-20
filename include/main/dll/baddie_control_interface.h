#ifndef MAIN_DLL_BADDIE_CONTROL_INTERFACE_H_
#define MAIN_DLL_BADDIE_CONTROL_INTERFACE_H_

#include "types.h"

typedef struct GameObject GameObject;

/* Function-pointer table exported by the baddie-control DLL (0x19); slot K
 * here is the DLL's exported func(K - 4) (releaseState = dll_19_func12,
 * findAggroTarget = dll_19_func14, updateHitReaction = dll_19_func16,
 * initGroundBaddie = dll_19_func18). Named slots are those with recovered
 * call sites; the pads are unrecovered slots. */
typedef struct BaddieControlInterface
{
    u8 pad00[0x28];
    void (*startHitReaction)(int obj, int state, int hitReactState, int gameBit, int a5, int a6, int a7, int mode,
                             int slot);                                      /* 0x28 */
    void (*updateGravity)(int obj, int state, f32 gravityScale, int slot);   /* 0x2C */
    int (*checkAwake)(int obj, int state, int mode);                         /* 0x30 */
    u8 pad34[0x40 - 0x34];
    void (*releaseState)(int* obj, u8* state, int mode);                     /* 0x40 */
    u8 pad44[0x48 - 0x44];
    u32 (*findAggroTarget)(int obj, int state, f32 aggroRange, int angleRange); /* 0x48 */
    GameObject* (*spawnChild)(GameObject* obj, int spawnType, int unused, int alt); /* 0x4C */
    int (*updateHitReaction)(int obj, int state, int hitReactState, int gameBit, char* sfxTblA, char* sfxTblB,
                             int mode, char* aux);                           /* 0x50 */
    u8 pad54[4];
    void (*initGroundBaddie)(int* obj, u8* def, u8* state, int hp, int a5, int moveId, u8 mode,
                             f32 radius);                                    /* 0x58 */
} BaddieControlInterface;

extern int* gBaddieControlInterface;

#endif /* MAIN_DLL_BADDIE_CONTROL_INTERFACE_H_ */
