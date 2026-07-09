#ifndef MAIN_DLL_DIM_DLL_01D9_DIM2PRISONMAMMOTH_H_
#define MAIN_DLL_DIM_DLL_01D9_DIM2PRISONMAMMOTH_H_

#include "types.h"
#include "main/objanim_update.h"

typedef struct Dim2prisonmammothPlacement
{
    u8 pad0[0x18 - 0x0];
    s8 rotByte;      /* 0x18 packed into rotX as (s16)(rotByte << 8) at init */
    s8 spawnVariant; /* 0x19 spawn variant selector (stateHandler00) */
    u8 pad1A[0x20 - 0x1A];
} Dim2prisonmammothPlacement;

typedef struct Dim2prisonmammothState
{
    s32 flags; /* 0x0 object flag bits (0x8000, 0x400000) */
    u8 pad4[0x25F - 0x4];
    u8 unk25F;
    u8 pad260[0x274 - 0x260];
    s16 stateIndex; /* 0x274 indexes gPrisonMammothStateFlagsTable */
    u8 pad276[0x28C - 0x276];
    f32 unk28C;
    f32 unk290;
    u8 pad294[0x318 - 0x294];
    s32 unk318;
    s32 unk31C;
    u8 pad320[0x330 - 0x320];
    s16 unk330;
    u8 pad332[0x354 - 0x332];
    u8 unk354;
    u8 pad355[0x38C - 0x355];
    s16 unk38C;
    u8 pad38E[0x5FC - 0x38E];
    u8 hitReactState; /* 0x5FC carried in/out of ObjHitReact_Update */
    u8 pad5FD[0x604 - 0x5FD];
} Dim2prisonmammothState;

int dim2prisonmammoth_defaultStateHandler(void);
int dim2prisonmammoth_stateHandler03(int obj, int state);
int dim2prisonmammoth_stateHandler02(int obj, int state);
int dim2prisonmammoth_stateHandler01(int obj, int state);
int dim2prisonmammoth_stateHandler00(int* obj);
int dim2prisonmammoth_SeqFn(int obj, int state, ObjAnimUpdateState* animUpdate);
int dim2prisonmammoth_getExtraSize(void);
int dim2prisonmammoth_getObjectTypeId(void);
void dim2prisonmammoth_free(void);
void dim2prisonmammoth_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void dim2prisonmammoth_hitDetect(void);
void dim2prisonmammoth_update(int obj);
void dim2prisonmammoth_init(int obj, int params);
void dim2prisonmammoth_release(void);
void dim2prisonmammoth_initialise(void);
void fn_802BC788(struct GameObject *obj, int b);

#endif
