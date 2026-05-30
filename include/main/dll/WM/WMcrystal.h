#ifndef MAIN_DLL_WM_WMCRYSTAL_H_
#define MAIN_DLL_WM_WMCRYSTAL_H_

#include "ghidra_import.h"
#include "main/objanim_update.h"

typedef struct ScTotemPuzzleState {
    f32 pulseTimer;
    f32 pulseTimerReset;
    f32 peerPhaseOffset;
    f32 angle;
    s16 stepIndex;
    s16 flags;
} ScTotemPuzzleState;

typedef struct ScTotemPuzzleObject {
    s16 yaw;
    u8 pad02[0xAD - 0x02];
    s8 puzzleIndex;
    u8 padAE[0xB0 - 0xAE];
    u16 objectFlags;
    u8 padB2[0xB8 - 0xB2];
    ScTotemPuzzleState *state;
    void (*animEventCallback)(int obj);
} ScTotemPuzzleObject;

typedef struct ScTotemPuzzleMapData {
    u8 pad00[0x1B];
    u8 puzzleIndex;
} ScTotemPuzzleMapData;

typedef struct ScTotemBondState {
    u8 pad00[0x24];
    s16 ringIndex;
    u8 eventFlags;
} ScTotemBondState;

typedef struct ScTotemBondObject {
    s16 yaw;
    u8 pad02[0x0C - 0x02];
    f32 x;
    f32 y;
    f32 z;
    u8 pad18[0x4C - 0x18];
    u8 *definition;
    u8 pad50[0xB0 - 0x50];
    u16 objectFlags;
    u8 padB2[0xB8 - 0xB2];
    ScTotemBondState *state;
    undefined4 (*animEventCallback)(struct ScTotemBondObject *obj,undefined4 param2,ObjAnimUpdateState *animUpdate);
} ScTotemBondObject;

void sc_totempuzzle_update(ScTotemPuzzleObject *obj);
void sc_totempuzzle_init(ScTotemPuzzleObject *obj,ScTotemPuzzleMapData *params);
void sc_totempuzzle_release(void);
void sc_totempuzzle_initialise(void);
void FUN_801dd6b8(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void FUN_801dd6e0(undefined2 *param_1);
void FUN_801dd6e4(undefined2 *param_1,int param_2);
void sc_totembond_spawnGameBitOrbs(ScTotemBondObject *obj,ScTotemBondState *state,f32 radius);
undefined4 sc_totempuzzle_processAnimEvents(ScTotemBondObject *obj,undefined4 param_2,ObjAnimUpdateState *animUpdate);
void FUN_801ddb0c(void);
void FUN_801ddb3c(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible);
void sc_totembond_init(ScTotemBondObject *obj,int params);
int fn_801DE320(u16 *gameBitIds,u16 newValue);

#endif /* MAIN_DLL_WM_WMCRYSTAL_H_ */
