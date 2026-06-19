#ifndef MAIN_DLL_LANDEDARWING_H_
#define MAIN_DLL_LANDEDARWING_H_

#include "ghidra_import.h"
#include "global.h"

/*
 * Per-object extra block for the landed-arwing baddie (dll_D3) -- the 0x94-byte
 * GroundBaddieState::control region, memset in dll_D3_init. Shared by
 * treasurechest.c (dll_D3_*), landedArwing.c, staffAction.c (fn_80165xxx
 * movement helpers) and backpack.c (LandedArwing_Update* action callbacks).
 * flags92 is bit-accessed through per-TU overlay structs (LandedArwingFlags,
 * StaffBits) -- keep those casts at the use sites.
 */
typedef struct LandedArwingState {
  void *boundsObj;        /* nearest defNo-0x4AD object; fills bounds + bounceFlags */
  f32 unk_04;
  u8 pad08[0x18 - 0x08];
  f32 unk_18;
  u8 pad1C[0x2C - 0x1C];
  f32 unk_2C;
  u8 pad30[0x40 - 0x30];
  f32 unk_40;
  f32 animSpeed;
  f32 boundsMinX;
  f32 boundsMaxX;
  f32 boundsMaxZ;
  f32 boundsMinZ;
  f32 boundsMaxY;
  f32 boundsMinY;
  f32 speed;
  f32 wanderTargetX;
  f32 wanderTargetY;
  f32 wanderTargetZ;
  f32 scriptTargetX; /* init: spawn position */
  f32 scriptTargetY;
  f32 scriptTargetZ;
  f32 surfaceNormalX; /* init: (0, 1, 0) */
  f32 surfaceNormalY;
  f32 surfaceNormalZ;
  f32 surfacePlaneD; /* init: -spawnY */
  u16 wanderTimer;
  u16 scriptTimer;
  u8 surfaceMode; /* 0-5 = wall axis lock, 6 = script/free flight */
  u8 bounceFlags; /* per-wall bounce-allowed bits, from boundsObj */
  u8 flags92;
  u8 pad93;
} LandedArwingState;

STATIC_ASSERT(sizeof(LandedArwingState) == 0x94);
STATIC_ASSERT(offsetof(LandedArwingState, animSpeed) == 0x44);
STATIC_ASSERT(offsetof(LandedArwingState, boundsMinX) == 0x48);
STATIC_ASSERT(offsetof(LandedArwingState, speed) == 0x60);
STATIC_ASSERT(offsetof(LandedArwingState, wanderTargetX) == 0x64);
STATIC_ASSERT(offsetof(LandedArwingState, scriptTargetX) == 0x70);
STATIC_ASSERT(offsetof(LandedArwingState, surfaceNormalX) == 0x7C);
STATIC_ASSERT(offsetof(LandedArwingState, wanderTimer) == 0x8C);
STATIC_ASSERT(offsetof(LandedArwingState, scriptTimer) == 0x8E);
STATIC_ASSERT(offsetof(LandedArwingState, surfaceMode) == 0x90);
STATIC_ASSERT(offsetof(LandedArwingState, flags92) == 0x92);

u32 LandedArwing_UpdateFlightChase(int obj, int state);

#endif /* MAIN_DLL_LANDEDARWING_H_ */
