#ifndef MAIN_DLL_DR_DLL_026E_DRSHACKLE_H_
#define MAIN_DLL_DR_DLL_026E_DRSHACKLE_H_

#include "main/game_object.h"
#include "global.h"
#include "main/objanim_update.h"

typedef struct DrshacklePlacement
{
    u8 pad0[0xC - 0x0];
    f32 posX; /* 0x0C */
    f32 posY; /* 0x10 */
    f32 posZ; /* 0x14 */
    u8 pad18[0x19 - 0x18];
    s8 unk19;             /* 0x19: reported by drshackle_func0B */
    s16 pathObjGroupBase; /* 0x1A: base id of the path objects this chain binds */
    s16 quarterTurns;     /* 0x1C: rotZ in quarter turns; ==1 also selects two slots */
    s16 activeGameBit;    /* 0x1E: game bit that keeps the chain active */
} DrshacklePlacement;

typedef struct DrshackleState
{
    s32 pathSlots[2]; /* 0x00: path-object pointer slots (one per slot) */
    f32 savedPosX;    /* 0x08 */
    f32 savedPosY;    /* 0x0C */
    f32 savedPosZ;    /* 0x10 */
    s32 slotCount;    /* 0x14: number of path slots (1 or 2) */
    u8 pad18[0x19 - 0x18];
    s8 unk19;              /* 0x19 */
    u8 pad1A[0x1B - 0x1A]; /* 0x1A: BitFlags8 active flag */
    u8 pathPointA;         /* 0x1B: path-point index of slot 0 */
    u8 pathPointB;         /* 0x1C: path-point index of slot 1 */
    u8 pad1D[0x20 - 0x1D];
} DrshackleState;

STATIC_ASSERT(offsetof(DrshacklePlacement, posX) == 0x0C);
STATIC_ASSERT(offsetof(DrshacklePlacement, unk19) == 0x19);
STATIC_ASSERT(offsetof(DrshacklePlacement, pathObjGroupBase) == 0x1A);
STATIC_ASSERT(offsetof(DrshacklePlacement, quarterTurns) == 0x1C);
STATIC_ASSERT(offsetof(DrshacklePlacement, activeGameBit) == 0x1E);
STATIC_ASSERT(offsetof(DrshackleState, savedPosX) == 0x08);
STATIC_ASSERT(offsetof(DrshackleState, slotCount) == 0x14);
STATIC_ASSERT(offsetof(DrshackleState, pathPointA) == 0x1B);
STATIC_ASSERT(offsetof(DrshackleState, pathPointB) == 0x1C);
STATIC_ASSERT(sizeof(DrshackleState) == 0x20);

int drshackle_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int drshackle_func0B(GameObject* obj);
int drshackle_setScale(int obj, int a, int b, int c, int d, int e, int f);
int drshackle_getExtraSize(void);
int drshackle_getObjectTypeId(void);
void drshackle_free(int obj);
void drshackle_render(int obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible);
void drshackle_hitDetect(unsigned long obj);
void drshackle_update(GameObject* obj);
void drshackle_init(GameObject* obj, char* arg);
void drshackle_release(void);
void drshackle_initialise(void);

#endif /* MAIN_DLL_DR_DLL_026E_DRSHACKLE_H_ */
