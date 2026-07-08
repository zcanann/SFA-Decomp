#ifndef MAIN_DLL_DLL_025B_MSPLANTINGS_H_
#define MAIN_DLL_DLL_025B_MSPLANTINGS_H_

#include "global.h"

typedef struct MoonSeedPlantingSpotPlacement
{
    u8 pad0[0xC - 0x0];
    f32 posY; /* 0x0c: planted-spot Y position */
    u8 pad10[0x14 - 0x10];
    s32 mapId; /* 0x14: ObjPlacement head mapId */
    u8 pad18[0x1F - 0x18];
    u8 rotByte; /* 0x1f: rotX in 1/256 turns */
} MoonSeedPlantingSpotPlacement;

typedef struct MoonSeedPlantingSpotState
{
    u8 phase;
    u8 flags;
    u8 pad2[0x8 - 0x2];
    s16 plantedGameBit;
    s16 harvestedGameBit;
    s16 colorPhase;
    u8 padE[0x10 - 0xE];
    f32 growthTimer;
    f32 burstTimer;
} MoonSeedPlantingSpotState;

STATIC_ASSERT(sizeof(MoonSeedPlantingSpotState) == 0x18);

int MoonSeedPlantingSpot_SeqFn(int obj);
int MoonSeedPlantingSpot_render2(void);
int MoonSeedPlantingSpot_modelMtxFn(void);
int MoonSeedPlantingSpot_func0B(void);
int MoonSeedPlantingSpot_setScale(int* obj, int arg);
int MoonSeedPlantingSpot_getExtraSize(void);
int MoonSeedPlantingSpot_getObjectTypeId(void);
void MoonSeedPlantingSpot_free(int obj);
void MoonSeedPlantingSpot_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void MoonSeedPlantingSpot_hitDetect(void);
void MoonSeedPlantingSpot_update(int obj);
void MoonSeedPlantingSpot_init(int* obj, MoonSeedPlantingSpotPlacement* init);
void MoonSeedPlantingSpot_release(void);
void MoonSeedPlantingSpot_initialise(void);

#endif /* MAIN_DLL_DLL_025B_MSPLANTINGS_H_ */
