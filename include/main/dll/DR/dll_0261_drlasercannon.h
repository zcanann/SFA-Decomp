#ifndef MAIN_DLL_DR_DLL_0261_DRLASERCANNON_H_
#define MAIN_DLL_DR_DLL_0261_DRLASERCANNON_H_

#include "global.h"
#include "main/game_object.h"

typedef struct DrLaserCannonBeamSetup
{
    s16 objectType;
    u8 field02;
    u8 pad03;
    u8 field04;
    u8 field05;
    u8 field06;
    u8 field07;
    f32 spawnX;
    f32 spawnY;
    f32 spawnZ;
} DrLaserCannonBeamSetup;

STATIC_ASSERT(offsetof(DrLaserCannonBeamSetup, objectType) == 0x0);
STATIC_ASSERT(offsetof(DrLaserCannonBeamSetup, field02) == 0x2);
STATIC_ASSERT(offsetof(DrLaserCannonBeamSetup, field04) == 0x4);
STATIC_ASSERT(offsetof(DrLaserCannonBeamSetup, field05) == 0x5);
STATIC_ASSERT(offsetof(DrLaserCannonBeamSetup, field06) == 0x6);
STATIC_ASSERT(offsetof(DrLaserCannonBeamSetup, field07) == 0x7);
STATIC_ASSERT(offsetof(DrLaserCannonBeamSetup, spawnX) == 0x8);
STATIC_ASSERT(offsetof(DrLaserCannonBeamSetup, spawnY) == 0xc);
STATIC_ASSERT(offsetof(DrLaserCannonBeamSetup, spawnZ) == 0x10);

int DR_LaserCannon_getExtraSize(void);
int DR_LaserCannon_getObjectTypeId(void);
void DR_LaserCannon_initialise(void);
void DR_LaserCannon_release(void);
void DR_LaserCannon_free(GameObject* obj);
void DR_LaserCannon_render(GameObject* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible);
int drlasercannon_getTrackedTarget(int obj, int* arg);
void DR_LaserCannon_init(int obj, char* arg);
void DR_LaserCannon_hitDetect(GameObject* obj);
void DR_LaserCannon_update(int obj);

#endif /* MAIN_DLL_DR_DLL_0261_DRLASERCANNON_H_ */
