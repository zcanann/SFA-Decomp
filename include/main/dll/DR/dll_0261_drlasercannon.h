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

typedef struct DrLaserCannonSetup
{
    u8 pad00[0x18];
    s8 initialYaw;
    s8 reloadFrames;
    s16 targetRange;
    s16 beamSpeed;
    s16 destroyedGameBit;
    s16 warningOffGameBit;
} DrLaserCannonSetup;

typedef struct DrLaserCannonAim
{
    u8 pad00[0x14];
    s16 yaw;
    u8 pad16[0x44 - 0x16];
    s16 pitch;
} DrLaserCannonAim;

STATIC_ASSERT(offsetof(DrLaserCannonBeamSetup, objectType) == 0x0);
STATIC_ASSERT(offsetof(DrLaserCannonBeamSetup, field02) == 0x2);
STATIC_ASSERT(offsetof(DrLaserCannonBeamSetup, field04) == 0x4);
STATIC_ASSERT(offsetof(DrLaserCannonBeamSetup, field05) == 0x5);
STATIC_ASSERT(offsetof(DrLaserCannonBeamSetup, field06) == 0x6);
STATIC_ASSERT(offsetof(DrLaserCannonBeamSetup, field07) == 0x7);
STATIC_ASSERT(offsetof(DrLaserCannonBeamSetup, spawnX) == 0x8);
STATIC_ASSERT(offsetof(DrLaserCannonBeamSetup, spawnY) == 0xc);
STATIC_ASSERT(offsetof(DrLaserCannonBeamSetup, spawnZ) == 0x10);
STATIC_ASSERT(offsetof(DrLaserCannonSetup, initialYaw) == 0x18);
STATIC_ASSERT(offsetof(DrLaserCannonSetup, reloadFrames) == 0x19);
STATIC_ASSERT(offsetof(DrLaserCannonSetup, targetRange) == 0x1a);
STATIC_ASSERT(offsetof(DrLaserCannonSetup, beamSpeed) == 0x1c);
STATIC_ASSERT(offsetof(DrLaserCannonSetup, destroyedGameBit) == 0x1e);
STATIC_ASSERT(offsetof(DrLaserCannonSetup, warningOffGameBit) == 0x20);
STATIC_ASSERT(offsetof(DrLaserCannonAim, yaw) == 0x14);
STATIC_ASSERT(offsetof(DrLaserCannonAim, pitch) == 0x44);

int DR_LaserCannon_getExtraSize(void);
int DR_LaserCannon_getObjectTypeId(void);
void DR_LaserCannon_initialise(void);
void DR_LaserCannon_release(void);
void DR_LaserCannon_free(GameObject* obj);
void DR_LaserCannon_render(GameObject* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible);
GameObject* drlasercannon_getTrackedTarget(GameObject* obj, int* cooldown);
int drlasercannon_aimAtTarget(GameObject* self, GameObject* target, DrLaserCannonAim* out, int maxRate, f32* eyePos);
void DR_LaserCannon_init(GameObject* obj, DrLaserCannonSetup* setup);
void DR_LaserCannon_hitDetect(GameObject* obj);
void DR_LaserCannon_update(GameObject* obj);

extern f32 lbl_803E68E8;
extern f32 lbl_803E68EC;
extern f32 gLaserCannonAngleRateScale;
extern f32 lbl_803E68E4;
extern s16 gLaserCannonMaxAimStep;
extern f32 lbl_803E690C;
extern f32 lbl_803E6920;
extern f32 lbl_803E6938;
extern f32 lbl_803E68F0;
extern f32 lbl_803E68F4;
extern f32 lbl_803E68F8;
extern f32 lbl_803E68FC;
extern f32 lbl_803E6900;
extern f32 lbl_803E6904;
extern f32 lbl_803E6908;
extern f32 lbl_803E6910;
extern f32 lbl_803E6914;
extern f32 lbl_803E6918;
extern f32 lbl_803E691C;
extern f32 lbl_803E6924;
extern f32 lbl_803E6928;
extern f32 lbl_803E692C;
extern f32 lbl_803DC2A8;
extern s16 lbl_803DC2AC;
extern f32 lbl_803DDD68;

#endif /* MAIN_DLL_DR_DLL_0261_DRLASERCANNON_H_ */
