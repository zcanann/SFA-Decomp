#ifndef MAIN_DLL_DR_DLL_0251_KTREXFLOORSWITCH_H_
#define MAIN_DLL_DR_DLL_0251_KTREXFLOORSWITCH_H_

#include "main/game_object.h"
#include "global.h"

typedef struct Vec3Blob
{
    int x;
    int y;
    int z;
} Vec3Blob;

typedef struct KtrexfloorswitchPlacement
{
    u8 pad0[0x8 - 0x0];
    f32 curveX;     /* 0x08: rom-curve lookup coordinates */
    f32 baseHeight; /* 0x0C: top/raised Y of the plate */
    f32 curveZ;     /* 0x10 */
    u8 pad14[0x18 - 0x14];
    u8 rotByte;      /* 0x18: byte yaw, shifted into anim.rotX at init */
    u8 chargeReload; /* 0x19: charge timer reload value */
    s16 levelBit;    /* 0x1A: game bit holding the 0..15 charge level */
    s16 activeBit;   /* 0x1C: game bit; nonzero/2 makes the plate active */
    u8 retractDepth; /* 0x1E: depth subtracted when settling */
    u8 sinkDepth;    /* 0x1F: depth subtracted while pressed */
} KtrexfloorswitchPlacement;

STATIC_ASSERT(offsetof(KtrexfloorswitchPlacement, curveX) == 0x08);
STATIC_ASSERT(offsetof(KtrexfloorswitchPlacement, baseHeight) == 0x0C);
STATIC_ASSERT(offsetof(KtrexfloorswitchPlacement, curveZ) == 0x10);
STATIC_ASSERT(offsetof(KtrexfloorswitchPlacement, rotByte) == 0x18);
STATIC_ASSERT(offsetof(KtrexfloorswitchPlacement, chargeReload) == 0x19);
STATIC_ASSERT(offsetof(KtrexfloorswitchPlacement, levelBit) == 0x1A);
STATIC_ASSERT(offsetof(KtrexfloorswitchPlacement, activeBit) == 0x1C);
STATIC_ASSERT(offsetof(KtrexfloorswitchPlacement, retractDepth) == 0x1E);
STATIC_ASSERT(offsetof(KtrexfloorswitchPlacement, sinkDepth) == 0x1F);
STATIC_ASSERT(sizeof(KtrexfloorswitchPlacement) == 0x20);

typedef struct KtrexfloorswitchSpawnEnergyArcState
{
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 angleScale; /* 0xC: multiplier applied to `angle` to build the arc's dir[1] */
    void* boltObj;  /* 0x10: lightning bolt object (ktlazerwall overlay) */
} KtrexfloorswitchSpawnEnergyArcState;

STATIC_ASSERT(offsetof(KtrexfloorswitchSpawnEnergyArcState, unk8) == 0x8);
STATIC_ASSERT(offsetof(KtrexfloorswitchSpawnEnergyArcState, angleScale) == 0xC);
STATIC_ASSERT(offsetof(KtrexfloorswitchSpawnEnergyArcState, boltObj) == 0x10);

typedef struct KtrexfloorswitchState
{
    u8 pad0[0x4 - 0x0];
    u8 graceTimer;     /* 0x04: frames the plate stays pressed after release */
    u8 prevGraceTimer; /* 0x05: previous frame's graceTimer */
    u8 pad6[0x8 - 0x6];
    f32 chargeTimer; /* 0x08: counts down between level increments */
    f32 scrollSpeed; /* 0x0C: texture scroll velocity */
    u8 flags;        /* 0x10: motion/state bits (see KTREXFLOORSWITCH_FLAG_*) */
    u8 pad11[0x14 - 0x11];
} KtrexfloorswitchState;

STATIC_ASSERT(offsetof(KtrexfloorswitchState, graceTimer) == 0x04);
STATIC_ASSERT(offsetof(KtrexfloorswitchState, prevGraceTimer) == 0x05);
STATIC_ASSERT(offsetof(KtrexfloorswitchState, chargeTimer) == 0x08);
STATIC_ASSERT(offsetof(KtrexfloorswitchState, scrollSpeed) == 0x0C);
STATIC_ASSERT(offsetof(KtrexfloorswitchState, flags) == 0x10);
STATIC_ASSERT(sizeof(KtrexfloorswitchState) == 0x14);

void KT_RexFloorSwitch_free(void);
int KT_RexFloorSwitch_getExtraSize(void);
int KT_RexFloorSwitch_getObjectTypeId(void);
void KT_RexFloorSwitch_hitDetect(void);
void KT_RexFloorSwitch_initialise(void);
void KT_RexFloorSwitch_release(void);
void KT_RexFloorSwitch_render(void* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible);
void KT_RexFloorSwitch_init(GameObject* obj, char* placement);
void ktrexfloorswitch_spawnEnergyArc(GameObject* obj, f32 scale, int angle);
void KT_RexFloorSwitch_update(GameObject* obj);

extern int gKTrexFloorSwitchCurveFindResult;
extern f32 lbl_803E6858;
extern f32 lbl_803E6898;
extern f32 lbl_803E689C;
extern f32 lbl_803E68A0;
extern f32 lbl_803E68A4;
extern f32 lbl_802C2560[];
extern f32 lbl_802C256C[];
extern f64 gKTrexFloorSwitchPi;
extern f64 gKTrexFloorSwitchBamHalfCircle;
extern f32 gKTrexFloorSwitchTriggerBoxInset;
extern f32 gKTrexFloorSwitchRiseSpeed;
extern f32 gKTrexFloorSwitchRetractSpeed;
extern f32 lbl_803E687C;
extern f32 gKTrexFloorSwitchScrollSpeed;
extern int gKTrexFloorSwitchPrevMoved;

#endif /* MAIN_DLL_DR_DLL_0251_KTREXFLOORSWITCH_H_ */
