#ifndef MAIN_DLL_DR_DLL_026C_DRCAGEWITH_H_
#define MAIN_DLL_DR_DLL_026C_DRCAGEWITH_H_

#include "global.h"
#include "main/game_object.h"
#include "main/objanim_update.h"
#include "main/dll/DR/dr_types.h"

typedef struct DrcagewithPlacement
{
    u8 pad0[0x5 - 0x0];
    u8 flags; /* 0x5: low flag bits copied into spawned object (mask 0x18) */
    u8 pad6[0x18 - 0x6];
    s8 initRotXByte; /* 0x18: signed byte, <<8 into anim.rotX at init */
    u8 pad19[0x1A - 0x19];
    s16 unk1A;         /* 0x1A: int->float setup value (unk10) */
    s16 unk1C;         /* 0x1C: int->float setup value (unk8) */
    s16 openedGameBit; /* 0x1E: game bit set when this cage is opened */
} DrcagewithPlacement;

typedef struct DrcagewithState
{
    GameObject* spawnedObject; /* 0x0: spawned rope/winch object */
    GameObject* linkedObject;  /* 0x4: linked rope object */
    f32 unk8;
    u8 padC[0x10 - 0xC];
    f32 unk10;
    f32 unk14;
    f32 unk18;
    f32 unk1C;
    f32 unk20;
    f32 angularVel; /* 0x24: damped angular velocity */
    u8 pad28[0x30 - 0x28];
    u8 scaleMode;
    BitFlags8 ropeFlags;
    u8 pad32[0x34 - 0x32];
} DrcagewithState;

STATIC_ASSERT(offsetof(DrcagewithPlacement, flags) == 0x5);
STATIC_ASSERT(offsetof(DrcagewithPlacement, initRotXByte) == 0x18);
STATIC_ASSERT(offsetof(DrcagewithPlacement, unk1A) == 0x1A);
STATIC_ASSERT(offsetof(DrcagewithPlacement, unk1C) == 0x1C);
STATIC_ASSERT(offsetof(DrcagewithPlacement, openedGameBit) == 0x1E);
STATIC_ASSERT(offsetof(DrcagewithState, spawnedObject) == 0x0);
STATIC_ASSERT(offsetof(DrcagewithState, linkedObject) == 0x4);
STATIC_ASSERT(offsetof(DrcagewithState, angularVel) == 0x24);
STATIC_ASSERT(offsetof(DrcagewithState, scaleMode) == 0x30);
STATIC_ASSERT(offsetof(DrcagewithState, ropeFlags) == 0x31);
STATIC_ASSERT(sizeof(DrcagewithState) == 0x34);

int DR_CageWith_setScale(GameObject* obj);
int DR_CageWith_toggleRopeStateCallback(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int DR_CageWith_getExtraSize(void);
int DR_CageWith_getObjectTypeId(void);
void DR_CageWith_free(GameObject* obj, int arg);
void DR_CageWith_render(GameObject* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible);
void DR_CageWith_hitDetect(GameObject* obj);
void DR_CageWith_update(void);
void DR_CageWith_init(GameObject* obj, DrcagewithPlacement* placement);
void DR_CageWith_release(void);
void DR_CageWith_initialise(void);

extern f32 lbl_803E69F0;
extern f32 gDrCageWithFindObjMaxDist;
extern f32 lbl_803E69F8;
extern f32 lbl_803E69FC;
extern f32 lbl_803E6A00;
extern f32 gDrCageWithAngVelRateMin;
extern f32 gDrCageWithAngVelRateMax;
extern f32 lbl_803E6A0C;
extern f32 lbl_803E6A10;
extern f32 lbl_803E6A14;
extern f32 lbl_803E6A18;
extern f32 lbl_803E6A1C;

#endif /* MAIN_DLL_DR_DLL_026C_DRCAGEWITH_H_ */
