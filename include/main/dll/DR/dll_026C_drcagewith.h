#ifndef MAIN_DLL_DR_DLL_026C_DRCAGEWITH_H_
#define MAIN_DLL_DR_DLL_026C_DRCAGEWITH_H_

#include "global.h"
#include "main/game_object.h"
#include "main/objanim_update.h"

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
    s32 linkedObject;          /* 0x4: linked rope object, freed via Obj_FreeObject */
    f32 unk8;
    u8 padC[0x10 - 0xC];
    f32 unk10;
    f32 unk14;
    f32 unk18;
    f32 unk1C;
    f32 unk20;
    f32 angularVel; /* 0x24: damped angular velocity */
    u8 pad28[0x34 - 0x28];
} DrcagewithState;

STATIC_ASSERT(offsetof(DrcagewithPlacement, flags) == 0x5);
STATIC_ASSERT(offsetof(DrcagewithPlacement, initRotXByte) == 0x18);
STATIC_ASSERT(offsetof(DrcagewithPlacement, unk1A) == 0x1A);
STATIC_ASSERT(offsetof(DrcagewithPlacement, unk1C) == 0x1C);
STATIC_ASSERT(offsetof(DrcagewithPlacement, openedGameBit) == 0x1E);
STATIC_ASSERT(offsetof(DrcagewithState, spawnedObject) == 0x0);
STATIC_ASSERT(offsetof(DrcagewithState, linkedObject) == 0x4);
STATIC_ASSERT(offsetof(DrcagewithState, angularVel) == 0x24);
STATIC_ASSERT(sizeof(DrcagewithState) == 0x34);

int DR_CageWith_setScale(struct GameObject *obj);
int DR_CageWith_toggleRopeStateCallback(struct GameObject *obj, int unused, ObjAnimUpdateState* animUpdate);
int DR_CageWith_getExtraSize(void);
int DR_CageWith_getObjectTypeId(void);
void DR_CageWith_free(int obj, int arg);
void DR_CageWith_render(void* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible);
void DR_CageWith_hitDetect(int obj);
void DR_CageWith_update(void);
void DR_CageWith_init(int obj, char* arg);
void DR_CageWith_release(void);
void DR_CageWith_initialise(void);

#endif /* MAIN_DLL_DR_DLL_026C_DRCAGEWITH_H_ */
