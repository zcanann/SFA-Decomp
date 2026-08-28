#ifndef DLLS_OBJECTS_386_MMP_MOONROC_H_
#define DLLS_OBJECTS_386_MMP_MOONROC_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"
#include "main/dll/partfx_interface.h"
#include "main/carryable_state.h"

#define MMP_MOON_ROCK_SEQUENCE_ID 0x519

typedef struct MMPMoonRockPlacement {
    ObjPlacement base;
    u8 unknown18[2];
    s16 kindGameBit;
    u8 unknown1C[2];
    s16 unknown1E;
    s16 pickupGateGameBit;
    u8 unknown22[2];
} MMPMoonRockPlacement;

STATIC_ASSERT(sizeof(MMPMoonRockPlacement) == 0x24);
STATIC_ASSERT(offsetof(MMPMoonRockPlacement, base) == 0x00);
STATIC_ASSERT(offsetof(MMPMoonRockPlacement, unknown18) == 0x18);
STATIC_ASSERT(offsetof(MMPMoonRockPlacement, kindGameBit) == 0x1A);
STATIC_ASSERT(offsetof(MMPMoonRockPlacement, unknown1C) == 0x1C);
STATIC_ASSERT(offsetof(MMPMoonRockPlacement, unknown1E) == 0x1E);
STATIC_ASSERT(offsetof(MMPMoonRockPlacement, pickupGateGameBit) == 0x20);
STATIC_ASSERT(offsetof(MMPMoonRockPlacement, unknown22) == 0x22);

typedef struct MMPMoonRockState {
    CarryableState carryable;
    u8 pad0A[2];
    f32 baseY;
    f32 unknown10;
    f32 resetTimer;
    f32 homeX;
    f32 homeY;
    f32 homeZ;
    u16 flags;
    u16 bobPhase;
    u16 rollPhase;
    u16 pitchPhase;
    u8 unknown2C[2];
    u8 kind;
    u8 heightLevel;
} MMPMoonRockState;

STATIC_ASSERT(sizeof(MMPMoonRockState) == 0x30);
STATIC_ASSERT(offsetof(MMPMoonRockState, carryable) == 0x00);
STATIC_ASSERT(offsetof(MMPMoonRockState, baseY) == 0x0C);
STATIC_ASSERT(offsetof(MMPMoonRockState, unknown10) == 0x10);
STATIC_ASSERT(offsetof(MMPMoonRockState, resetTimer) == 0x14);
STATIC_ASSERT(offsetof(MMPMoonRockState, homeX) == 0x18);
STATIC_ASSERT(offsetof(MMPMoonRockState, homeY) == 0x1C);
STATIC_ASSERT(offsetof(MMPMoonRockState, homeZ) == 0x20);
STATIC_ASSERT(offsetof(MMPMoonRockState, flags) == 0x24);
STATIC_ASSERT(offsetof(MMPMoonRockState, bobPhase) == 0x26);
STATIC_ASSERT(offsetof(MMPMoonRockState, rollPhase) == 0x28);
STATIC_ASSERT(offsetof(MMPMoonRockState, pitchPhase) == 0x2A);
STATIC_ASSERT(offsetof(MMPMoonRockState, unknown2C) == 0x2C);
STATIC_ASSERT(offsetof(MMPMoonRockState, kind) == 0x2E);
STATIC_ASSERT(offsetof(MMPMoonRockState, heightLevel) == 0x2F);

extern PartFxSpawnParams gMMPMoonRockSpawnParams;
extern ObjectDescriptor gMMPMoonRockObjDescriptor;

void mmpMoonRock_handleImpact(GameObject* obj);
void mmpMoonRock_updateThrow(GameObject* obj);
void mmpMoonRock_throwFromPlayer(GameObject* obj);
void mmpMoonRock_reconcilePlacement(GameObject* obj, u8 place, u8 mode);
void mmpMoonRock_setPosition(GameObject* obj, f32 x, f32 y, f32 z);
void mmpMoonRock_setFrozen(GameObject* obj, u8 frozen);
int mmpMoonRock_getExtraSize(void);
int mmpMoonRock_getObjectTypeId(void);
void mmpMoonRock_free(GameObject* obj);
void mmpMoonRock_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible);
void mmpMoonRock_hitDetect(void);
void mmpMoonRock_update(GameObject* obj);
void mmpMoonRock_init(GameObject* obj, const MMPMoonRockPlacement* placement);
void mmpMoonRock_release(void);
void mmpMoonRock_initialise(void);

#endif /* DLLS_OBJECTS_386_MMP_MOONROC_H_ */
