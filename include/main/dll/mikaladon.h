#ifndef H_MAIN_DLL_MIKALADON_H
#define H_MAIN_DLL_MIKALADON_H

#include "main/dll/baddie_state.h"
#include "main/game_object.h"
#include "main/obj_placement.h"

typedef struct MikaladonFields
{
    u8 pad00[0x324];
    f32 orbitCenterX;
    f32 homeY;
    f32 orbitCenterZ;
    f32 loopSfxTimer;
    f32 ambientSfxTimer;
    u16 orbitAngle;
    u8 verticalPhase;
    u8 dropTimer;
} MikaladonFields;

/* The shared baddie core treats 0x323..0x345 as per-family scratch. */
typedef union MikaladonState
{
    BaddieState baddie;
    MikaladonFields actor;
} MikaladonState;

typedef struct MikaladonDropSetup
{
    ObjPlacement base;
    u8 pad18[0x24 - sizeof(ObjPlacement)];
} MikaladonDropSetup;

STATIC_ASSERT(offsetof(MikaladonFields, orbitCenterX) == 0x324);
STATIC_ASSERT(offsetof(MikaladonFields, loopSfxTimer) == 0x330);
STATIC_ASSERT(offsetof(MikaladonFields, ambientSfxTimer) == 0x334);
STATIC_ASSERT(offsetof(MikaladonFields, orbitAngle) == 0x338);
STATIC_ASSERT(offsetof(MikaladonFields, verticalPhase) == 0x33A);
STATIC_ASSERT(offsetof(MikaladonFields, dropTimer) == 0x33B);
STATIC_ASSERT(sizeof(MikaladonDropSetup) == 0x24);

extern const f32 gMikaladonZero;
extern const f32 gMikaladonDefaultPeriod;

void mikaladon_update(GameObject* obj, MikaladonState* state);
void mikaladon_init(GameObject* obj, MikaladonState* state);

#endif /* H_MAIN_DLL_MIKALADON_H */
