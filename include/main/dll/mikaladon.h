#ifndef H_MAIN_DLL_MIKALADON_H
#define H_MAIN_DLL_MIKALADON_H

#include "dlls/objects/201_Baddie.h"
#include "game/objects/object.h"
#include "game/objects/object_setup.h"

typedef struct MikaladonDropSetup
{
    ObjPlacement base;
    u8 pad18[0x24 - sizeof(ObjPlacement)];
} MikaladonDropSetup;

STATIC_ASSERT(sizeof(MikaladonDropSetup) == 0x24);

extern const f32 gMikaladonZero[];
extern const f32 gMikaladonDefaultPeriod[];

void mikaladon_update(GameObject* obj, EnemyState* state);
void mikaladon_init(GameObject* obj, EnemyState* state);

#endif /* H_MAIN_DLL_MIKALADON_H */
