#ifndef MAIN_DLL_DLL_0293_SUNTEMPLE_H
#define MAIN_DLL_DLL_0293_SUNTEMPLE_H

#include "global.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"
#include "main/vec_types.h"

typedef struct SunTempleSetup
{
    ObjPlacement base;
    u8 rotXByte;
    u8 rotYByte;
    u8 rotZByte;
    u8 flags;
    s16 activationGameBit;
    s16 readyEventId;
    s8 triggerSlot;
    s8 bankIndex;
    s16 gateGameBit;
    s16 preemptSequenceId;
} SunTempleSetup;

typedef struct SunTempleState
{
    u8 activationLatched;
    u8 mapEventMode;
} SunTempleState;

STATIC_ASSERT(offsetof(SunTempleSetup, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(SunTempleSetup, flags) == 0x1B);
STATIC_ASSERT(offsetof(SunTempleSetup, activationGameBit) == 0x1C);
STATIC_ASSERT(offsetof(SunTempleSetup, readyEventId) == 0x1E);
STATIC_ASSERT(offsetof(SunTempleSetup, triggerSlot) == 0x20);
STATIC_ASSERT(offsetof(SunTempleSetup, bankIndex) == 0x21);
STATIC_ASSERT(offsetof(SunTempleSetup, gateGameBit) == 0x22);
STATIC_ASSERT(offsetof(SunTempleSetup, preemptSequenceId) == 0x24);
STATIC_ASSERT(sizeof(SunTempleSetup) == 0x28);
STATIC_ASSERT(sizeof(SunTempleState) == 2);

extern ObjectDescriptor gSunTempleObjDescriptor;
extern Vec3f lbl_802C25D8;
extern f32 lbl_803E6E18;

int suntemple_getExtraSize(void);
int suntemple_getObjectTypeId(void);
void suntemple_free(void);
void suntemple_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void suntemple_hitDetect(GameObject* obj);
int suntemple_interactCallback(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
void suntemple_init(GameObject* obj, SunTempleSetup* setup);
void suntemple_update(GameObject* obj);
void suntemple_release(void);
void suntemple_initialise(void);

#endif /* MAIN_DLL_DLL_0293_SUNTEMPLE_H */
