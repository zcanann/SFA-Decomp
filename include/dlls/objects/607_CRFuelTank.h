#ifndef DLLS_OBJECTS_607_CRFUELTANK_H_
#define DLLS_OBJECTS_607_CRFUELTANK_H_

#include "types.h"
#include "game/objects/object.h"
#include "game/objects/object_setup.h"
#include "dlls/object_descriptor.h"

/* crfueltank_getExtraSize returns 0x10 in retail EN. */
typedef struct CrFuelTankState {
    u8 unk00[0xC];
    f32 respawnTimer;
} CrFuelTankState;

STATIC_ASSERT(offsetof(CrFuelTankState, respawnTimer) == 0xC);
STATIC_ASSERT(sizeof(CrFuelTankState) == 0x10);

/* EN reader view only: the complete serialized extent is not established.
 * EN rev1 and JP cloudrace records are 0x24 bytes. Do not allocate or copy a
 * placement using sizeof this prefix.
 */
typedef struct CrFuelTankPlacementPrefix {
    ObjPlacement base;
    u8 unk18[2];
    s16 hitVolumeIdTimes10;
    u8 unk1C[2];
    s16 hitGameBit;
} CrFuelTankPlacementPrefix;

STATIC_ASSERT(offsetof(CrFuelTankPlacementPrefix, base) == 0);
STATIC_ASSERT(offsetof(CrFuelTankPlacementPrefix, hitVolumeIdTimes10) == 0x1A);
STATIC_ASSERT(offsetof(CrFuelTankPlacementPrefix, hitGameBit) == 0x1E);

extern ObjectDescriptor gCrFuelTankObjDescriptor;

int crfueltank_getExtraSize(void);
int crfueltank_getObjectTypeId(void);
void crfueltank_free(void);
void crfueltank_render(void);
void crfueltank_hitDetect(GameObject* obj);
void crfueltank_update(GameObject* obj);
void crfueltank_init(GameObject* obj, CrFuelTankPlacementPrefix* def);
void crfueltank_release(void);
void crfueltank_initialise(void);

#endif /* DLLS_OBJECTS_607_CRFUELTANK_H_ */
