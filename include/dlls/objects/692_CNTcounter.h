#ifndef DLLS_OBJECTS_692_CNTCOUNTER_H_
#define DLLS_OBJECTS_692_CNTCOUNTER_H_

#include "global.h"
#include "game/objects/object_fwd.h"
#include "dlls/object_descriptor.h"
#include "game/objects/object_setup.h"

/* CntCounter_getExtraSize returns the required eight-byte state size. */
typedef struct CntCounterState {
    int remainingCount;
    u8 displayHud;
    u8 unknown05[3];
} CntCounterState;

STATIC_ASSERT(offsetof(CntCounterState, remainingCount) == 0x00);
STATIC_ASSERT(offsetof(CntCounterState, displayHud) == 0x04);
STATIC_ASSERT(offsetof(CntCounterState, unknown05) == 0x05);
STATIC_ASSERT(sizeof(CntCounterState) == 0x08);

/* Reader prefix through +0x21; the active EN serialized extent is unproven.
 * Secondary EN rev1 / JP placements are 0x24 bytes. Do not use this prefix's
 * sizeof as an allocation or copy size. */
typedef struct CntCounterPlacementPrefix
{
    ObjPlacement base;
    u8 unknown18;
    u8 displayHud;
    s16 initialCount;
    u8 unknown1C[2];
    s16 doneGameBit;
    s16 countInputGameBit; /* Starts an idle counter; supplies active decrements. */
} CntCounterPlacementPrefix;

STATIC_ASSERT(offsetof(CntCounterPlacementPrefix, base) == 0x00);
STATIC_ASSERT(offsetof(CntCounterPlacementPrefix, unknown18) == 0x18);
STATIC_ASSERT(offsetof(CntCounterPlacementPrefix, displayHud) == 0x19);
STATIC_ASSERT(offsetof(CntCounterPlacementPrefix, initialCount) == 0x1A);
STATIC_ASSERT(offsetof(CntCounterPlacementPrefix, unknown1C) == 0x1C);
STATIC_ASSERT(offsetof(CntCounterPlacementPrefix, doneGameBit) == 0x1E);
STATIC_ASSERT(offsetof(CntCounterPlacementPrefix, countInputGameBit) == 0x20);


extern ObjectDescriptor gCNTcounterObjDescriptor;

int CntCounter_getExtraSize(void);
int CntCounter_getObjectTypeId(void);
void CntCounter_free(GameObject* obj);
void CntCounter_hitDetect(void);
void CntCounter_render(void);
void CntCounter_init(GameObject* obj);
void CntCounter_update(GameObject* obj);
void CntCounter_release(void);
void CntCounter_initialise(void);

#endif
