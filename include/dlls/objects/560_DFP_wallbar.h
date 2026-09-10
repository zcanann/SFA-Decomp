#ifndef DLLS_OBJECTS_560_DFP_WALLBAR_H_
#define DLLS_OBJECTS_560_DFP_WALLBAR_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object.h"
#include "game/objects/object_setup.h"

/* EN accesses establish this prefix through the halfword at 0x1C.
 * The complete placement record size is not yet verified. */
typedef struct DfpWallbarPlacementPrefix {
    ObjPlacement base;
    s8 rotationHighByte;
    u8 rowIndex;
    s16 initialRotZ;
    s16 motionScaleDivisor;
} DfpWallbarPlacementPrefix;

/* chuka_getExtraSize returns the complete 0x0C-byte allocation. */
typedef struct DfpWallbarState {
    f32 initialLocalPosY; /* initialized only; no reader in this TU */
    GameObject* levelController;
    u8 rowIndex;
    u8 safeTileIndex;
    u8 unk0A[2];
} DfpWallbarState;

STATIC_ASSERT(offsetof(DfpWallbarPlacementPrefix, base) == 0x00);
STATIC_ASSERT(offsetof(DfpWallbarPlacementPrefix, rotationHighByte) == 0x18);
STATIC_ASSERT(offsetof(DfpWallbarPlacementPrefix, rowIndex) == 0x19);
STATIC_ASSERT(offsetof(DfpWallbarPlacementPrefix, initialRotZ) == 0x1A);
STATIC_ASSERT(offsetof(DfpWallbarPlacementPrefix, motionScaleDivisor) == 0x1C);

STATIC_ASSERT(offsetof(DfpWallbarState, initialLocalPosY) == 0x00);
STATIC_ASSERT(offsetof(DfpWallbarState, levelController) == 0x04);
STATIC_ASSERT(offsetof(DfpWallbarState, rowIndex) == 0x08);
STATIC_ASSERT(offsetof(DfpWallbarState, safeTileIndex) == 0x09);
STATIC_ASSERT(sizeof(DfpWallbarState) == 0x0C);

extern u8 gDFPWallbarSafeFloorTiles[9];
extern ObjectDescriptor10WithPadding gChukaObjDescriptor;

int chuka_SeqFn(void);
int chuka_getExtraSize(void);
int chuka_getObjectTypeId(void);
void chuka_free(GameObject* obj);
void chuka_render(void);
void chuka_hitDetect(GameObject* obj);
void chuka_update(GameObject* obj);
void chuka_init(GameObject* obj, DfpWallbarPlacementPrefix* params);
void chuka_release(void);
void chuka_initialise(void);

#endif /* DLLS_OBJECTS_560_DFP_WALLBAR_H_ */
