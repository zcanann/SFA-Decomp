#ifndef DLLS_OBJECTS_489_SB_PROPELLE_H_
#define DLLS_OBJECTS_489_SB_PROPELLE_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"

typedef struct SBPropellerState {
    f32 smokeTimer;
    f32 spinBlend;
    s32 spinRate;
    s8 health;
    u8 unk0D[0x03];
} SBPropellerState;

/*
 * Only the field consumed by this DLL is modeled. The active-target retail
 * placement files are unavailable, so this does not claim a complete record
 * width.
 */
typedef struct SBPropellerPlacementView {
    ObjPlacement base;
    u8 unk18[0x02];
    s16 modelBankIndex;
} SBPropellerPlacementView;

STATIC_ASSERT(offsetof(SBPropellerState, smokeTimer) == 0x00);
STATIC_ASSERT(offsetof(SBPropellerState, spinBlend) == 0x04);
STATIC_ASSERT(offsetof(SBPropellerState, spinRate) == 0x08);
STATIC_ASSERT(offsetof(SBPropellerState, health) == 0x0C);
STATIC_ASSERT(sizeof(SBPropellerState) == 0x10);

STATIC_ASSERT(offsetof(SBPropellerPlacementView, base) == 0x00);
STATIC_ASSERT(offsetof(SBPropellerPlacementView, modelBankIndex) == 0x1A);

GameObject* sbGetPropeller(void);
int SB_Propeller_getExtraSize(void);
void SB_Propeller_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible);
void SB_Propeller_hitDetect(GameObject* obj);
void SB_Propeller_update(GameObject* obj);
void SB_Propeller_init(GameObject* obj, SBPropellerPlacementView* placement);

extern ObjectDescriptor gSB_PropellerObjDescriptor;

#endif /* DLLS_OBJECTS_489_SB_PROPELLE_H_ */
