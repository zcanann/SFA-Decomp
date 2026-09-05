#ifndef DLLS_OBJECTS_547_VFP_COREPLA_H_
#define DLLS_OBJECTS_547_VFP_COREPLA_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"

typedef struct VfpCorePlatformState {
    s16 gameBitId;
    u8 pad02[2];
} VfpCorePlatformState;

typedef struct VfpCorePlatformPlacement {
    ObjPlacement base;
    s8 rotXByte;
    u8 axisMode;
    u8 pad1A[6];
    s16 gameBitId;
} VfpCorePlatformPlacement;

STATIC_ASSERT(sizeof(VfpCorePlatformState) == 0x4);

STATIC_ASSERT(offsetof(VfpCorePlatformState, gameBitId) == 0x0);
STATIC_ASSERT(offsetof(VfpCorePlatformPlacement, base) == 0x0);
STATIC_ASSERT(offsetof(VfpCorePlatformPlacement, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(VfpCorePlatformPlacement, gameBitId) == 0x20);

int VFP_coreplat_sequenceCallback(void);
int VFP_coreplat_getExtraSize(void);
int VFP_coreplat_getObjectTypeId(void);
void VFP_coreplat_free(int obj);
void VFP_coreplat_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void VFP_coreplat_hitDetect(void);
void VFP_coreplat_update(void);
void VFP_coreplat_init(GameObject* obj, VfpCorePlatformPlacement* data);
void VFP_coreplat_release(void);
void VFP_coreplat_initialise(void);

extern ObjectDescriptor gVFP_coreplatObjDescriptor;

#endif /* DLLS_OBJECTS_547_VFP_COREPLA_H_ */
