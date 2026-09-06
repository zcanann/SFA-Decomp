#ifndef DLLS_OBJECTS_544_H_
#define DLLS_OBJECTS_544_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"

typedef struct VfpDoorSwitchState {
    s16 gameBitId;
    u8 activated : 1;
    u8 exploded : 1;
    u8 _state2_lo : 6;
} VfpDoorSwitchState;

typedef struct VfpDoorSwitchPlacement {
    ObjPlacement base;
    s8 rotXByte;
    s8 rotZByte;
    u8 pad1A[2];
    s16 rotY;
    s16 gameBitId;
} VfpDoorSwitchPlacement;

STATIC_ASSERT(offsetof(VfpDoorSwitchState, gameBitId) == 0x0);
STATIC_ASSERT(sizeof(VfpDoorSwitchState) == 0x4);
STATIC_ASSERT(offsetof(VfpDoorSwitchPlacement, base) == 0x0);
STATIC_ASSERT(offsetof(VfpDoorSwitchPlacement, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(VfpDoorSwitchPlacement, rotZByte) == 0x19);
STATIC_ASSERT(offsetof(VfpDoorSwitchPlacement, rotY) == 0x1C);
STATIC_ASSERT(offsetof(VfpDoorSwitchPlacement, gameBitId) == 0x1E);

void vfpdoorswitch_updateExplodingVariant(GameObject* obj);
int VFP_DoorSwitch_getExtraSize(void);
int VFP_DoorSwitch_getObjectTypeId(void);
void VFP_DoorSwitch_free(int obj);
void VFP_DoorSwitch_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void VFP_DoorSwitch_hitDetect(void);
void VFP_DoorSwitch_update(GameObject* obj);
void VFP_DoorSwitch_init(GameObject* obj, VfpDoorSwitchPlacement* data);
void VFP_DoorSwitch_release(void);
void VFP_DoorSwitch_initialise(void);

extern ObjectDescriptor gVFP_DoorSwitchObjDescriptor;

#endif /* DLLS_OBJECTS_544_H_ */
