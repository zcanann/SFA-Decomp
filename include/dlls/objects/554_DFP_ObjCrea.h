#ifndef DLLS_OBJECTS_554_DFP_OBJCREA_H_
#define DLLS_OBJECTS_554_DFP_OBJCREA_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object.h"
#include "game/objects/object_setup.h"

/* EN accesses establish this prefix through byte 0x20. The complete EN
 * record extent is unverified; secondary romlists use 0x24-byte records. */
typedef struct DfpObjCreatorPlacementPrefix {
    ObjPlacement base;
    s16 gameBit;
    s16 behaviorMode;
    s16 spawnPeriod;
    union {
        s8 rotationHighByte;
        s8 childUserData1;
    } parameter;
    s8 unk1F;
    u8 unk20;
} DfpObjCreatorPlacementPrefix;

/* DFP_ObjCreator_getExtraSize returns 0x1C in retail EN. */
typedef struct DfpObjCreatorState {
    GameObject* ownedObj; /* freed on final destruction; no assignment in this TU */
    u8 unk04[8];
    s16 gameBit;
    s16 spawnPeriod;
    s16 spawnTimer;
    s16 unk12;
    s16 unk14;
    s16 unk16;
    u8 unk18[4];
} DfpObjCreatorState;

STATIC_ASSERT(offsetof(DfpObjCreatorPlacementPrefix, base) == 0x00);
STATIC_ASSERT(offsetof(DfpObjCreatorPlacementPrefix, gameBit) == 0x18);
STATIC_ASSERT(offsetof(DfpObjCreatorPlacementPrefix, behaviorMode) == 0x1A);
STATIC_ASSERT(offsetof(DfpObjCreatorPlacementPrefix, spawnPeriod) == 0x1C);
STATIC_ASSERT(offsetof(DfpObjCreatorPlacementPrefix, parameter.rotationHighByte) == 0x1E);
STATIC_ASSERT(offsetof(DfpObjCreatorPlacementPrefix, parameter.childUserData1) == 0x1E);
STATIC_ASSERT(offsetof(DfpObjCreatorPlacementPrefix, unk1F) == 0x1F);
STATIC_ASSERT(offsetof(DfpObjCreatorPlacementPrefix, unk20) == 0x20);

STATIC_ASSERT(offsetof(DfpObjCreatorState, ownedObj) == 0x00);
STATIC_ASSERT(offsetof(DfpObjCreatorState, gameBit) == 0x0C);
STATIC_ASSERT(offsetof(DfpObjCreatorState, spawnPeriod) == 0x0E);
STATIC_ASSERT(offsetof(DfpObjCreatorState, spawnTimer) == 0x10);
STATIC_ASSERT(offsetof(DfpObjCreatorState, unk12) == 0x12);
STATIC_ASSERT(offsetof(DfpObjCreatorState, unk14) == 0x14);
STATIC_ASSERT(offsetof(DfpObjCreatorState, unk16) == 0x16);
STATIC_ASSERT(sizeof(DfpObjCreatorState) == 0x1C);

extern ObjectDescriptor gDFP_ObjCreatorObjDescriptor;

int DFP_ObjCreator_getExtraSize(void);
int DFP_ObjCreator_getObjectTypeId(void);
void DFP_ObjCreator_free(GameObject* obj, int flag);
void DFP_ObjCreator_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void DFP_ObjCreator_hitDetect(void);
void DFP_ObjCreator_update(GameObject* obj);
void DFP_ObjCreator_init(GameObject* obj, DfpObjCreatorPlacementPrefix* placement);
void DFP_ObjCreator_release(void);
void DFP_ObjCreator_initialise(void);

#endif /* DLLS_OBJECTS_554_DFP_OBJCREA_H_ */
