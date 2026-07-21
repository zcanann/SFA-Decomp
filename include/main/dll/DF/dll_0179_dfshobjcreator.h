#ifndef MAIN_DLL_DF_DLL_0179_DFSHOBJCREATOR_H_
#define MAIN_DLL_DF_DLL_0179_DFSHOBJCREATOR_H_

#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"

typedef struct DfshObjCreatorPlacement
{
    ObjPlacement base;
    u8 pad18[0x1E - 0x18];
    s8 rotByte;
    s8 triggerGameBitOffset;
} DfshObjCreatorPlacement;

typedef struct DfshObjCreatorSpawnSetup
{
    ObjPlacement base;
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    u8 pad1E[0x22 - 0x1E];
    s16 unk22;
    u8 pad24[0x27 - 0x24];
    u8 unk27;
    u8 pad28;
    u8 unk29;
    s8 rotByte;
    u8 unk2B;
    u8 pad2C[0x2E - 0x2C];
    s8 unk2E;
    u8 pad2F;
    s16 unk30;
    u8 pad32[0x34 - 0x32];
    u16 unk34;
    u8 pad36[0x38 - 0x36];
} DfshObjCreatorSpawnSetup;

typedef struct DfshObjCreatorState
{
    s16 spawnTimer;
    s16 spawnTimerStep;
} DfshObjCreatorState;

STATIC_ASSERT(offsetof(DfshObjCreatorPlacement, rotByte) == 0x1E);
STATIC_ASSERT(offsetof(DfshObjCreatorPlacement, triggerGameBitOffset) == 0x1F);
STATIC_ASSERT(offsetof(DfshObjCreatorSpawnSetup, unk18) == 0x18);
STATIC_ASSERT(offsetof(DfshObjCreatorSpawnSetup, unk22) == 0x22);
STATIC_ASSERT(offsetof(DfshObjCreatorSpawnSetup, unk27) == 0x27);
STATIC_ASSERT(offsetof(DfshObjCreatorSpawnSetup, unk29) == 0x29);
STATIC_ASSERT(offsetof(DfshObjCreatorSpawnSetup, rotByte) == 0x2A);
STATIC_ASSERT(offsetof(DfshObjCreatorSpawnSetup, unk2E) == 0x2E);
STATIC_ASSERT(offsetof(DfshObjCreatorSpawnSetup, unk30) == 0x30);
STATIC_ASSERT(offsetof(DfshObjCreatorSpawnSetup, unk34) == 0x34);
STATIC_ASSERT(sizeof(DfshObjCreatorSpawnSetup) == 0x38);
STATIC_ASSERT(offsetof(DfshObjCreatorState, spawnTimer) == 0x0);
STATIC_ASSERT(offsetof(DfshObjCreatorState, spawnTimerStep) == 0x2);
STATIC_ASSERT(sizeof(DfshObjCreatorState) == 0x4);

int DFSH_ObjCreator_getExtraSize(void);
int DFSH_ObjCreator_getObjectTypeId(void);
void DFSH_ObjCreator_free(void);
void DFSH_ObjCreator_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void DFSH_ObjCreator_hitDetect(void);
void DFSH_ObjCreator_update(GameObject* obj);
void DFSH_ObjCreator_init(GameObject* obj, DfshObjCreatorPlacement* placement);
void DFSH_ObjCreator_release(void);
void DFSH_ObjCreator_initialise(void);

extern const f32 gDfshObjCreatorRenderScale;
extern ObjectDescriptor gDFSH_ObjCreatorObjDescriptor;

#endif /* MAIN_DLL_DF_DLL_0179_DFSHOBJCREATOR_H_ */
