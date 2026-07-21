#ifndef MAIN_DLL_MMP_DLL_010F_MMPBRIDGE_H_
#define MAIN_DLL_MMP_DLL_010F_MMPBRIDGE_H_

#include "global.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"

typedef struct MmpBridgePlacement
{
    ObjPlacement base;
    s8 rotXByte; /* 0x18: rotX in 1/256 turns */
    u8 pad19[0x1E - 0x19];
    s16 enableBit; /* 0x1E: gamebit that deploys the bridge */
} MmpBridgePlacement;

STATIC_ASSERT(offsetof(MmpBridgePlacement, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(MmpBridgePlacement, enableBit) == 0x1e);
STATIC_ASSERT(sizeof(MmpBridgePlacement) == 0x20);

int mmp_bridge_getExtraSize(void);
int mmp_bridge_getObjectTypeId(void);
void mmp_bridge_free(void);
void mmp_bridge_render(void);
void mmp_bridge_hitDetect(void);
void mmp_bridge_update(GameObject* obj);
void mmp_bridge_init(GameObject* obj);
void mmp_bridge_release(void);
void mmp_bridge_initialise(void);

extern ObjectDescriptor gMMP_BridgeObjDescriptor;

#endif /* MAIN_DLL_MMP_DLL_010F_MMPBRIDGE_H_ */
