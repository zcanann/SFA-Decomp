#ifndef MAIN_DLL_CF_DLL_014A_CFPOWERBASE_H_
#define MAIN_DLL_CF_DLL_014A_CFPOWERBASE_H_

#include "global.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"

typedef struct CfPowerBaseState
{
    s16 poweredGameBit; /* gamebit 0x54..0x56, from placement +0x1e */
    s16 crystalGameBit; /* held power gem 0x51..0x53, consumed on activation */
    s8 baseIndex; /* 0/1/2 trigger-sequence index */
    u8 pad5;
} CfPowerBaseState;

typedef struct CfPowerBaseMapData
{
    ObjPlacement base;
    s8 rotX; /* 0x18: rotation in 1/256 turns */
    u8 pad19[5];
    s16 poweredGameBit; /* 0x1E: base-powered game bit (0x54..0x56) */
} CfPowerBaseMapData;

STATIC_ASSERT(sizeof(CfPowerBaseMapData) == 0x20);
STATIC_ASSERT(offsetof(CfPowerBaseMapData, rotX) == 0x18);
STATIC_ASSERT(offsetof(CfPowerBaseMapData, poweredGameBit) == 0x1E);

int CFPowerBase_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int CFPowerBase_getExtraSize(void);
int CFPowerBase_getObjectTypeId(void);
void CFPowerBase_free(void);
void CFPowerBase_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void CFPowerBase_hitDetect(void);
void CFPowerBase_update(GameObject* obj);
void CFPowerBase_init(GameObject* obj, CfPowerBaseMapData* placement);
void CFPowerBase_release(void);
void CFPowerBase_initialise(void);

extern ObjectDescriptor gCFPowerBaseObjDescriptor;

#endif /* MAIN_DLL_CF_DLL_014A_CFPOWERBASE_H_ */
