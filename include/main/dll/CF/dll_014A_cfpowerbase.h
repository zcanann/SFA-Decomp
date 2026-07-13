#ifndef MAIN_DLL_CF_DLL_014A_CFPOWERBASE_H_
#define MAIN_DLL_CF_DLL_014A_CFPOWERBASE_H_

#include "global.h"
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"

typedef struct CfPowerBaseState
{
    s16 typeBit; /* gamebit 0x54..0x56, from params+0x1e */
    s16 litBit; /* gamebit 0x51..0x53 gating the lit state */
    s8 typeIndex; /* 0/1/2 trigger argument */
    u8 pad5;
} CfPowerBaseState;

typedef struct CfPowerBaseMapData
{
    ObjPlacement base;
    s8 rotXByte; /* 0x18: rotX in 1/256 turns */
    u8 pad19[5];
    s16 typeBit; /* 0x1E: type game bit (0x54..0x56) */
} CfPowerBaseMapData;

STATIC_ASSERT(offsetof(CfPowerBaseMapData, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(CfPowerBaseMapData, typeBit) == 0x1E);

int CFPowerBase_SeqFn(GameObject* p1, int unused, ObjAnimUpdateState* animUpdate);
int CFPowerBase_getExtraSize(void);
int CFPowerBase_getObjectTypeId(void);
void CFPowerBase_free(void);
void CFPowerBase_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void CFPowerBase_hitDetect(void);
void CFPowerBase_update(GameObject* obj);
void CFPowerBase_init(GameObject* obj, u8* params);
void CFPowerBase_release(void);
void CFPowerBase_initialise(void);

#endif /* MAIN_DLL_CF_DLL_014A_CFPOWERBASE_H_ */
