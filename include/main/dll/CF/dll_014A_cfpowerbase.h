#ifndef MAIN_DLL_CF_DLL_014A_CFPOWERBASE_H_
#define MAIN_DLL_CF_DLL_014A_CFPOWERBASE_H_

#include "global.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"

typedef struct CfPowerBaseMapData
{
    ObjPlacement base;
    s8 rotXByte; /* 0x18: rotX in 1/256 turns */
    u8 pad19[5];
    s16 typeBit; /* 0x1E: type game bit (0x54..0x56) */
} CfPowerBaseMapData;

STATIC_ASSERT(offsetof(CfPowerBaseMapData, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(CfPowerBaseMapData, typeBit) == 0x1E);

int CFPowerBase_SeqFn(int p1, int unused, ObjAnimUpdateState* animUpdate);
void CFPowerBase_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

#endif /* MAIN_DLL_CF_DLL_014A_CFPOWERBASE_H_ */
