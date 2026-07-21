#ifndef MAIN_DLL_SB_DLL_01E9_SBPROPELLER_H_
#define MAIN_DLL_SB_DLL_01E9_SBPROPELLER_H_

#include "main/dll/sbshipheadstate_struct.h"
#include "main/dll/sbpropellerstate_struct.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"
#include "main/objhits.h"
#include "main/dll/DB/DBstealerworm.h"

typedef struct SBPropellerPlacement
{
    ObjPlacement base;
    u8 reserved18[2];
    s16 modelBankIndex;
} SBPropellerPlacement;

STATIC_ASSERT(offsetof(SBPropellerPlacement, modelBankIndex) == 0x1a);
STATIC_ASSERT(sizeof(SBPropellerPlacement) == 0x1c);

u32 sbGetPropeller(void);
int SB_Propeller_getExtraSize(void);
void SB_Propeller_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void SB_Propeller_hitDetect(GameObject* obj);
void SB_Propeller_update(GameObject* obj);
void SB_Propeller_init(GameObject* obj, SBPropellerPlacement* placement);

extern ObjectDescriptor gSB_PropellerObjDescriptor;

#endif
