#ifndef MAIN_DLL_VF_DLL_0216_VFPLEVELCONTROL_H_
#define MAIN_DLL_VF_DLL_0216_VFPLEVELCONTROL_H_

#include "main/game_object.h"
#include "ghidra_import.h"
#include "global.h"

typedef union VfpLevelControlLatch
{
    u8 raw[8];

    struct
    {
        u8 pad00[4];
        u8 sequenceStep; /* 0x04: index of the next sequence bit to light */
        u8 pad05[3];
    } fields;
} VfpLevelControlLatch;

typedef struct VfpLevelControlState
{
    u8 pad00[2];
    s16 unk02[6]; /* 0x02: cleared at init, never read back */
    s16 areaMode; /* 0x0E: 1..2, from setup (defaults to 1) */
    u8 pad10[4];
    VfpLevelControlLatch latch; /* 0x14 */
} VfpLevelControlState;

typedef struct VfpLevelControlSetup
{
    u8 pad00[0x1a];
    s16 areaMode; /* 0x1A */
} VfpLevelControlSetup;

STATIC_ASSERT(offsetof(VfpLevelControlState, unk02) == 0x02);
STATIC_ASSERT(offsetof(VfpLevelControlState, areaMode) == 0x0E);
STATIC_ASSERT(offsetof(VfpLevelControlState, latch) == 0x14);
STATIC_ASSERT(sizeof(VfpLevelControlState) == 0x1c);
STATIC_ASSERT(offsetof(VfpLevelControlLatch, fields.sequenceStep) == 0x04);
STATIC_ASSERT(offsetof(VfpLevelControlSetup, areaMode) == 0x1A);

extern int lbl_803DC148;

void fn_801F9804(GameObject* obj);
int VFP_LevelControl_getExtraSize(void);
int VFP_LevelControl_getObjectTypeId(void);
void VFP_LevelControl_free(GameObject* obj);
void VFP_LevelControl_render(void);
void VFP_LevelControl_hitDetect(void);
void VFP_LevelControl_update(GameObject* obj);
void VFP_LevelControl_init(GameObject* obj, VfpLevelControlSetup* setup);
void VFP_LevelControl_release(void);
void VFP_LevelControl_initialise(void);

#endif /* MAIN_DLL_VF_DLL_0216_VFPLEVELCONTROL_H_ */
