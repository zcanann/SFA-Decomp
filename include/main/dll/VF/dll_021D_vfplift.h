#ifndef MAIN_DLL_VF_DLL_021D_VFPLIFT_H_
#define MAIN_DLL_VF_DLL_021D_VFPLIFT_H_

#include "ghidra_import.h"
#include "main/game_object.h"
#include "global.h"
#include "main/obj_placement.h"

typedef struct VfpLiftState
{
    f32 travelDistance;
    u8 pad04[0x0a - 0x04];
    s16 mode;
    s16 hitDisableGameBit;
    s16 toggleGameBit;
    u8 pad10[0x12 - 0x10];
    s16 anim[4];
    u8 mapEventNo;
    u8 pad1b;
    u8 applyHeight : 1;
    u8 forceRaised : 1;
    u8 flagsPad : 6;
} VfpLiftState;

typedef struct VfpLiftPlacement
{
    ObjPlacement base;
    s8 rotXByte;
    u8 pad19;
    s16 travelDistance;
    s16 mapEventNo;
    s16 toggleGameBit;
    s16 hitDisableGameBit;
} VfpLiftPlacement;

STATIC_ASSERT(sizeof(VfpLiftState) == 0x20);
STATIC_ASSERT(offsetof(VfpLiftState, travelDistance) == 0x00);
STATIC_ASSERT(offsetof(VfpLiftState, mode) == 0x0A);
STATIC_ASSERT(offsetof(VfpLiftState, hitDisableGameBit) == 0x0C);
STATIC_ASSERT(offsetof(VfpLiftState, toggleGameBit) == 0x0E);
STATIC_ASSERT(offsetof(VfpLiftState, anim) == 0x12);
STATIC_ASSERT(offsetof(VfpLiftState, mapEventNo) == 0x1A);
STATIC_ASSERT(sizeof(VfpLiftPlacement) == 0x24);
STATIC_ASSERT(offsetof(VfpLiftPlacement, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(VfpLiftPlacement, travelDistance) == 0x1A);
STATIC_ASSERT(offsetof(VfpLiftPlacement, mapEventNo) == 0x1C);
STATIC_ASSERT(offsetof(VfpLiftPlacement, toggleGameBit) == 0x1E);
STATIC_ASSERT(offsetof(VfpLiftPlacement, hitDisableGameBit) == 0x20);

int VFPLift_SeqFn(GameObject* obj);
void vfplift23_updateState(GameObject* obj);
void vfplift1_updateState(GameObject* obj);
int VFPLift_getExtraSize(void);
int VFPLift_getObjectTypeId(void);
void VFPLift_free(int obj);
void VFPLift_render(int p1, int p2, int p3, int p4, int p5, s8 vis);
void VFPLift_hitDetect(GameObject* obj);
void VFPLift_update(GameObject* obj);
void VFPLift_init(int* obj, VfpLiftPlacement* init);
void VFPLift_release(void);
void VFPLift_initialise(void);

#endif /* MAIN_DLL_VF_DLL_021D_VFPLIFT_H_ */
