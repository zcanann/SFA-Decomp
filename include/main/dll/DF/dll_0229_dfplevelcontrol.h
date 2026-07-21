#ifndef MAIN_DLL_DF_DLL_0229_DFPLEVELCONTROL_H_
#define MAIN_DLL_DF_DLL_0229_DFPLEVELCONTROL_H_

#include "main/object_descriptor.h"
#include "main/game_object.h"
#include "main/obj_placement.h"

typedef struct DfpLevelControlPlacement
{
    ObjPlacement base;
    u8 unk18[2];
    s16 mode;
} DfpLevelControlPlacement;

STATIC_ASSERT(offsetof(DfpLevelControlPlacement, mode) == 0x1A);
STATIC_ASSERT(sizeof(DfpLevelControlPlacement) == 0x1C);

extern ObjectDescriptor11 gDFP_LevelControlObjDescriptor;
extern s16 gDFPLevelControlPuzzleValues[10];

void DFP_LevelControl_updateMapAct2(GameObject* obj);
void DFP_LevelControl_updateMapAct1(GameObject* obj);
int DFP_LevelControl_sequenceCallback(GameObject* obj);
void DFP_LevelControl_copyPuzzleValues(int unused, u8* out);
int DFP_LevelControl_getExtraSize(void);
int DFP_LevelControl_getObjectTypeId(void);
void DFP_LevelControl_free(GameObject* obj);
void DFP_LevelControl_render(void);
void DFP_LevelControl_hitDetect(void);
void DFP_LevelControl_update(GameObject* obj);
void DFP_LevelControl_init(GameObject* obj, DfpLevelControlPlacement* placement);
void DFP_LevelControl_release(void);
void DFP_LevelControl_initialise(void);

#endif /* MAIN_DLL_DF_DLL_0229_DFPLEVELCONTROL_H_ */
