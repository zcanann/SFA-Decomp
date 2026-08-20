#ifndef MAIN_DLL_DF_DLL_0229_DFPLEVELCONTROL_H_
#define MAIN_DLL_DF_DLL_0229_DFPLEVELCONTROL_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object.h"
#include "game/objects/object_setup.h"

typedef struct DfpLevelControlPlacement
{
    ObjPlacement base;
    u8 unk18[2];
    s16 mode;
} DfpLevelControlPlacement;

STATIC_ASSERT(offsetof(DfpLevelControlPlacement, mode) == 0x1A);
STATIC_ASSERT(sizeof(DfpLevelControlPlacement) == 0x1C);

/* Export table reached by the electric-floor puzzle objects through anim.dll. */
typedef struct DfpLevelControlInterface
{
    void* pad00[8];
    void (*copySafeFloorTiles)(GameObject* controller, u8* out);
} DfpLevelControlInterface;

#define DFP_LEVEL_CONTROL_INTERFACE(controller) \
    ((DfpLevelControlInterface*)*((GameObject*)(controller))->anim.dll)

STATIC_ASSERT(offsetof(DfpLevelControlInterface, copySafeFloorTiles) == 0x20);

extern ObjectDescriptor11ExtraSize gDFP_LevelControlObjDescriptor;
extern s16 gDFPLevelControlSafeFloorTiles[10];

void DFP_LevelControl_updateAct2(GameObject* obj);
void DFP_LevelControl_updateAct1(GameObject* obj);
int DFP_LevelControl_animCallback(GameObject* obj);
void DFP_LevelControl_copySafeFloorTiles(GameObject* unused, u8* out);
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
