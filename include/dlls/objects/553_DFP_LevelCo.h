#ifndef DLLS_OBJECTS_553_DFP_LEVELCO_H_
#define DLLS_OBJECTS_553_DFP_LEVELCO_H_

#include "dlls/object_descriptor.h"
#include "dlls/objects/430_SH_LevelCon.h"
#include "game/objects/object.h"
#include "game/objects/object_setup.h"

/* EN establishes the mode halfword at 0x1A, not the complete record size. */
typedef struct DfpLevelControlPlacementPrefix {
    ObjPlacement base;
    u8 unk18[2];
    s16 mode;
} DfpLevelControlPlacementPrefix;

STATIC_ASSERT(offsetof(DfpLevelControlPlacementPrefix, mode) == 0x1A);
STATIC_ASSERT(offsetof(DfpLevelControlPlacementPrefix, base) == 0x00);

/* Export table reached by the electric-floor puzzle objects through anim.dll. */
typedef struct DfpLevelControlInterface {
    ObjectInterface base;
    void (*copySafeFloorTiles)(GameObject* controller, u8* out);
} DfpLevelControlInterface;

#define DFP_LEVEL_CONTROL_INTERFACE(controller) ((DfpLevelControlInterface*)*((GameObject*)(controller))->anim.dll)

STATIC_ASSERT(offsetof(DfpLevelControlInterface, base) == 0x00);
STATIC_ASSERT(offsetof(DfpLevelControlInterface, copySafeFloorTiles) == 0x20);
STATIC_ASSERT(sizeof(DfpLevelControlInterface) == 0x24);

/* Object ID used by both puzzle-bar consumers to find this controller. */
#define DFP_LEVEL_CONTROL_OBJECT_ID 0x431

typedef struct DfpLevelControlSfxState {
    u8 triggerD5d : 1;
    u8 triggerD59 : 1;
    u8 triggerD5a : 1;
    u8 unused : 5;
} DfpLevelControlSfxState;

/* DFP_LevelControl_getExtraSize returns the complete 0x0C-byte allocation. */
typedef struct DfpLevelControlState {
    s16 zappedTimer;   /* counts down by timeDelta; set to 300 when the player is zapped */
    s16 placementMode; /* accepts nonzero values <=2; no subsequent reader in this TU */
    u8 unk04[2];
    u8 previousPuzzlePadState; /* GAMEBIT_OFP_PuzzlePadPressed as of the previous frame */
    DfpLevelControlSfxState previousSfxState;
    GameBitLatchState musicLatch;
} DfpLevelControlState;

STATIC_ASSERT(sizeof(DfpLevelControlSfxState) == 0x01);
STATIC_ASSERT(offsetof(DfpLevelControlState, zappedTimer) == 0x00);
STATIC_ASSERT(offsetof(DfpLevelControlState, placementMode) == 0x02);
STATIC_ASSERT(offsetof(DfpLevelControlState, previousPuzzlePadState) == 0x06);
STATIC_ASSERT(offsetof(DfpLevelControlState, previousSfxState) == 0x07);
STATIC_ASSERT(offsetof(DfpLevelControlState, musicLatch) == 0x08);
STATIC_ASSERT(sizeof(DfpLevelControlState) == 0x0C);

extern ObjectDescriptor11ExtraSize gDFP_LevelControlObjDescriptor;
extern s16 gDFPLevelControlSafeFloorTiles[9];
extern s16 gDFPLevelControlMapAct1Timer;
extern u8 gDFPLevelControlInitialiseAct1;
extern u8 gDFPLevelControlInitialiseAct2;

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
void DFP_LevelControl_init(GameObject* obj, DfpLevelControlPlacementPrefix* placement);
void DFP_LevelControl_release(void);
void DFP_LevelControl_initialise(void);

#endif /* DLLS_OBJECTS_553_DFP_LEVELCO_H_ */
