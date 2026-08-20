#ifndef MAIN_DLL_BADDIE_DLL_022F_DFPFLOORBAR_H_
#define MAIN_DLL_BADDIE_DLL_022F_DFPFLOORBAR_H_

#include "game/objects/object.h"
#include "types.h"
#include "dlls/object_descriptor.h"

typedef struct DfpfloorbarPlacement DfpfloorbarPlacement;

#define DFPFLOORBAR_MODE_ROW_COUNT     3
#define DFPFLOORBAR_MODE_ROW_SIZE      3
#define DFPFLOORBAR_MODE_COUNT         (DFPFLOORBAR_MODE_ROW_COUNT * DFPFLOORBAR_MODE_ROW_SIZE)
#define DFPFLOORBAR_MODE_TABLE_STORAGE 12

typedef struct DfpFloorbarState
{
    s16 triggerGameBit;
    s16 loweredGameBit;
    u8 lowered;
    u8 rowIndex;
    u8 safeTileIndex;
    u8 previousShowSolutionState;
    int* levelController;
} DfpFloorbarState;

int dfpfloorbar_SeqFn(void);
int DFP_Floorbar_getExtraSize(void);
int DFP_Floorbar_getObjectTypeId(void);
void DFP_Floorbar_free(GameObject* obj);
void DFP_Floorbar_render(GameObject* p1, int p2, int p3, int p4, int p5, s8 visible);
void DFP_Floorbar_hitDetect(GameObject* obj);
void DFP_Floorbar_update(GameObject* obj);
void DFP_Floorbar_init(GameObject* obj, DfpfloorbarPlacement* params);
void DFP_Floorbar_release(void);
void DFP_Floorbar_initialise(void);
extern u8 gDFPFloorbarSafeFloorTiles[DFPFLOORBAR_MODE_TABLE_STORAGE];
extern ObjectDescriptor10WithPadding gDfpfloorbarObjDescriptor;

#endif /* MAIN_DLL_BADDIE_DLL_022F_DFPFLOORBAR_H_ */
