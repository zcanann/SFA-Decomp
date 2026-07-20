#ifndef MAIN_DLL_BADDIE_DLL_022F_DFPFLOORBAR_H_
#define MAIN_DLL_BADDIE_DLL_022F_DFPFLOORBAR_H_

#include "main/game_object.h"
#include "ghidra_import.h"
#include "main/object_descriptor.h"

#define DFPFLOORBAR_MODE_ROW_COUNT     3
#define DFPFLOORBAR_MODE_ROW_SIZE      3
#define DFPFLOORBAR_MODE_COUNT         (DFPFLOORBAR_MODE_ROW_COUNT * DFPFLOORBAR_MODE_ROW_SIZE)
#define DFPFLOORBAR_MODE_TABLE_STORAGE 12

typedef struct DfpFloorbarState
{
    s16 triggerGameBit;
    s16 completionGameBit;
    u8 active;
    u8 modeIndex;
    u8 requiredScore;
    u8 lastSequenceValue;
    int* linkedObject;
} DfpFloorbarState;

int dfpfloorbar_SeqFn(void);
int DFP_Floorbar_getExtraSize(void);
int DFP_Floorbar_getObjectTypeId(void);
void DFP_Floorbar_free(int* obj);
void DFP_Floorbar_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void DFP_Floorbar_hitDetect(int* obj);
void DFP_Floorbar_update(GameObject* obj);
void DFP_Floorbar_init(GameObject* obj, int params);
void DFP_Floorbar_release(void);
void DFP_Floorbar_initialise(void);
extern u8 gDfpfloorbarModeTable[DFPFLOORBAR_MODE_TABLE_STORAGE];
extern ObjectDescriptor10WithPadding gDfpfloorbarObjDescriptor;

#endif /* MAIN_DLL_BADDIE_DLL_022F_DFPFLOORBAR_H_ */
