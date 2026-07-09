#ifndef MAIN_DLL_BADDIE_DLL_022F_DFPFLOORBAR_H_
#define MAIN_DLL_BADDIE_DLL_022F_DFPFLOORBAR_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

#define DFPFLOORBAR_MODE_ROW_COUNT 3
#define DFPFLOORBAR_MODE_ROW_SIZE 3
#define DFPFLOORBAR_MODE_COUNT (DFPFLOORBAR_MODE_ROW_COUNT * DFPFLOORBAR_MODE_ROW_SIZE)
#define DFPFLOORBAR_MODE_TABLE_STORAGE 12

typedef struct DfpFloorbarState {
    s16 triggerGameBit;
    s16 completionGameBit;
    u8 active;
    u8 modeIndex;
    u8 requiredScore;
    u8 lastSequenceValue;
    int *linkedObject;
} DfpFloorbarState;

void DFP_Floorbar_update(int param_1);
int dfpfloorbar_SeqFn(void);
void DFP_Floorbar_release(void);
void DFP_Floorbar_init(struct GameObject *obj, int params);
void DFP_Floorbar_initialise(void);
extern u8 gDfpfloorbarModeTable[DFPFLOORBAR_MODE_TABLE_STORAGE];
extern ObjectDescriptor10WithPadding gDfpfloorbarObjDescriptor;

#endif /* MAIN_DLL_BADDIE_DLL_022F_DFPFLOORBAR_H_ */
