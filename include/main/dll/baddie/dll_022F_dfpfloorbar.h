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

void dfpfloorbar_update(int param_1);
int dfpfloorbar_SeqFn(void);
void dfpfloorbar_release(void);
void dfpfloorbar_init(int obj, int params);
void dfpfloorbar_initialise(void);
extern u8 gDfpfloorbarModeTable[DFPFLOORBAR_MODE_TABLE_STORAGE];
extern ObjectDescriptor10WithPadding gDfpfloorbarObjDescriptor;

#endif /* MAIN_DLL_BADDIE_DLL_022F_DFPFLOORBAR_H_ */
