#ifndef MAIN_DLL_BADDIE_CHUKACHUCK_H_
#define MAIN_DLL_BADDIE_CHUKACHUCK_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

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
void dfpfloorbar_release(void);
void dfpfloorbar_init(int obj, int params);
void dfpfloorbar_initialise(void);
extern u8 gDfpfloorbarModeTable[12];
extern ObjectDescriptor10WithPadding gDfpfloorbarObjDescriptor;

#endif /* MAIN_DLL_BADDIE_CHUKACHUCK_H_ */
