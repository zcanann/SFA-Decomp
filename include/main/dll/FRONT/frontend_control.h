#ifndef MAIN_DLL_FRONT_FRONTEND_CONTROL_H_
#define MAIN_DLL_FRONT_FRONTEND_CONTROL_H_

#include "types.h"

typedef struct FrontendSaveSlot {
    char name[4];
    u8 completionPercent;
    u8 rankA;
    u8 rankB;
    u8 pad07;
    u32 playTimeSeconds;
    char* taskTexts[5];
    u8 isOccupied;
    u8 chaptersUnlocked;
    u8 padding[2];
} FrontendSaveSlot;

#define FRONTEND_SAVE_SLOT_COUNT 3

void saveFileSelect_checkCheatCodes(void);
void saveSelect_drawText(int unused, int alpha);

#endif /* MAIN_DLL_FRONT_FRONTEND_CONTROL_H_ */
