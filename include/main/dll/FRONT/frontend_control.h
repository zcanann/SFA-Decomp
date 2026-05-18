#ifndef MAIN_DLL_FRONT_FRONTEND_CONTROL_H_
#define MAIN_DLL_FRONT_FRONTEND_CONTROL_H_

#include "ghidra_import.h"

typedef struct FrontendSaveSlot {
    char name[4];
    u8 completionPercent;
    u8 magicCount;
    u8 lifeCount;
    u8 pad07;
    u32 playTimeSeconds;
    u8 pad0C[0x20 - 0x0C];
    u8 isOccupied;
    u8 cheatFlag;
    u8 pad22[0x24 - 0x22];
} FrontendSaveSlot;

void saveFileSelect_checkCheatCodes(void);
void saveSelect_drawText(int param_1, int param_2);

#endif /* MAIN_DLL_FRONT_FRONTEND_CONTROL_H_ */
