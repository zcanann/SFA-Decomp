#ifndef MAIN_DLL_DLL_47_H_
#define MAIN_DLL_DLL_47_H_

#include "ghidra_import.h"

void FUN_8011a0dc(u64 param_1,double param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,u8 param_10);
void FUN_8011a298(u64 param_1,double param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,int param_10);
void FUN_8011a99c(u64 param_1,double param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_8011ab20(u64 param_1,double param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
void FUN_8011afa4(u64 param_1,u64 param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
int FUN_8011b5d4(u64 param_1,double param_2,u64 param_3,u64 param_4,
                u64 param_5,u64 param_6,u64 param_7,u64 param_8);


/* extern-cleanup: defining-file public prototypes */
void saveSelectGoToChooseSlot(int arg);

extern u8 saveFileSelect_debugCheatProgress;
extern u8 saveFileSelect_saveCheatProgress;
extern u8 saveFileSelect_cheatInputTimer;
extern s8 saveFileSelect_currentSlotIndex;
extern u8 saveFileSelect_saveDirty;
extern struct FrontendSaveSlot* saveFileSelect_saveSlotsBase;
extern struct FrontendSaveSlot* saveFileSelect_saveSlots;
extern u16 saveFileSelect_slotCheatSequence[6];
extern char sFrontendCompletionPercentFormat[5];
extern char sFrontendSingleDigitFormat[4];

#endif /* MAIN_DLL_DLL_47_H_ */
