#ifndef MAIN_UNKNOWN_AUTOS_PLACEHOLDER_80283E4C_H_
#define MAIN_UNKNOWN_AUTOS_PLACEHOLDER_80283E4C_H_

#include "ghidra_import.h"

void hwSaveSample(u32 **sample, void **ptr);
void FUN_80283e00(int param_1,ushort param_2);
void hwRemoveSample(u32 *sample, void *ptr);
void hwSyncSampleMem(void);
void FUN_80283e0c(int param_1,char param_2);
void hwFrameDone(void);
void sndSetHooks(u32 *values);
void hwDisableHRTF(void);
int hwGetVirtualSampleID(int slot);
int hwVoiceInStartup(int slot);

#endif /* MAIN_UNKNOWN_AUTOS_PLACEHOLDER_80283E4C_H_ */
