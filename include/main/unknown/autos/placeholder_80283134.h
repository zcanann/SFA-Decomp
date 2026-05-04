#ifndef MAIN_UNKNOWN_AUTOS_PLACEHOLDER_80283134_H_
#define MAIN_UNKNOWN_AUTOS_PLACEHOLDER_80283134_H_

#include "ghidra_import.h"

void snd_handle_irq(void);
int hwInit(u32 value, u8 valueA, u8 valueB, u32 flags);
void hwExit(void);
void hwSetTimeOffset(u8 value);
u8 hwGetTimeOffset(void);
int hwIsActive(int slot);
void hwSetMesgCallback(u32 value);
void hwSetPriority(int slot, u32 value);
void hwInitSamplePlayback(int slot, u16 value70, u32 *values, u32 resetAdsr, u32 priority, u32 value18, u32 resetSrc, u32 itdMode);

#endif /* MAIN_UNKNOWN_AUTOS_PLACEHOLDER_80283134_H_ */
