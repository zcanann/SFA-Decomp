#ifndef MAIN_UNKNOWN_AUTOS_PLACEHOLDER_80283BF0_H_
#define MAIN_UNKNOWN_AUTOS_PLACEHOLDER_80283BF0_H_

#include "ghidra_import.h"

void hwRemoveInput(u32 idx);
int hwChangeStudio(int slot);
void hwGetPos(int dest, u32 streamPos, int byteCount, int stream, undefined4 callback,
              undefined4 callbackArg);
void hwFlushStream(int stream);
void hwInitStream(void);

#endif /* MAIN_UNKNOWN_AUTOS_PLACEHOLDER_80283BF0_H_ */
