#ifndef MAIN_AUDIO_HW_STREAM_H_
#define MAIN_AUDIO_HW_STREAM_H_

#include "ghidra_import.h"

void hwRemoveInput(u32 idx, void *input);
int hwChangeStudio(int slot);
void hwGetPos(int dest, u32 streamPos, int byteCount, int stream, undefined4 callback,
              undefined4 callbackArg);
void hwFlushStream(int stream);
void hwInitStream(void);

#endif /* MAIN_AUDIO_HW_STREAM_H_ */
