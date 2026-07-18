#ifndef MAIN_AUDIO_HW_STREAM_H_
#define MAIN_AUDIO_HW_STREAM_H_

#include "ghidra_import.h"
#include "main/audio/snd_types.h"

u32 hwRemoveInput(u8 studio, SND_STUDIO_INPUT *input);
int hwChangeStudio(int slot);
void hwGetPos(int dest, u32 streamPos, int byteCount, int stream, u32 callback,
              u32 callbackArg);
void hwFlushStream(int stream);
void hwInitStream(void);

#endif /* MAIN_AUDIO_HW_STREAM_H_ */
