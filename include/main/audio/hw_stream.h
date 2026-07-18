#ifndef MAIN_AUDIO_HW_STREAM_H_
#define MAIN_AUDIO_HW_STREAM_H_

#include "ghidra_import.h"
#include "main/audio/snd_types.h"

u32 hwRemoveInput(u8 studio, SND_STUDIO_INPUT *input);
u32 hwChangeStudio(u32 voice);
void hwGetPos(void *buffer, u32 offset, u32 byteCount, u8 streamHandle,
              void (*callback)(u32), u32 callbackArg);
void *hwFlushStream(u8 streamHandle);
void hwInitStream(void);

#endif /* MAIN_AUDIO_HW_STREAM_H_ */
