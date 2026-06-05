#ifndef MAIN_AUDIO_DECODE_THREAD_H_
#define MAIN_AUDIO_DECODE_THREAD_H_

#include "ghidra_import.h"
#include "dolphin/os.h"

BOOL CreateAudioDecodeThread(OSPriority priority, void *param);

#endif /* MAIN_AUDIO_DECODE_THREAD_H_ */
