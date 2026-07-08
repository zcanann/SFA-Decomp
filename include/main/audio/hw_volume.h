#ifndef MAIN_AUDIO_HW_VOLUME_H_
#define MAIN_AUDIO_HW_VOLUME_H_

#include "ghidra_import.h"

void hwSetVolume(int slot, u32 p2, f32 vol, f32 auxa, f32 auxb, u32 aux, u32 p7);

#endif /* MAIN_AUDIO_HW_VOLUME_H_ */
