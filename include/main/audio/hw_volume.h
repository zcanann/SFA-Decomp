#ifndef MAIN_AUDIO_HW_VOLUME_H_
#define MAIN_AUDIO_HW_VOLUME_H_

#include "ghidra_import.h"

void hwSetVolume(int slot, u32 volumeTable, f32 volume, f32 auxA, f32 auxB,
                 u32 pan, u32 surroundPan);

#endif /* MAIN_AUDIO_HW_VOLUME_H_ */
