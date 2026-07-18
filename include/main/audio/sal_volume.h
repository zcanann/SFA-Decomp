#ifndef MAIN_AUDIO_SAL_VOLUME_H_
#define MAIN_AUDIO_SAL_VOLUME_H_

#include "ghidra_import.h"

void salCalcVolumeMatrix(u8 volumeTable, f32 *out, u32 pan, u32 surroundPan,
                         u32 itd, u32 dpl2, f32 volume, f32 auxA, f32 auxB);

#endif /* MAIN_AUDIO_SAL_VOLUME_H_ */
