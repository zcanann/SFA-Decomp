#ifndef MAIN_AUDIO_SYNTH_INIT_H_
#define MAIN_AUDIO_SYNTH_INIT_H_

#include "ghidra_import.h"

u32 audioLayerFn_8026f8b8(u16 layerID, s16 priority, u8 maxVoices, u16 allocId,
                          u8 key, u8 volume, u8 panning, u8 midi, u8 midiSet,
                          u8 section, u16 step, u16 trackId, u32 vidFlag,
                          u8 voiceGroup, u8 studio, u32 itd);

#endif /* MAIN_AUDIO_SYNTH_INIT_H_ */
