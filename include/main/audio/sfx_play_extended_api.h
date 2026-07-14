#ifndef MAIN_AUDIO_SFX_PLAY_EXTENDED_API_H_
#define MAIN_AUDIO_SFX_PLAY_EXTENDED_API_H_

#include "types.h"

void Sfx_PlayFromObjectEx(u32 obj, f32* pos, u32 channel, u16 sfxId);

#define Sfx_PlayFromObjectExIntSfxLegacy(obj, pos, channel, sfxId)                                        \
    ((void (*)(u32, f32*, u32, int))Sfx_PlayFromObjectEx)((obj), (pos), (channel), (sfxId))

#endif /* MAIN_AUDIO_SFX_PLAY_EXTENDED_API_H_ */
