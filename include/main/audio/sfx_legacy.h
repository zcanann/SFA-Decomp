#ifndef MAIN_AUDIO_SFX_LEGACY_H_
#define MAIN_AUDIO_SFX_LEGACY_H_

#include "types.h"
#include "main/audio/sfx_object_query_api.h"
#include "main/audio/sfx_play_legacy_api.h"
#include "main/audio/sfx_stop_object_api.h"

void Sfx_KeepAliveLoopedObjectSound(int obj, int sfxId);
void Sfx_PlayAtPositionFromObject(int obj, int sfxId, f32 x, f32 y, f32 z);

#endif /* MAIN_AUDIO_SFX_LEGACY_H_ */
