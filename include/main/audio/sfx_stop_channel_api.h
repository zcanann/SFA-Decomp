#ifndef MAIN_AUDIO_SFX_STOP_CHANNEL_API_H_
#define MAIN_AUDIO_SFX_STOP_CHANNEL_API_H_

#include "game/objects/object.h"

#define SFX_OBJECT_CHANNEL_MASK_ALL 0x7f

void Sfx_StopObjectChannel(GameObject* obj, int channel);

#endif /* MAIN_AUDIO_SFX_STOP_CHANNEL_API_H_ */
