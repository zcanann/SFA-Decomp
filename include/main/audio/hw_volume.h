#ifndef MAIN_AUDIO_HW_VOLUME_H_
#define MAIN_AUDIO_HW_VOLUME_H_

#include "ghidra_import.h"
#include "main/audio/snd_types.h"

void hwSetVolume(u32 voice, u8 volumeTable, f32 volume, u32 pan, u32 surroundPan,
                 f32 auxA, f32 auxB);
void hwOff(s32 voice);
void hwSetAUXProcessingCallbacks(u8 studio, void *auxACallback, void *auxAUser,
                                 void *auxBCallback, void *auxBUser);
void hwActivateStudio(u8 studio, bool isMaster, SND_STUDIO_TYPE type);
void hwDeactivateStudio(u8 studio);

#endif /* MAIN_AUDIO_HW_VOLUME_H_ */
