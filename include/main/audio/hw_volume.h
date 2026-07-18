#ifndef MAIN_AUDIO_HW_VOLUME_H_
#define MAIN_AUDIO_HW_VOLUME_H_

#include "ghidra_import.h"
#include "main/audio/snd_types.h"

void hwSetVolume(int slot, u32 volumeTable, f32 volume, f32 auxA, f32 auxB,
                 u32 pan, u32 surroundPan);
void hwOff(s32 voice);
void hwSetAUXProcessingCallbacks(u8 studio, void *auxACallback, void *auxAUser,
                                 void *auxBCallback, void *auxBUser);
void hwActivateStudio(u8 studio, bool isMaster, SND_STUDIO_TYPE type);
void hwDeactivateStudio(u8 studio);

#endif /* MAIN_AUDIO_HW_VOLUME_H_ */
