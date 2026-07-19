#ifndef MAIN_AUDIO_SND_SYNTH_API_H_
#define MAIN_AUDIO_SND_SYNTH_API_H_

#include "ghidra_import.h"
#include "main/audio/synth_control.h"
#include "main/audio/snd_types.h"

void sndSeqVolume(u8 volume, u16 time, u32 seqId, u8 mode);
u16 seqGetMIDIPriority(u8 slot, u8 event);
int sndFXCtrl(u32 handle, u8 controller, u8 value);
int sndFXKeyOff(u32 handle);
u32 sndFXStartEx(u16 fxId, u8 volume, u8 pan, u8 studio);
int sndFXCheck(u32 id);
void sndVolume(u8 volume, u16 time, u8 group);
void sndMasterVolume(u8 volume, u16 time, u8 musicFlag, u8 fxFlag);
void sndOutputMode(int mode);
void sndSetAuxProcessingCallbacks(u8 studio, void *auxACallback, void *auxAUser, u8 auxAIndex,
                                  void *auxAData, void *auxBCallback, void *auxBUser,
                                  u8 auxBIndex, void *auxBData);
void synthActivateStudio(u8 studio, u32 isMaster, SND_STUDIO_TYPE type);
void synthDeactivateStudio(u8 studio);
u32 synthAddStudioInput(u8 studio, SND_STUDIO_INPUT *input);
u32 synthRemoveStudioInput(u8 studio, SND_STUDIO_INPUT *input);

#endif /* MAIN_AUDIO_SND_SYNTH_API_H_ */
