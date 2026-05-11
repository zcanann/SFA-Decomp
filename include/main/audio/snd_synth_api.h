#ifndef MAIN_AUDIO_SND_SYNTH_API_H_
#define MAIN_AUDIO_SND_SYNTH_API_H_

#include "ghidra_import.h"

void sndSeqVolume(int seqId, int volume, int time, int mode);
u16 seqGetMIDIPriority(u8 slot, u8 event);
int sndFXCtrl(int handle, u8 controller, u8 value);
int sndFXCtrl14(int handle, u8 controller, u16 value);
int sndFXKeyOff(int handle);
int sndFXStartEx(int fxId, int volume, int pan, int studio);
int sndFXCheck(u32 id);
void sndVolume(int group, int volume, int time);
void sndMasterVolume(int volume, int time, u8 musicFlag, u8 fxFlag);
void sndOutputMode(int mode);
void sndSetAuxProcessingCallbacks(u32 studio, void *auxACallback, void *auxAUser, u8 auxAIndex,
                                  void *auxAData, void *auxBCallback, void *auxBUser,
                                  u8 auxBIndex, void *auxBData);
void synthActivateStudio(u32 slot, int a, int b);
void synthDeactivateStudio(u8 slot);
void synthAddStudioInput(u8 idx);
void synthRemoveStudioInput(u8 idx);

#endif /* MAIN_AUDIO_SND_SYNTH_API_H_ */
