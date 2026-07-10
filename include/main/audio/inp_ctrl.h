#ifndef MAIN_AUDIO_INP_CTRL_H_
#define MAIN_AUDIO_INP_CTRL_H_

#include "ghidra_import.h"
#include "main/audio/mcmd.h"

u16 _GetInputValue(McmdVoiceState *state, McmdInputSlot *slot, u32 midiSlot, u32 midiKey);
u16 inpGetVolume(McmdVoiceState *state);
u16 inpGetPanning(McmdVoiceState *state);
int inpGetSurPanning(McmdVoiceState *state);
int inpGetPitchBend(McmdVoiceState *state);
u16 inpGetDoppler(McmdVoiceState *state);
u16 inpGetModulation(McmdVoiceState *state);
u16 inpGetPedal(McmdVoiceState *state);
u16 inpGetPreAuxA(McmdVoiceState *state);
u16 inpGetReverb(McmdVoiceState *state);
u16 inpGetPreAuxB(McmdVoiceState *state);
u16 inpGetPostAuxB(McmdVoiceState *state);
u16 inpGetTremolo(McmdVoiceState *state);
void inpInit(u32 state);
u32 inpTranslateExCtrl(u32 input);
u32 inpGetExCtrl(McmdVoiceState *state, u32 ctrl);
void inpSetExCtrl(McmdVoiceState *state, u32 ctrl, s16 value);
u16 sndRand(void);
s16 sndSin(u32 packed);
void *sndBSearch(void *key, void *base, int count, u32 stride, int (*cmp)(void *, void *));
void sndConvertMs(u32 *p);
void sndConvertTicks(u32 *p, int x);
u32 sndConvert2Ms(u32 x);

#endif /* MAIN_AUDIO_INP_CTRL_H_ */
