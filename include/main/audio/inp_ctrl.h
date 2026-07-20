#ifndef MAIN_AUDIO_INP_CTRL_H_
#define MAIN_AUDIO_INP_CTRL_H_

#include "ghidra_import.h"
#include "main/audio/mcmd.h"

u16 _GetInputValue(McmdVoiceState *state, McmdInputSlot *slot, u8 midiSlot, u8 midiKey);
u16 inpGetVolume(McmdVoiceState *state);
u16 inpGetPanning(McmdVoiceState *state);
u16 inpGetSurPanning(McmdVoiceState *state);
u16 inpGetPitchBend(McmdVoiceState *state);
u16 inpGetDoppler(McmdVoiceState *state);
u16 inpGetModulation(McmdVoiceState *state);
u16 inpGetPedal(McmdVoiceState *state);
u16 inpGetPreAuxA(McmdVoiceState *state);
u16 inpGetReverb(McmdVoiceState *state);
u16 inpGetPreAuxB(McmdVoiceState *state);
u16 inpGetPostAuxB(McmdVoiceState *state);
u16 inpGetTremolo(McmdVoiceState *state);
void inpInit(u32 state);
u8 inpTranslateExCtrl(u8 ctrl);
u16 inpGetExCtrl(McmdVoiceState *state, u8 ctrl);
void inpSetExCtrl(McmdVoiceState *state, u8 ctrl, s16 value);
#endif /* MAIN_AUDIO_INP_CTRL_H_ */
