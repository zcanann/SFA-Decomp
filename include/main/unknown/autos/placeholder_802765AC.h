#ifndef MAIN_UNKNOWN_AUTOS_PLACEHOLDER_802765AC_H_
#define MAIN_UNKNOWN_AUTOS_PLACEHOLDER_802765AC_H_

#include "ghidra_import.h"
#include "main/audio/mcmd.h"

void mcmdRandomKey(McmdVoiceState *state, McmdCommandArgs *args);
void SelectSource(McmdVoiceState *svoice, McmdInputSlot *dest, McmdCommandArgs *cstep,
                  u64 tstflag, u32 dirtyFlag);
u32 varGet32(McmdVoiceState *state, u32 useExCtrl, u32 index);
int varGet(McmdVoiceState *state, u32 useExCtrl, u32 index);
void varSet32(McmdVoiceState *state, u32 useExCtrl, u32 index, u32 value);
void mcmdPortamento(McmdVoiceState *state, McmdCommandArgs *args);
void mcmdVarCalculation(McmdVoiceState *state, McmdCommandArgs *args, u8 op);
void mcmdSendMessage(McmdVoiceState *state, McmdCommandArgs *args);
void mcmdSetKeyGroup(McmdVoiceState *state, McmdCommandArgs *args);
void macHandleActive(McmdVoiceState *sv);
void macHandle(u32 deltaTime);
void macSampleEndNotify(McmdVoiceState *sv);
void macSetExternalKeyoff(McmdVoiceState *sv);
void macSetPedalState(McmdVoiceState *sv, u32 state);
void TimeQueueAdd(McmdVoiceState *state);
void fn_802788B4(McmdVoiceState *sv, u32 disableUpdate);
void audioFn_80278990(McmdVoiceState *state);
void fn_80278A98(McmdVoiceState *sv, int newState);
u32 audioFn_80278b94(u16 macid, u8 priority, u8 maxVoices, u16 allocId, u8 key, u8 vol,
                     u8 panning, u8 midi, u8 midiSet, u8 section, u16 step, u16 trackid,
                     u8 new_vid, u8 vGroup, u8 studio, u32 itd);
void fn_80278EA4(void);

#endif /* MAIN_UNKNOWN_AUTOS_PLACEHOLDER_802765AC_H_ */
