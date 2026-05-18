#ifndef MAIN_UNKNOWN_AUTOS_PLACEHOLDER_802765AC_H_
#define MAIN_UNKNOWN_AUTOS_PLACEHOLDER_802765AC_H_

#include "ghidra_import.h"
#include "main/audio/mcmd.h"

void mcmdRandomKey(McmdVoiceState *state, McmdCommandArgs *args);
void SelectSource(int state, int ctrlObj, u32 *args, int unused, u32 stateFlag,
                  u32 activeFlag, u32 dirtyFlag);
u32 varGet32(McmdVoiceState *state, u32 useExCtrl, u32 index);
int varGet(McmdVoiceState *state, u32 useExCtrl, u32 index);
void varSet32(McmdVoiceState *state, u32 useExCtrl, u32 index, u32 value);
void mcmdPortamento(McmdVoiceState *state, McmdCommandArgs *args);
void mcmdVarCalculation(McmdVoiceState *state, McmdCommandArgs *args, u8 op);
void mcmdSendMessage(McmdVoiceState *state, McmdCommandArgs *args);
void mcmdSetKeyGroup(McmdVoiceState *state, McmdCommandArgs *args);
void macHandleActive(int state);
void macHandle(u32 delta);
void macSampleEndNotify(int state);
u32 macSetExternalKeyoff(int state);
void macSetPedalState(int state, u32 defer);
void TimeQueueAdd(int state);
void fn_802788B4(int state, u32 skipFadeReset);
void audioFn_80278990(int state);
void fn_80278A98(int state, int mode);
int audioFn_80278b94(u16 instrumentKey, u32 priority, u32 maxInstances, u32 baseSample,
                     u8 keyFlags, u8 volume, u8 pan, u32 midiSlot, u8 midiEvent,
                     u8 midiLayer, u16 sampleOffsetIndex, u8 studio, u8 returnNewId,
                     u8 auxA, u8 auxB, int startImmediately);
void fn_80278EA4(void);

#endif /* MAIN_UNKNOWN_AUTOS_PLACEHOLDER_802765AC_H_ */
