#ifndef MAIN_UNKNOWN_AUTOS_PLACEHOLDER_802765AC_H_
#define MAIN_UNKNOWN_AUTOS_PLACEHOLDER_802765AC_H_

#include "ghidra_import.h"

void FUN_8027656c(int param_1,uint *param_2);
void FUN_80276570(int param_1,undefined4 *param_2);
void FUN_80276574(int param_1,uint *param_2,uint param_3);
uint FUN_80276578(uint param_1,short param_2);
void FUN_80276580(int param_1,uint *param_2,int param_3);
void FUN_80276584(int param_1,uint *param_2);
void FUN_80276588(int param_1,int param_2,uint *param_3,undefined4 param_4,uint param_5,uint param_6
                 ,uint param_7);
void FUN_8027658c(int param_1,uint *param_2);
uint FUN_80276590(int param_1,int param_2,uint param_3);
int FUN_80276598(int param_1,int param_2,uint param_3);
void FUN_802765a0(int param_1,int param_2,uint param_3,undefined4 param_4);
void FUN_802765a4(int param_1,uint *param_2,byte param_3);
void FUN_802765a8(int param_1,uint *param_2);
void FUN_802765ac(int param_1,uint *param_2);
void FUN_802765b0(int *param_1);
void FUN_802765b4(uint param_1);
void FUN_802765b8(int *param_1);
uint FUN_802765bc(int *param_1);
void FUN_802765c4(int *param_1,int param_2);
void mcmdRandomKey(int state, u32 *args);
void SelectSource(int state, int ctrlObj, u32 *args, int unused, u32 stateFlag,
                  u32 activeFlag, u32 dirtyFlag);
u32 varGet32(int state, u32 useExCtrl, u32 index);
int varGet(int state, u32 useExCtrl, u32 index);
void varSet32(int state, u32 useExCtrl, u32 index, u32 value);
void mcmdPortamento(int state, u32 *args);
void mcmdVarCalculation(int state, u32 *args, u8 op);
void mcmdSendMessage(int state, u32 *args);
void mcmdSetKeyGroup(int state, u32 *args);
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
