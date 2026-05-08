#ifndef MAIN_UNKNOWN_AUTOS_PLACEHOLDER_80281A9C_H_
#define MAIN_UNKNOWN_AUTOS_PLACEHOLDER_80281A9C_H_

#include "ghidra_import.h"

void FUN_80281a30(byte param_1,byte param_2,byte param_3,byte param_4);
void FUN_80281a34(byte param_1,byte param_2,byte param_3,uint param_4);
void FUN_80281a38(uint param_1,uint param_2,int param_3);
void inpResetMidiCtrl(u8 a, u8 b, u32 mode);
u32 inpGetMidiCtrl(u8 r3, u8 r4, u8 r5);
u8 *inpGetChannelDefaults(u8 a, u8 b);
void inpResetChannelDefaults(u8 a, u8 b);
void inpAddCtrl(int obj, int b, int c, int d, u32 flag);
void inpFXCopyCtrl(u8 controller, int dstState, int srcState);
void inpSetMidiLastNote(u8 a, u8 b, u8 v);
u8 inpGetMidiLastNote(u8 a, u8 b);

#endif /* MAIN_UNKNOWN_AUTOS_PLACEHOLDER_80281A9C_H_ */
