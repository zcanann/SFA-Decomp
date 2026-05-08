#ifndef MAIN_UNKNOWN_AUTOS_PLACEHOLDER_802827D4_H_
#define MAIN_UNKNOWN_AUTOS_PLACEHOLDER_802827D4_H_

#include "ghidra_import.h"

uint FUN_802827c8(int param_1,byte *param_2,uint param_3,uint param_4);
uint FUN_802827d0(int param_1);
uint FUN_802827d8(int param_1);
uint FUN_802827e0(int param_1);
uint FUN_802827e8(int param_1);
uint FUN_802827f0(int param_1);
uint FUN_802827f8(int param_1);
uint FUN_80282800(int param_1);
uint FUN_80282808(int param_1);
uint FUN_80282810(int param_1);
uint FUN_80282818(int param_1);
uint FUN_80282820(int param_1);
uint FUN_80282828(int param_1);
uint FUN_80282830(uint param_1,uint param_2,uint param_3,uint param_4);
uint FUN_80282838(uint param_1,uint param_2,uint param_3,uint param_4);
u16 inpGetPostAuxB(int state);
u16 inpGetTremolo(int state);
u32 inpGetAuxA(u32 studio, u32 channel, u32 auxIndex, u32 handleIndex);
u32 inpGetAuxB(u32 studio, u32 channel, u32 auxIndex, u32 handleIndex);
void inpInit(u32 state);
u32 inpTranslateExCtrl(u32 input);
u32 inpGetExCtrl(int state, u32 ctrl);
void inpSetExCtrl(int state, u32 ctrl, s16 value);
u16 sndRand(void);
s16 sndSin(u32 packed);
void *sndBSearch(void *key, void *base, u16 count, u32 stride, int (*cmp)(void *, void *));
void sndConvertMs(u32 *p);
void sndConvertTicks(u32 *p, int x);
u32 sndConvert2Ms(u32 x);

#endif /* MAIN_UNKNOWN_AUTOS_PLACEHOLDER_802827D4_H_ */
