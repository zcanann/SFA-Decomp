#ifndef MAIN_UNKNOWN_AUTOS_PLACEHOLDER_802827D4_H_
#define MAIN_UNKNOWN_AUTOS_PLACEHOLDER_802827D4_H_

#include "ghidra_import.h"

u16 inpGetPostAuxB(int state);
u16 inpGetTremolo(int state);
u16 inpGetAuxA(u32 studio, u32 channel, u32 auxIndex, u32 handleIndex);
u16 inpGetAuxB(u32 studio, u32 channel, u32 auxIndex, u32 handleIndex);
void inpInit(u32 state);
u32 inpTranslateExCtrl(u32 input);
u32 inpGetExCtrl(int state, u32 ctrl);
void inpSetExCtrl(int state, u32 ctrl, s16 value);
u16 sndRand(void);
s16 sndSin(u32 packed);
void *sndBSearch(void *key, void *base, int count, u32 stride, int (*cmp)(void *, void *));
void sndConvertMs(u32 *p);
void sndConvertTicks(u32 *p, int x);
u32 sndConvert2Ms(u32 x);

#endif /* MAIN_UNKNOWN_AUTOS_PLACEHOLDER_802827D4_H_ */
