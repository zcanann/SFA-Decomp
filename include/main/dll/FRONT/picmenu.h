#ifndef MAIN_DLL_FRONT_PICMENU_H_
#define MAIN_DLL_FRONT_PICMENU_H_

#include "dolphin/os.h"
#include "dolphin/dvd.h"
#include "dolphin/thp/THPPlayer.h"

BOOL movieLoad(const char* fileName, void* param2);
void audioFn_801192ec(void);
BOOL attractModeAudioFn_80119338(int param_1);
void fn_80119458(OSMessage msg);
OSMessage fn_80119488(void);
void fn_801194BC(OSMessage msg);
OSMessage fn_801194EC(void);
void fn_80119520(void);
void fn_80119618(void);
void fn_80119654(void);
BOOL fn_80119688(OSPriority priority);
OSMessage fn_80119724(s32 flags);
void fn_80119768(OSMessage msg);
void fn_80119798(void* param);
void fn_801198E0(void* param);
void fn_80119A1C(void);
void fn_80119AE8(void);
void fn_80119B24(void);
BOOL fn_80119B58(int param_1, int param_2);

#endif /* MAIN_DLL_FRONT_PICMENU_H_ */
