#ifndef MAIN_DLL_HUD_TEXTURES_H_
#define MAIN_DLL_HUD_TEXTURES_H_

#include "global.h"

/*
 * HudTextures - the 0x198 pause-menu HUD work record at hudTextures
 * (.bss 0x803A89B0). Field widths mirror the deref widths observed in
 * pausemenu.c / dll_0000_gameui.c; unobserved ranges padded.
 */
typedef struct HudTextures {
    u8 pad0[0x5C - 0x0];
    void * unk5C;
    u8 pad60[0xBC - 0x60];
    void * unkBC;
    void * unkC0;
    u8 padC4[0x13C - 0xC4];
    s32 unk13C;
    s32 unk140;
    s32 unk144;
    s32 unk148;
    s32 unk14C;
    u8 pad150[0x198 - 0x150];
} HudTextures;


/* extern-cleanup: consolidated prototypes */
f32 gameTextFn_80019c00(void);

#endif
