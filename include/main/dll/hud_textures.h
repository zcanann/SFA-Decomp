#ifndef MAIN_DLL_HUD_TEXTURES_H_
#define MAIN_DLL_HUD_TEXTURES_H_

#include "global.h"

/*
 * HudTextures - the 0x198 pause-menu HUD work record at hudTextures
 * (.bss 0x803A89B0). Field widths mirror the deref widths observed in
 * pausemenu.c / dll_0000_gameui.c; unobserved ranges padded.
 */
typedef struct HudTextures {
    u8 pad0[0x28 - 0x0];
    void * tex28;
    void * tex2C;
    void * tex30;
    void * tex34;
    void * tex38;
    void * tex3C;
    void * tex40;
    u8 pad44[0x5C - 0x44];
    void * unk5C;
    u8 pad60[0x80 - 0x60];
    void * tex80;
    u8 pad84[0xB8 - 0x84];
    void * texB8;
    void * unkBC;
    void * unkC0;
    u8 padC4[0xF8 - 0xC4];
    void * texF8;
    void * texFC;
    void * tex100;
    void * tex104;
    u8 pad108[0x10C - 0x108];
    void * tex10C;
    void * tex110;
    void * tex114;
    void * tex118;
    void * tex11C;
    u8 pad120[0x134 - 0x120];
    void * tex134;
    u8 pad138[0x13C - 0x138];
    s32 unk13C;
    s32 unk140;
    s32 unk144;
    s32 unk148;
    s32 unk14C;
    void * tex150;
    u8 pad154[0x170 - 0x154];
    void * tex170;
    u8 pad174[0x17C - 0x174];
    void * tex17C;
    void * tex180;
    void * tex184;
    u8 pad188[0x198 - 0x188];
} HudTextures;

STATIC_ASSERT(sizeof(HudTextures) == 0x198);
STATIC_ASSERT(offsetof(HudTextures, tex28) == 0x28);
STATIC_ASSERT(offsetof(HudTextures, unk5C) == 0x5C);
STATIC_ASSERT(offsetof(HudTextures, tex80) == 0x80);
STATIC_ASSERT(offsetof(HudTextures, unkBC) == 0xBC);
STATIC_ASSERT(offsetof(HudTextures, texF8) == 0xF8);
STATIC_ASSERT(offsetof(HudTextures, tex134) == 0x134);
STATIC_ASSERT(offsetof(HudTextures, unk13C) == 0x13C);
STATIC_ASSERT(offsetof(HudTextures, tex170) == 0x170);


/* extern-cleanup: consolidated prototypes */
f32 gameTextFn_80019c00(void);

#endif
