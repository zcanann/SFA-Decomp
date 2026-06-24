#ifndef MAIN_DLL_DLL_0000_GAMEUI_H_
#define MAIN_DLL_DLL_0000_GAMEUI_H_

#include "ghidra_import.h"

/* Shared struct layouts for dll_0000_gameui (the in-game GameUI / HUD /
 * C-menu unit, DLL 0). Field offsets are recovered from the EN v1.0 asm. */

typedef struct TaskHintEntry
{
    u16 hint0; /* 0x00 */
    u16 hint2; /* 0x02 */
    u16 hint4; /* 0x04 */
    u8 _6[0x2]; /* 0x06 */
    s32 hint8; /* 0x08 */
    s32 hintC; /* 0x0c */
    s32 hint10; /* 0x10 */
    u8 _14[0x2]; /* 0x14 */
    u16 bit_id; /* 0x16 */
    u8 thresh; /* 0x18 */
    u8 _19; /* 0x19 */
    u16 bit1a; /* 0x1a */
} TaskHintEntry; /* sizeof = 0x1c */

typedef struct
{
    s16 id; /* 0x00 */
    u16 x; /* 0x02 */
    u16 y; /* 0x04 */
    s16 ofs6; /* 0x06 */
    u8 trailX; /* 0x08 */
    u8 trailY; /* 0x09 */
    u8 count; /* 0x0a */
    u8 _b; /* 0x0b */
    s8 nav[4]; /* 0x0c */
    f32 f10; /* 0x10 */
    s32 f14; /* 0x14 */
    s32 f18; /* 0x18 */
    u8 f1c; /* 0x1c */
    u8 _1d[3];
} GridEntry; /* sizeof = 0x20 */

typedef struct
{
    s16 f0;
    u8 _2[0x1e];
} HintCell; /* 0x20 */

typedef struct
{
    u8 _pad0[0x190];
    int times190[12]; /* 0x190 */
    int textures1C0[0x66]; /* 0x1c0 */
    s16 texIds358[0x28]; /* 0x358 */
    int textures3A8[0x28]; /* 0x3a8 */
    u8 _pad448[0x40]; /* 0x448 */
    u8 enabled[0x40]; /* 0x488 */
    u8 closeMode[0x40]; /* 0x4c8 */
    u8 _pad508[0x40]; /* 0x508 */
    s16 icons[0x40]; /* 0x548 */
    u8 _pad5c8[0x80]; /* 0x5c8 */
    int ids648[0x40]; /* 0x648 */
    int ids748[0x40]; /* 0x748 */
    int ids848[0x40]; /* 0x848 */
    s16 texIds[0x40]; /* 0x948 */
    u8 _pad9c8[0x258]; /* 0x9c8 */
    char* anims[4]; /* 0xc20 */
} CMenuHud;

typedef struct
{
    u8 _pad0[0x210];

    struct
    {
        s16 bitA;
        s16 bitB;
        u8 thresh;
        u8 _5[3];
    } tokens[4]; /* 0x210 */
    u8 _pad230[0x490]; /* 0x230 */
    struct
    {
        s16 id;
        u8 _2[4];
        s16 alt;
        u8 _8[8];
    } items[8]; /* 0x6c0 */
    int list740[4]; /* 0x740 */
    struct
    {
        u8 _0[0xe];
        s16 alt;
    } alts[31]; /* 0x750 */
    u8 _pad940[4]; /* 0x940 */
    struct
    {
        u16 cell;
        u16 code;
    } cellMap[0x2d]; /* 0x944 */
    GridEntry grid9F8[14]; /* 0x9f8 */
    s16 gbids[12]; /* 0xbb8 */
    GridEntry gridBD0[13]; /* 0xbd0 */
    GridEntry gridD70[13]; /* 0xd70 */
    GridEntry gridF10[3]; /* 0xf10 */
    GridEntry gridF70[19]; /* 0xf70 */
    int flags11D0[12]; /* 0x11d0 */
} PauseTbl;

typedef struct
{
    u8 _pad000[0x1c0];
    void* hudTextures[102]; /* 0x1c0 */
    u8 _pad358[0x448 - 0x358];
    u8 itemFlags[64]; /* 0x448 */
    u8 _pad488[0x948 - 0x488];
    s16 itemSlots[64]; /* 0x948 */
    void* itemTextures[64]; /* 0x9c8 */
} GameUiHud;


/* extern-cleanup: defining-file public prototypes */
void fn_8012C000(void);
void pauseMenuInit(void);
void CMenu_SetFadeCounter(s16 v);
void pauseMenuDoSave(void);
void perspectiveFn_80129db4(void);

#endif /* MAIN_DLL_DLL_0000_GAMEUI_H_ */
