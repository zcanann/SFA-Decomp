/* === moved from main/dll/baddie/dll_DB.c [80130124-80130888) (TU re-split, docs/boundary_audit.md) === */
#pragma scheduling on
#pragma peephole on
#include "main/dll/baddie/dll_DB.h"

extern u32 randomGetRange(int min, int max);


/*
 * --INFO--
 *
 * Function: textureFreeFn_8012fcec
 * EN v1.0 Address: 0x8012FCEC
 * EN v1.0 Size: 192b
 * EN v1.1 Address: 0x8012FD0C
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void textureFree(void* p);

#pragma scheduling off
#pragma peephole off
void textureFreeFn_8012fcec(void);
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_8012fdac
 * EN v1.0 Address: 0x8012FDAC
 * EN v1.0 Size: 196b
 * EN v1.1 Address: 0x8012FDC8
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8012fdac(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9);

/*
 * --INFO--
 *
 * Function: FUN_8012fe70
 * EN v1.0 Address: 0x8012FE70
 * EN v1.0 Size: 300b
 * EN v1.1 Address: 0x8012FE84
 * EN v1.1 Size: 112b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8012fe70(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8);


/* ===== EN v1.0 retargeted leaves ========================================= */

extern u8 linkFlag_803dd8f8;
extern u8 linkIsRotated;
extern s16 linkItemOpacity;
extern s16 linkCount_803dd90e;
extern s8 linkSelected;
extern u8 linkTextures[0x30];
extern void* textureLoadAsset(int id);

typedef struct LinkMenuItemDB
{
    u16 field00;
    u16 itemId;
    s16 field04;
    s16 field06;
    u8 pad8[4];
    s16 field0C;
    u8 padE[2];

    union
    {
        int textureAssetId;
        void* texture;
    };

    u16 field14;
    u16 field16;
    u8 pad18[2];
    u8 field1A;
    u8 pad1B[3];
    s8 state;
    s8 slots[25];
    s8 field38;
    u8 pad39[3];
} LinkMenuItemDB;


#pragma peephole off
#pragma peephole reset
#pragma peephole off
#pragma peephole reset
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

void titleScreenFn_80130464(u8 v) { linkFlag_803dd8f8 = v; }
void setLinkNotRotated(void) { linkIsRotated = 0; }
void setLinkIsRotated(void) { linkIsRotated = 1; }
u8 Link_func0C(void) { return (u8)linkCount_803dd90e; }
void Link_func0A(int idx, int v) { extern LinkMenuItemDB lbl_803A9458[40];  lbl_803A9458[idx].state = (s8)v; }
s32 Link_func09(int idx) { extern LinkMenuItemDB lbl_803A9458[40];  return lbl_803A9458[idx].state; }
void Link_setOpacity(u8 v) { linkItemOpacity = v; }
#pragma peephole off
void Link_setSelected(int v) { linkSelected = (s8)v; }
#pragma peephole reset
s32 Link_getSelected(void) { return linkSelected; }

/* Stubs added to align function set with v1.0 asm. Source had many Ghidra
 * FUN_xxx splits at wrong addresses; these stubs (no body yet) ensure the
 * asm symbol set is fully present so future hunters can fill bodies. */
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off

#pragma peephole reset
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling off
u16 fn_80130124(void)
{
    extern LinkMenuItemDB lbl_803A9458[40];
    return lbl_803A9458[linkSelected].itemId;
}
#pragma scheduling reset
extern void OSReport(const char* fmt, ...);
extern char lbl_8031C234[];
#pragma scheduling off
#pragma peephole off
void linkInitTextures(LinkMenuItemDB* item)
{
    int budget;
    int i;

    budget = item->field14;
    for (i = 0; i < 25; i++)
    {
        item->slots[i] = -1;
    }
    item->slots[0] = 0;
    i = 1;
    budget -= linkTextures[6] + linkTextures[14];
    while (budget != 0)
    {
        if (budget >= 80)
        {
            item->slots[i] = (s8)randomGetRange(2, 5);
        }
        else if (budget >= 40)
        {
            item->slots[i] = (s8)randomGetRange(4, 5);
        }
        else
        {
            item->slots[i] = 5;
        }
        budget -= linkTextures[item->slots[i] * 8 + 6];
        i++;
    }
    item->slots[i] = 1;
    i++;
    if (i >= 25)
    {
        OSReport(lbl_8031C234);
    }
}
#pragma peephole reset
#pragma scheduling reset
extern int getCurLanguage(void);
extern u8 lbl_802C8680[];
#pragma scheduling off
#pragma peephole off
void linkDrawFn_801302c0(void);
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off
void linkDrawFn_80130484(void);
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off
void Link_func0F(void)
{
    extern u8 lbl_803DD911; /* #57 */
    extern LinkMenuItemDB lbl_803A9458[40];
    int i;

    for (i = 0; i < (s8)lbl_803DD911; i++)
    {
        lbl_803A9458[i].field38 = 4;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
void Link_copy(u8* srcArg)
{
    extern u8 lbl_803DD911; /* #57 */
    extern LinkMenuItemDB lbl_803A9458[40];
    LinkMenuItemDB* dst;
    LinkMenuItemDB* src;
    int i;

    i = 0;
    dst = lbl_803A9458;
    src = (LinkMenuItemDB*)srcArg;
    for (; i < (s8)lbl_803DD911; i++)
    {
        dst->field16 = src->field16;
        dst->field1A = src->field1A;
        dst->field04 = src->field04;
        if (src->textureAssetId != -1)
        {
            if (dst->texture == NULL)
            {
                dst->texture = textureLoadAsset(src->textureAssetId);
            }
        }
        else
        {
            if (dst->texture != NULL)
            {
                textureFree(dst->texture);
            }
            dst->texture = NULL;
        }
        dst++;
        src++;
    }
}
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off
void Link_func0B(u8* srcArg)
{
    extern u8 lbl_803DD911; /* #57 */
    extern LinkMenuItemDB lbl_803A9458[40];
    LinkMenuItemDB* src;
    int i;

    src = (LinkMenuItemDB*)srcArg;
    for (i = 0; i < (s8)lbl_803DD911; i++)
    {
        lbl_803A9458[i].field00 = src[i].field00;
        lbl_803A9458[i].itemId = src[i].itemId;
        lbl_803A9458[i].field38 = 2;
    }
}
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling reset
#pragma peephole reset

/* === merged from main/dll/baddie/dll_DA.c [80130888-80130CF0) (TU re-split, docs/boundary_audit.md) === */
#include "ghidra_import.h"
#include "main/dll/baddie/dll_DA.h"


typedef struct LinkTexture
{
    void* texture;
    u8 pad4[2];
    u8 width;
    u8 pad7;
} LinkTexture;

typedef struct LinkMenuItemDA
{
    u16 textId;
    u16 boxId;
    s16 field04;
    s16 field06;
    u8 pad08[2];
    s16 x;
    s16 y;
    u8 pad0E[2];
    void* texture;
    u16 field14;
    u16 flags;
    u8 pad18[2];
    u8 field1A;
    u8 pad1B[3];
    s8 state;
    s8 slots[25];
    s8 timer;
    u8 pad39[3];
} LinkMenuItemDA;

extern void drawTexture(void* texture, u8 alpha, f32 x, f32 y, u16 scale);
extern void gameTextFn_80016810(int textId, int arg1, int arg2);
extern void* gameTextGetBox(int boxId);
extern void gameTextSetColor(int red, int green, int blue, int alpha);
extern void gameTextShow(int textId);
extern void gameTextShowStr(void* text, int boxId, int arg2, int arg3);
extern void MWTRACE(int boxId);

extern void* saveFileSelect_saveSlots;
extern s16 lbl_803DD8FA;
extern s16 lbl_803DD8FC;
extern s16 lbl_803DD8FE;
extern s16 lbl_803DD900;
extern s16 lbl_803DD902;
extern s16 lbl_803DD904;
extern f64 lbl_803E21E0;

#define LINK_FLAG_DRAW_SLOTS       0x0004
#define LINK_FLAG_DRAW_BLACK_SHADOW 0x0100
#define LINK_FLAG_DIM_OPACITY      0x0800
#define LINK_FLAG_FADE_TIMER_ONLY  0x1040
#define LINK_FLAG_HIDDEN           0x4000
#define LINK_FLAG_SELECTED_COLOR   0x0080

/*
 * --INFO--
 *
 * Function: Link_render
 * EN v1.0 Address: 0x80130888
 * EN v1.0 Size: 1128b
 * EN v1.1 Address: 0x801309A8
 * EN v1.1 Size: 616b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void Link_render(void)
{
    extern LinkMenuItemDA lbl_803A9458[40]; /* #57 */
    extern s8 lbl_803DD911; /* #57 */
    LinkMenuItemDA* item;
    LinkMenuItemDA* drawItem;
    int i;
    int slotIndex;
    int textureIndex;
    int opacity;
    int alpha;
    int red;
    int green;
    int blue;
    u16 textId;
    int x;
    int y;
    s8 timer;

    item = lbl_803A9458;
    for (i = 0; i < lbl_803DD911; i++)
    {
        drawItem = item;

        if ((item->flags & LINK_FLAG_HIDDEN) == 0)
        {
            if ((item->flags & LINK_FLAG_FADE_TIMER_ONLY) != 0)
            {
                timer = item->timer - 1;
                item->timer = timer;
                if (timer < 0)
                {
                    item->timer = 0;
                }
            }
            else
            {
                if (item->state != -1)
                {
                    drawItem = &lbl_803A9458[item->state];
                }

                if ((drawItem->flags & LINK_FLAG_DRAW_SLOTS) != 0)
                {
                    slotIndex = 0;
                    x = drawItem->x;
                    y = drawItem->y;
                    while (drawItem->slots[slotIndex] != -1 && slotIndex < 25)
                    {
                        textureIndex = drawItem->slots[slotIndex];
                        drawTexture(((LinkTexture*)linkTextures)[textureIndex].texture, 0xff, (f32)x, (f32)y, 0x100);
                        x += ((LinkTexture*)linkTextures)[drawItem->slots[slotIndex]].width;
                        slotIndex++;
                    }
                }

                if ((drawItem->flags & LINK_FLAG_DIM_OPACITY) != 0)
                {
                    opacity = linkItemOpacity * 200 >> 8;
                }
                else
                {
                    opacity = linkItemOpacity;
                }

                MWTRACE(drawItem->boxId);
                if (linkSelected == i)
                {
                    alpha = opacity;
                }
                else
                {
                    alpha = (((int)((u32)opacity >> 31)) + opacity) >> 1;
                }
                *(u8*)((char*)gameTextGetBox(drawItem->boxId) + 0x1e) = (u8)alpha;

                if ((drawItem->flags & LINK_FLAG_DRAW_BLACK_SHADOW) != 0)
                {
                    gameTextSetColor(0, 0, 0, (u8)(((linkCount_803dd90e + 1) * linkItemOpacity) >> 8));
                    gameTextFn_80016810(drawItem->textId, 2, 2);
                }

                if ((drawItem->flags & LINK_FLAG_SELECTED_COLOR) != 0)
                {
                    if (linkSelected == i)
                    {
                        red = lbl_803DD904 + ((linkCount_803dd90e * (lbl_803DD8FE - lbl_803DD904)) >> 8);
                        green = lbl_803DD902 + ((linkCount_803dd90e * (lbl_803DD8FC - lbl_803DD902)) >> 8);
                        blue = lbl_803DD900 + ((linkCount_803dd90e * (lbl_803DD8FA - lbl_803DD900)) >> 8);
                        if ((drawItem->flags & LINK_FLAG_DIM_OPACITY) != 0)
                        {
                            alpha = linkItemOpacity * 200 >> 8;
                        }
                        else
                        {
                            alpha = linkItemOpacity;
                        }
                        gameTextSetColor((u8)red, (u8)green, (u8)blue, (u8)alpha);
                    }
                    else
                    {
                        gameTextSetColor((u8)lbl_803DD904, (u8)lbl_803DD902, (u8)lbl_803DD900,
                                         (u8)((((int)((u32)opacity >> 31)) + opacity) >> 1));
                    }
                }
                else
                {
                    gameTextSetColor(0xff, 0xff, 0xff, (u8)opacity);
                }

                textId = drawItem->textId;
                if (textId > 0x14 && textId != 0xffff)
                {
                    gameTextShow(textId);
                }
                else if (textId != 0xffff)
                {
                    gameTextShowStr((char*)saveFileSelect_saveSlots + textId * 0x24, drawItem->boxId, 0, 0);
                }

                if (drawItem->texture != NULL)
                {
                    if ((drawItem->flags & LINK_FLAG_DRAW_SLOTS) != 0)
                    {
                        if ((drawItem->flags & LINK_FLAG_DIM_OPACITY) != 0)
                        {
                            alpha = linkItemOpacity * 200 >> 8;
                        }
                        else
                        {
                            alpha = linkItemOpacity;
                        }
                        drawTexture(drawItem->texture, (u8)alpha, (f32)(drawItem->x + 11), (f32)drawItem->y, 0x100);
                    }
                    else
                    {
                        if ((drawItem->flags & LINK_FLAG_DIM_OPACITY) != 0)
                        {
                            alpha = linkItemOpacity * 200 >> 8;
                        }
                        else
                        {
                            alpha = linkItemOpacity;
                        }
                        drawTexture(drawItem->texture, (u8)alpha, (f32)drawItem->x, (f32)drawItem->y, 0x100);
                    }
                }

                timer = drawItem->timer - 1;
                drawItem->timer = timer;
                if (timer < 0)
                {
                    drawItem->timer = 0;
                }
            }
        }

        item++;
    }

    MWTRACE(0xff);
}

#include "main/audio/sfx_ids.h"
#include "main/dll/baddie/TumbleweedBush.h"

typedef struct TitleMenuItem
{
    s16 x;
    s16 y;
    u8 flags;
    u8 kind;
    s8 frameDelay;
    u8 pad7;
    s16 minValue;
    s16 maxValue;
    s16 value;

    union
    {
        s16 textId;

        struct
        {
            u16 phraseId;
            u16 windowId;
        } window;
    } extra;
} TitleMenuItem;

typedef struct LinkTextureSlot
{
    void* texture;
    s16 assetId;
    u8 width;
    u8 pad7;
} LinkTextureSlot;

typedef struct LinkMenuItem
{
    u16 textId;
    u16 boxId;
    s16 field04;
    s16 field06;
    s16 field08;
    s16 x;
    s16 y;
    u8 pad0E[2];

    union
    {
        int textureAssetId;
        void* texture;
    };

    u16 field14;
    u16 flags;
    u8 pad18[2];
    s8 upLink;
    s8 downLink;
    s8 leftLink;
    s8 rightLink;
    s8 state;
    s8 slots[25];
    s8 timer;
    u8 pad39[3];
} LinkMenuItem;

#define TITLE_MENU_FLAG_ENABLED        0x01
#define TITLE_MENU_FLAG_WRAP           0x02
#define TITLE_MENU_FLAG_MOVED_LEFT     0x04
#define TITLE_MENU_FLAG_MOVED_RIGHT    0x08
#define TITLE_MENU_FLAG_CHANGED        0x10
#define TITLE_MENU_FLAG_A_TOGGLE       0x20
#define TITLE_MENU_FLAG_VOLUME_PREVIEW 0x40
#define TITLE_MENU_FLAG_MUSIC_PREVIEW  0x80

#define LINK_FLAG_DISABLE_NAV_TO 0x1000
#define LINK_FLAG_NO_ACCEPT      0x0020
#define LINK_IS_NAVIGABLE(index) ((lbl_803A9458[(index)].flags & LINK_FLAG_DISABLE_NAV_TO) == 0)


extern undefined8 FUN_80003494();
extern undefined4 FUN_800067b0();
extern undefined4 FUN_80006818();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068c4();
extern undefined8 FUN_80006b9c();
extern undefined4 FUN_80006ba8();
extern undefined4 FUN_80006bac();
extern undefined4 FUN_80006bb0();
extern undefined4 FUN_80006bb4();
extern undefined4 FUN_80006c6c();
extern undefined4 FUN_80017460();
extern undefined4 FUN_80017480();
extern undefined4 FUN_80017484();
extern undefined4 FUN_8001750c();
extern undefined4 FUN_80017510();
extern uint GameBit_Get(int eventId);
extern int FUN_800176d0();
extern undefined4 FUN_80017814();
extern int FUN_80017830();
extern undefined4 FUN_80053754();
extern int FUN_8005398c();
extern undefined4 FUN_800709e8();
extern undefined8 FUN_800723a0();
extern undefined8 FUN_80286824();
extern undefined2 FUN_8028683c();
extern undefined2 FUN_80286840();
extern undefined4 FUN_80286870();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern int getHudHiddenFrameCount(void);
extern void padGetAnalogInput(int pad, s8* x, s8* y);
extern void padClearAnalogInputY(int pad);
extern void padClearAnalogInputX(int pad);
extern u32 getButtonsJustPressed(int pad);
extern void buttonDisable(int pad, int mask);
extern void linkDrawFn_801302c0(void);
extern void linkDrawFn_80130484(void);
extern u8 framesThisStep;
extern s8 lbl_803DD910;
extern s8 lbl_803DD913;

extern undefined4 DAT_8031cdf8;
extern undefined4 DAT_8031ce04;
extern short DAT_8031cef8;
extern undefined2 DAT_803aa0b8;
extern undefined4 DAT_803aa0bc;
extern undefined4 DAT_803aa0c2;
extern undefined4 DAT_803aa0cc;
extern undefined4 DAT_803aa0ce;
extern undefined4 DAT_803aa0d2;
extern undefined4 DAT_803aa0d3;
extern undefined4 DAT_803aa0d4;
extern undefined4 DAT_803aa0d5;
extern undefined4 DAT_803aa0d6;
extern int DAT_803aaa18;
extern undefined4 DAT_803aaa1c;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803de578;
extern undefined4 DAT_803de579;
extern undefined4 DAT_803de57a;
extern undefined4 DAT_803de57c;
extern undefined4 DAT_803de57e;
extern undefined4 DAT_803de580;
extern undefined4 DAT_803de582;
extern undefined4 DAT_803de584;
extern undefined4* DAT_803de588;
extern undefined4 DAT_803de58c;
extern undefined4 DAT_803de58e;
extern undefined4 DAT_803de590;
extern undefined4 DAT_803de591;
extern undefined4 DAT_803de592;
extern undefined4 DAT_803de593;
extern undefined4 DAT_803de598;
extern undefined4 DAT_803de5a0;
extern f64 DOUBLE_803e2e78;
extern f32 FLOAT_803de59c;
extern f32 FLOAT_803e2e80;
extern f32 FLOAT_803e2e84;
extern f32 FLOAT_803e2e88;

/*
 * --INFO--
 *
 * Function: Link_update
 * EN v1.0 Address: 0x80130CF0
 * EN v1.0 Size: 936b
 * EN v1.1 Address: 0x80131078
 * EN v1.1 Size: 1168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 Link_update(void)
{
    extern LinkMenuItem lbl_803A9458[40]; /* #57 */
    extern s8 lbl_803DD911; /* #57 */
    LinkMenuItem* item;
    int result;
    u32 buttons;
    s8 horizontalInput;
    s8 verticalInput;

    item = &lbl_803A9458[(s8)linkSelected];
    if ((s8)lbl_803DD911 == 0)
    {
        return -1;
    }

    result = -1;
    if (getHudHiddenFrameCount() != 0)
    {
        return -1;
    }

    padGetAnalogInput(0, &horizontalInput, &verticalInput);
    if (linkIsRotated != 0)
    {
        s8 oldHorizontal = horizontalInput;
        horizontalInput = verticalInput;
        verticalInput = (s8) - oldHorizontal;
    }

    if (verticalInput != 0)
    {
        horizontalInput = 0;
    }

    if (((horizontalInput != 0) || (verticalInput != 0)) && (linkFlag_803dd8f8 != 0))
    {
        if ((verticalInput < 0) && (item->downLink != -1) && LINK_IS_NAVIGABLE(item->downLink))
        {
            padClearAnalogInputY(0);
            linkSelected = item->downLink;
            linkCount_803dd90e = 0xff;
        }
        else if ((verticalInput > 0) && (item->upLink != -1) &&
            LINK_IS_NAVIGABLE(item->upLink))
        {
            padClearAnalogInputY(0);
            linkSelected = item->upLink;
            linkCount_803dd90e = 0xff;
        }

        if (item->state != -1)
        {
            item = &lbl_803A9458[item->state];
            if ((horizontalInput < 0) && (item->leftLink != -1))
            {
                padClearAnalogInputX(0);
                lbl_803A9458[(s8)linkSelected].state = item->leftLink;
                linkCount_803dd90e = 0xff;
            }
            else if ((horizontalInput > 0) && (item->rightLink != -1))
            {
                padClearAnalogInputX(0);
                lbl_803A9458[(s8)linkSelected].state = item->rightLink;
                linkCount_803dd90e = 0xff;
            }
        }
        else
        {
            if ((horizontalInput < 0) && (item->leftLink != -1) &&
                LINK_IS_NAVIGABLE(item->leftLink))
            {
                padClearAnalogInputX(0);
                linkSelected = item->leftLink;
                linkCount_803dd90e = 0xff;
            }
            else if ((horizontalInput > 0) && (item->rightLink != -1) &&
                LINK_IS_NAVIGABLE(item->rightLink))
            {
                padClearAnalogInputX(0);
                linkSelected = item->rightLink;
                linkCount_803dd90e = 0xff;
            }
        }

        if ((s8)linkSelected < 0)
        {
            linkSelected = (s8)((s8)lbl_803DD911 - 1);
        }
        if ((s8)linkSelected >= (s8)lbl_803DD911)
        {
            linkSelected = 0;
        }
    }

    if (lbl_803DD913 != 0)
    {
        buttons = getButtonsJustPressed(0);
        if ((buttons & 0x1100) != 0)
        {
            if (((lbl_803A9458[(s8)linkSelected].flags & LINK_FLAG_NO_ACCEPT) == 0) &&
                (GameBit_Get(0x44f) == 0))
            {
                buttonDisable(0, 0x1100);
                result = 1;
            }
        }
        else if ((buttons & 0x200) != 0)
        {
            buttonDisable(0, 0x200);
            result = 0;
        }
    }

    if (lbl_803DD910 != 0)
    {
        linkCount_803dd90e = (s16)(linkCount_803dd90e + framesThisStep * 5);
    }
    else
    {
        linkCount_803dd90e = (s16)(linkCount_803dd90e - framesThisStep * 5);
    }

    if (linkCount_803dd90e > 0xff)
    {
        linkCount_803dd90e = (s16)(0xff - (linkCount_803dd90e - 0xff));
        lbl_803DD910 = (s8)(lbl_803DD910 ^ 1);
    }
    else if (linkCount_803dd90e < 0)
    {
        linkCount_803dd90e = (s16) - linkCount_803dd90e;
        lbl_803DD910 = (s8)(lbl_803DD910 ^ 1);
    }

    lbl_803DD913 = 1;
    linkDrawFn_801302c0();
    linkDrawFn_80130484();
    return result;
}


/* ===== EN v1.0 retargeted leaves ========================================= */

/* EN v1.0 0x80131570  size: 12b  Read changed bit from item->flags. */
int TitleMenuItem_isChanged(TitleMenuItem* item);

/* EN v1.0 0x8013157C  size: 20b  Set item->value and item->frameDelay = 2.
 * Logic-only ? target has `extsh r0,r4; sth r0,0xc(r3)` but MWCC -O4
 * strips the redundant extsh before sth (same family as GameUI_func0F /
 * CMenu_SetShouldClose). */
void TitleMenuItem_setVal(TitleMenuItem* item, int val);

/* EN v1.0 0x80131590  size: 8b   Getter for item->value. */
s16 TitleMenuItem_getVal(TitleMenuItem* item);

extern s16 lbl_803DD918;
extern f32 lbl_803DD91C;
extern s8 lbl_803DD920;
extern void* lbl_803A9DB8[6];
extern f32 lbl_803E21F0;
extern f32 lbl_803E21F4;
extern f32 lbl_803E21F8;
extern s8 padGetStickX(int port);
extern void Sfx_PlayFromObject(u32 obj, u32 sfxId);
extern void Sfx_KeepAliveLoopedObjectSound(u32 obj, u32 sfxId);
extern void Sfx_SetObjectSfxVolume(u32 obj, u32 sfxId, u8 volume, f32 volumeScale);
extern void Music_PlayTrackByIndex(int index);
extern void* gameTextGetPhrase(int textId, int variant);
extern void gameTextSetColor(int r, int g, int b, int a);
extern void gameTextSetWindowStrPos(int windowId, int x, int y);
extern void gameTextAppendStr(void* str, int windowId);

/* EN v1.0 0x80131598  size: 116b  Toggle enabled bit on item->flags. */
void TitleMenuItem_setEnabled(TitleMenuItem* item, int flag);

/* EN v1.0 0x8013160C  size: 12b  Read enabled bit from item->flags. */
int TitleMenuItem_isEnabled(TitleMenuItem* item);

/* EN v1.0 0x80131618  size: 808b  Render title menu item. */
void TitleMenuItem_render(TitleMenuItem* item, int unused, int alpha);

/* EN v1.0 0x80131940  size: 948b  Update title menu item input state. */
void TitleMenuItem_update(TitleMenuItem* item);

/* EN v1.0 0x80132008  size: 8b   Trivial 1-returner. */
int Dummy3E_func05_ret_1(void);

/* EN v1.0 0x80132010  size: 4b   Empty no-op. */
void Dummy3E_func04_nop(void);

/* EN v1.0 0x80132014  size: 8b   Trivial 0-returner. */
int Dummy3E_func03_ret_0(void);

/* EN v1.0 0x8013201C  size: 4b   Empty no-op. */
void Dummy3E_release(void);

/* EN v1.0 0x80132020  size: 4b   Empty no-op. */
void Dummy3E_initialise(void);

extern s16 lbl_8031C2A8[6];
extern void mm_free(void);
extern void fn_8001BDD4(int);

/* EN v1.0 0x80131540  size: 48b  Toggle A-button bit of item->flags. */
void TitleMenuItem_setAButtonToggle(TitleMenuItem* item, int flag);

/* EN v1.0 0x80131CF4  size: 32b  Wrapper for mm_free. */
void TitleMenuItem_free(void);

/* EN v1.0 0x80131FE0  size: 40b  Zero 6 u32s at lbl_803A9DB8. */
void TitleMenuItem_initialise(void);

/* Drift-recovery: add new fns with v1.0 names. */
extern void fn_8001BE2C(int mode);
extern void* mmAlloc(int size, int heap, int flags);
extern void* memcpy(void* dst, const void* src, int size);
extern void padFn_80014b18(int value);
extern const char* lbl_803DD908;
extern char lbl_8031C1A8[];


/* EN v1.0 0x80131D14  size: 168b  Create text-window title menu item. */
TitleMenuItem* TitleMenuItem_createWithWindow(int phraseId, int windowId, s16 minValue, s16 maxValue, s16 value);

/* EN v1.0 0x80131DBC  size: 164b  Create simple title menu item. */
TitleMenuItem* TitleMenuItem_create(s16 x, s16 y, s16 minValue, s16 maxValue, s16 value);

/* EN v1.0 0x80131E60  size: 172b  Create text-backed title menu item. */
TitleMenuItem* TitleMenuItem_createWithText(s16 x, s16 y, s16 minValue, s16 maxValue, s16 value, int textId);

void fn_80131F0C(void);

void Link_release(void)
{
    u8* p;
    int i;

    i = 0;
    p = linkTextures;
    for (; i < 6; i++)
    {
        textureFree(*(void**)p);
        p += 8;
    }
    fn_8001BDD4(3);
}

void Link_initialise(void)
{
    LinkTextureSlot* slot;
    int i;

    i = 0;
    slot = (LinkTextureSlot*)linkTextures;
    for (; i < 6; i++)
    {
        slot->texture = textureLoadAsset(slot->assetId);
        slot++;
    }

    padFn_80014b18(10);
    linkItemOpacity = 0xff;
    fn_8001BE2C(3);
    linkIsRotated = 0;
    linkFlag_803dd8f8 = 1;
}

void Link_setup(LinkMenuItem* items, int count, int selected, const char* defaultMessage,
                int unused1, int unused2, int baseRed, int baseGreen, int baseBlue,
                int selectedRed, int selectedGreen, int selectedBlue)
{
    extern void linkInitTextures(LinkMenuItem* item); /* #57 */
    extern LinkMenuItem lbl_803A9458[40]; /* #57 */
    extern s8 lbl_803DD911; /* #57 */
    const char* defaultText;
    LinkMenuItem* src;
    LinkMenuItem* item;
    int linkedIndex;
    int i;

    src = items;
    defaultText = lbl_8031C1A8;
    if (count <= 40)
    {
        lbl_803DD911 = (s8)count;
        linkCount_803dd90e = 0xff;
        linkSelected = (s8)selected;
        lbl_803DD910 = 0;
        lbl_803DD913 = 0;

        memcpy(lbl_803A9458, items, count * sizeof(LinkMenuItem));

        item = lbl_803A9458;
        for (i = 0; i < count; i++)
        {
            linkedIndex = item->upLink;
            if ((linkedIndex < -1) || (linkedIndex >= count))
            {
                OSReport(defaultText + 0xa4, linkedIndex);
            }

            linkedIndex = item->downLink;
            if ((linkedIndex < -1) || (linkedIndex >= count))
            {
                OSReport(defaultText + 0xb8, linkedIndex);
            }

            linkedIndex = item->leftLink;
            if ((linkedIndex < -1) || (linkedIndex >= count))
            {
                OSReport(defaultText + 0xd0, linkedIndex);
            }

            linkedIndex = item->rightLink;
            if ((linkedIndex < -1) || (linkedIndex >= count))
            {
                OSReport(defaultText + 0xe8, linkedIndex);
            }

            if (src->textureAssetId != -1)
            {
                item->texture = textureLoadAsset(src->textureAssetId);
            }
            else
            {
                item->texture = NULL;
            }

            if ((item->flags & 0x10) != 0)
            {
                item->field14 = 0;
                item->field08 = 0;
            }

            if ((item->flags & 0x04) != 0)
            {
                linkInitTextures(item);
            }

            linkedIndex = item->leftLink;
            if ((linkedIndex != -1) && ((item->flags & 0x08) != 0))
            {
                LinkMenuItem* linked = &lbl_803A9458[linkedIndex];
                item->x = linked->x + linked->field14;
                item->field04 = linked->field04 + linked->field14;
            }

            if ((item->flags & 0x0400) != 0)
            {
                item->x -= (s16)(item->field14 >> 1);
                item->field04 = item->x;
            }

            item->timer = 4;
            item++;
            src++;
        }

        lbl_803DD904 = baseRed;
        lbl_803DD902 = baseGreen;
        lbl_803DD900 = baseBlue;
        lbl_803DD8FE = selectedRed;
        lbl_803DD8FC = selectedGreen;
        lbl_803DD8FA = selectedBlue;
        if (defaultMessage != NULL)
        {
            defaultText = defaultMessage;
        }
        lbl_803DD908 = defaultText;
    }
}

void TitleMenuItem_release(void);

void Link_free(void)
{
    extern LinkMenuItem lbl_803A9458[40]; /* #57 */
    extern s8 lbl_803DD911; /* #57 */
    LinkMenuItem* item;
    int i;

    i = 0;
    item = lbl_803A9458;
    for (; i < (s8)lbl_803DD911; i++)
    {
        if (item->texture != NULL)
        {
            textureFree(item->texture);
        }
        item++;
    }
    lbl_803DD911 = 0;
}


/* === helper-last relocation (re-split inline suppression; defs moved below their callers to suppress cross-TU-merge auto-inlining) === */
void linkDrawFn_801302c0(void)
{
    extern s8 lbl_803DD911; /* #57 */
    extern LinkMenuItemDB lbl_803A9458[40];
    LinkMenuItemDB* sel;
    LinkMenuItemDB* p;
    void* tex;
    int selLeft;
    int selRight;
    int itemLeft;
    int itemRight;
    int w;
    int i;

    sel = &lbl_803A9458[(s8)linkSelected];
    sel->field38 = 4;
    if (((sel->field16 & 4) != 0) && ((s8)sel->slots[0] != -1))
    {
        tex = *(void**)(linkTextures + (s8)sel->slots[0] * 8);
    }
    else
    {
        tex = sel->texture;
    }
    if (tex != NULL)
    {
        w = *(u16*)((char*)tex + 12);
        selLeft = sel->field0C;
    }
    else
    {
        if (getCurLanguage() == 4)
        {
            w = *(u16*)(lbl_802C8680 + 0xa) + 2;
        }
        else
        {
            w = *(u16*)(lbl_802C8680 + 0x4a) + 2;
        }
        selLeft = sel->field06 - 2;
    }
    selRight = selLeft + w;
    p = lbl_803A9458;
    for (i = 0; i < (s8)lbl_803DD911; i++)
    {
        if (i != (s8)linkSelected)
        {
            if (((p->field16 & 4) != 0) && ((s8)p->slots[0] != -1))
            {
                tex = *(void**)(linkTextures + (s8)p->slots[0] * 8);
            }
            else
            {
                tex = p->texture;
            }
            if (tex != NULL)
            {
                w = *(u16*)((char*)tex + 12);
                itemLeft = p->field0C;
            }
            else
            {
                if (getCurLanguage() == 4)
                {
                    w = *(u16*)(lbl_802C8680 + 0xa) + 2;
                }
                else
                {
                    w = *(u16*)(lbl_802C8680 + 0x4a) + 2;
                }
                itemLeft = p->field06 - 2;
            }
            itemRight = itemLeft + w;
            if (itemLeft < selRight && itemRight > selLeft)
            {
                p->field38 = 4;
            }
        }
        p++;
    }
}

void linkDrawFn_80130484(void)
{
    extern s8 lbl_803DD911; /* #57 */
    extern LinkMenuItemDB lbl_803A9458[40];
    LinkMenuItemDB* p;
    void* tex;
    int minX;
    int maxX;
    int w;
    int x;
    int right;
    int i;

    minX = 480;
    maxX = 0;
    p = lbl_803A9458;
    for (i = 0; i < (s8)lbl_803DD911; i++)
    {
        if (((p->field16 & 4) != 0) && ((s8)p->slots[0] != -1))
        {
            tex = *(void**)(linkTextures + (s8)p->slots[0] * 8);
        }
        else
        {
            tex = p->texture;
        }
        if (tex != NULL)
        {
            w = *(u16*)((char*)tex + 12);
            x = p->field0C;
        }
        else
        {
            if (getCurLanguage() == 4)
            {
                w = *(u16*)(lbl_802C8680 + 0xa) + 2;
            }
            else
            {
                w = *(u16*)(lbl_802C8680 + 0x4a) + 2;
            }
            x = p->field06 - 2;
        }
        right = x + w;
        if (x < minX)
        {
            minX = x;
        }
        if (right > maxX)
        {
            maxX = right;
        }
        p++;
    }
}
