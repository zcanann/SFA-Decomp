/*
 * dll_003C - the "Link" on-screen menu / icon-bar widget (despite the
 * TumbleweedBush DLL name, this object's symbol set is the EN v1.0 Link
 * menu code that was retargeted into this TU).
 *
 * A Link menu is an array of up to 40 LinkMenuItem entries (mirror copy in
 * lbl_803A9458). Each item carries a textId/boxId, position, a texture, and
 * up/down/left/right navigation links. Link_setup() installs the items and
 * the base/selected text colors; Link_update() reads analog + button input,
 * walks the navigation links, drives the highlight pulse (linkCount_803dd90e
 * oscillating 0..0xFF via lbl_803DD910) and returns 1 (accept) / 0 (cancel) /
 * -1 (idle). Link_render() draws each item's text/box/texture with the pulsed
 * highlight color and per-slot icon strip. The slot icons are picked by
 * linkInitTextures() from a random budget over the six entries in linkTextures
 * (LinkTextureSlot[6]).
 *
 * Item flag bits (LINK_FLAG_*) select draw style; navigation honors
 * LINK_FLAG_DISABLE_NAV_TO / LINK_FLAG_NO_ACCEPT. GameBit 0x44f gates accept.
 */
#pragma scheduling on
#pragma peephole on
#include "main/dll/baddie/dll_003C_TumbleweedBush.h"

extern u8 linkFlag_803dd8f8;        /* whether navigation input is accepted */
extern u8 linkIsRotated;            /* swap analog axes (rotated layout) */
extern s16 linkItemOpacity;
extern s16 linkCount_803dd90e;      /* selected-item highlight pulse counter */
extern s8 linkSelected;
extern u8 linkTextures[0x30];       /* LinkTextureSlot[6] */
extern s16 lbl_803DD8FA;            /* selected-color B */
extern s16 lbl_803DD8FC;            /* selected-color G */
extern s16 lbl_803DD8FE;            /* selected-color R */
extern s16 lbl_803DD900;            /* base-color B */
extern s16 lbl_803DD902;            /* base-color G */
extern s16 lbl_803DD904;            /* base-color R */
extern s8 lbl_803DD910;             /* highlight pulse direction */
extern s8 lbl_803DD913;             /* input enabled after first update */
extern const char* lbl_803DD908;    /* default message text */
extern void* saveFileSelect_saveSlots;
extern u8 framesThisStep;

extern u32 randomGetRange(int min, int max);
extern void textureFree(void* p);
extern void* textureLoadAsset(int id);
extern void OSReport(const char* fmt, ...);
extern char lbl_8031C234[]; /* "too many slots" overflow error format string */
extern char lbl_8031C1A8[]; /* base of the nav-link out-of-range error format strings */
extern int getCurLanguage(void);
extern u8 lbl_802C8680[];
extern void drawTexture(void* texture, u8 alpha, f32 x, f32 y, u16 scale);
extern void gameTextFn_80016810(int textId, int arg1, int arg2);
extern void* gameTextGetBox(int boxId);
extern void gameTextShow(int textId);
extern void gameTextShowStr(void* text, int boxId, int arg2, int arg3);
extern void gameTextSetColor(int r, int g, int b, int a);
extern void MWTRACE(int boxId);
extern uint GameBit_Get(int eventId);
extern int getHudHiddenFrameCount(void);
extern void padGetAnalogInput(int pad, s8* x, s8* y);
extern void padClearAnalogInputY(int pad);
extern void padClearAnalogInputX(int pad);
extern u32 getButtonsJustPressed(int pad);
extern void buttonDisable(int pad, int mask);
extern void linkDrawFn_801302c0(void);
extern void linkDrawFn_80130484(void);
extern void fn_8001BDD4(int mode); /* mode 3: free the three subtitle textures */
extern void fn_8001BE2C(int mode); /* mode 3: (re)load the three subtitle textures */
extern void* memcpy(void* dst, const void* src, int size);
extern void padFn_80014b18(int value);

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

void titleScreenFn_80130464(u8 v) { linkFlag_803dd8f8 = v; }
void setLinkNotRotated(void) { linkIsRotated = 0; }
void setLinkIsRotated(void) { linkIsRotated = 1; }
u8 Link_func0C(void) { return (u8)linkCount_803dd90e; }
#pragma scheduling off
#pragma peephole off
void Link_func0A(int idx, int v) { extern LinkMenuItemDB lbl_803A9458[40];  lbl_803A9458[idx].state = (s8)v; }
#pragma peephole reset
s32 Link_func09(int idx) { extern LinkMenuItemDB lbl_803A9458[40];  return lbl_803A9458[idx].state; }
#pragma scheduling reset
void Link_setOpacity(u8 v) { linkItemOpacity = v; }
#pragma peephole off
void Link_setSelected(int v) { linkSelected = (s8)v; }
#pragma peephole reset
s32 Link_getSelected(void) { return linkSelected; }

#pragma scheduling off
u16 fn_80130124(void)
{
    extern LinkMenuItemDB lbl_803A9458[40];
    return lbl_803A9458[linkSelected].itemId;
}
#pragma scheduling reset
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
    i = 1;
    item->slots[0] = 0;
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
    item->slots[i++] = 1;
    if (i >= 25)
    {
        OSReport(lbl_8031C234);
    }
}
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
    LinkMenuItemDB* src;
    int i;

    i = 0;
    src = (LinkMenuItemDB*)srcArg;
    for (; i < (s8)lbl_803DD911; i++)
    {
        lbl_803A9458[i].field16 = src->field16;
        lbl_803A9458[i].field1A = src->field1A;
        lbl_803A9458[i].field04 = src->field04;
        if (src->textureAssetId != -1)
        {
            if (lbl_803A9458[i].texture == NULL)
            {
                lbl_803A9458[i].texture = textureLoadAsset(src->textureAssetId);
            }
        }
        else
        {
            if (lbl_803A9458[i].texture != NULL)
            {
                textureFree(lbl_803A9458[i].texture);
            }
            lbl_803A9458[i].texture = NULL;
        }
        src++;
    }
}
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off
void Link_func0B(u8* srcArg)
{
    extern s8 lbl_803DD911; /* #57 */
    extern LinkMenuItemDB lbl_803A9458[40];
    LinkMenuItemDB* src;
    int i;

    src = (LinkMenuItemDB*)srcArg;
    for (i = 0; i < lbl_803DD911; i++)
    {
        lbl_803A9458[i].field00 = src[i].field00;
        lbl_803A9458[i].itemId = src[i].itemId;
        lbl_803A9458[i].field38 = 2;
    }
}
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling reset

typedef struct LinkTextureSlot
{
    void* texture;
    s16 assetId;
    u8 width;
    u8 pad7;
} LinkTextureSlot;

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

#define LINK_FLAG_DRAW_SLOTS       0x0004
#define LINK_FLAG_DRAW_BLACK_SHADOW 0x0100
#define LINK_FLAG_DIM_OPACITY      0x0800
#define LINK_FLAG_FADE_TIMER_ONLY  0x1040
#define LINK_FLAG_HIDDEN           0x4000
#define LINK_FLAG_SELECTED_COLOR   0x0080

#pragma peephole off
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
                        drawTexture(((LinkTextureSlot*)linkTextures)[textureIndex].texture, 0xff, (f32)x, (f32)y, 0x100);
                        x += ((LinkTextureSlot*)linkTextures)[drawItem->slots[slotIndex]].width;
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
#pragma peephole reset

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

#define LINK_FLAG_DISABLE_NAV_TO 0x1000
#define LINK_FLAG_NO_ACCEPT      0x0020
#define LINK_FLAG_INHERIT_X      0x0008
#define LINK_FLAG_NO_SLOTS       0x0010
#define LINK_FLAG_CENTRE         0x0400
#define LINK_IS_NAVIGABLE(index) ((lbl_803A9458[(index)].flags & LINK_FLAG_DISABLE_NAV_TO) == 0)

#pragma peephole off
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
#pragma peephole reset

/* ===== EN v1.0 retargeted leaves ========================================= */

/* EN v1.0 0x80131570  size: 12b  Read changed bit from item->flags. */

/* EN v1.0 0x8013157C  size: 20b  Set item->value and item->frameDelay = 2.
 * Logic-only ? target has `extsh r0,r4; sth r0,0xc(r3)` but MWCC -O4
 * strips the redundant extsh before sth (same family as GameUI_func0F /
 * CMenu_SetShouldClose). */

/* EN v1.0 0x80131590  size: 8b   Getter for item->value. */

/* EN v1.0 0x80131598  size: 116b  Toggle enabled bit on item->flags. */

/* EN v1.0 0x8013160C  size: 12b  Read enabled bit from item->flags. */

/* EN v1.0 0x80131618  size: 808b  Render title menu item. */

/* EN v1.0 0x80131940  size: 948b  Update title menu item input state. */

/* EN v1.0 0x80132008  size: 8b   Trivial 1-returner. */

/* EN v1.0 0x80132010  size: 4b   Empty no-op. */

/* EN v1.0 0x80132014  size: 8b   Trivial 0-returner. */

/* EN v1.0 0x8013201C  size: 4b   Empty no-op. */

/* EN v1.0 0x80132020  size: 4b   Empty no-op. */

/* EN v1.0 0x80131540  size: 48b  Toggle A-button bit of item->flags. */

/* EN v1.0 0x80131CF4  size: 32b  Wrapper for mm_free. */

/* EN v1.0 0x80131FE0  size: 40b  Zero 6 u32s at lbl_803A9DB8. */

/* EN v1.0 0x80131D14  size: 168b  Create text-window title menu item. */

/* EN v1.0 0x80131DBC  size: 164b  Create simple title menu item. */

/* EN v1.0 0x80131E60  size: 172b  Create text-backed title menu item. */

#pragma peephole off
void Link_release(void)
{
    int i;

    for (i = 0; i < 6; i++)
    {
        textureFree(((LinkTextureSlot*)linkTextures)[i].texture);
    }
    fn_8001BDD4(3);
}
#pragma peephole reset

#pragma peephole off
void Link_initialise(void)
{
    int i;

    for (i = 0; i < 6; i++)
    {
        ((LinkTextureSlot*)linkTextures)[i].texture =
            textureLoadAsset(((LinkTextureSlot*)linkTextures)[i].assetId);
    }

    padFn_80014b18(10);
    linkItemOpacity = 0xff;
    fn_8001BE2C(3);
    linkIsRotated = 0;
    linkFlag_803dd8f8 = 1;
}
#pragma peephole reset

#pragma peephole off
void Link_setup(LinkMenuItem* items, int count, int selected, const char* defaultMessage,
                int unused1, int unused2, int baseRed, int baseGreen, int baseBlue,
                int selectedRed, int selectedGreen, int selectedBlue)
{
    extern void linkInitTextures(LinkMenuItemDB* item); /* #57 */
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

            if ((item->flags & LINK_FLAG_NO_SLOTS) != 0)
            {
                item->field14 = 0;
                item->field08 = 0;
            }

            if ((item->flags & LINK_FLAG_DRAW_SLOTS) != 0)
            {
                linkInitTextures((LinkMenuItemDB*)item);
            }

            linkedIndex = item->leftLink;
            if ((linkedIndex != -1) && ((item->flags & LINK_FLAG_INHERIT_X) != 0))
            {
                LinkMenuItem* linked = &lbl_803A9458[linkedIndex];
                item->x = linked->x + linked->field14;
                item->field04 = linked->field04 + linked->field14;
            }

            if ((item->flags & LINK_FLAG_CENTRE) != 0)
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
#pragma peephole reset

void Link_free(void)
{
    extern LinkMenuItem lbl_803A9458[40]; /* #57 */
    extern s8 lbl_803DD911; /* #57 */
    int i;

    for (i = 0; i < (s8)lbl_803DD911; i++)
    {
        if (lbl_803A9458[i].texture != NULL)
        {
            textureFree(lbl_803A9458[i].texture);
        }
    }
    lbl_803DD911 = 0;
}

#pragma peephole off
void linkDrawFn_801302c0(void)
{
    extern s8 lbl_803DD911; /* #57 */
    extern LinkMenuItemDB lbl_803A9458[40];
    LinkMenuItemDB* sel;
    LinkMenuItemDB* p;
    void* tex;
    int i;
    int selLeft;
    int selRight;
    int itemLeft;
    int itemRight;
    int w;

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
    i = 0;
    p = lbl_803A9458;
    for (; i < (s8)lbl_803DD911; i++)
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
    void* tex;
    int i;
    int minX;
    int maxX;
    int w;
    int x;
    int right;

    minX = 480;
    maxX = 0;
    i = 0;
    for (; i < (s8)lbl_803DD911; i++)
    {
        if (((lbl_803A9458[i].field16 & 4) != 0) && ((s8)lbl_803A9458[i].slots[0] != -1))
        {
            tex = *(void**)(linkTextures + (s8)lbl_803A9458[i].slots[0] * 8);
        }
        else
        {
            tex = lbl_803A9458[i].texture;
        }
        if (tex != NULL)
        {
            w = *(u16*)((char*)tex + 12);
            x = lbl_803A9458[i].field0C;
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
            x = lbl_803A9458[i].field06 - 2;
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
    }
}
#pragma peephole reset
