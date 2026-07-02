/*
 * dll_003C - the "Link" on-screen menu / icon-bar widget (despite the
 * TumbleweedBush DLL name, this object's symbol set is the EN v1.0 Link
 * menu code that was retargeted into this TU).
 *
 * A Link menu is an array of up to 40 LinkMenuItem entries (mirror copy in
 * gTumbleweedBushItems). Each item carries a textId/boxId, position, a texture, and
 * up/down/left/right navigation links. Link_setup() installs the items and
 * the base/selected text colors; Link_update() reads analog + button input,
 * walks the navigation links, drives the highlight pulse (linkCount_803dd90e
 * oscillating 0..0xFF via gTumbleweedBushPulseDir) and returns 1 (accept) / 0 (cancel) /
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
#include "main/gameplay_runtime.h"
#include "main/texture.h"
#include "main/gamebits.h"
#include "main/pad.h"
#include "main/sfa_extern_decls.h"

#define LINK_ITEM_SLOTS 25          /* per-item icon-strip slot capacity */

extern u8 linkFlag_803dd8f8;        /* whether navigation input is accepted */
extern u8 linkIsRotated;            /* swap analog axes (rotated layout) */
extern s16 linkItemOpacity;
extern s16 linkCount_803dd90e;      /* selected-item highlight pulse counter */
extern s8 linkSelected;
extern u8 linkTextures[0x30];       /* LinkTextureSlot[6] */
extern s16 gTumbleweedBushSelColorB;            /* selected-color B */
extern s16 gTumbleweedBushSelColorG;            /* selected-color G */
extern s16 gTumbleweedBushSelColorR;            /* selected-color R */
extern s16 gTumbleweedBushBaseColorB;            /* base-color B */
extern s16 gTumbleweedBushBaseColorG;            /* base-color G */
extern s16 gTumbleweedBushBaseColorR;            /* base-color R */
extern s8 gTumbleweedBushPulseDir;             /* highlight pulse direction */
extern s8 gTumbleweedBushInputEnabled;             /* input enabled after first update */
extern const char* gTumbleweedBushDefaultText;    /* default message text */
extern void* saveFileSelect_saveSlots;
extern u8 framesThisStep;
extern void OSReport(const char* msg, ...);
extern char sTumbleweedBushSlotOverflowErr[]; /* "too many slots" overflow error format string */
extern char sTumbleweedBushNavLinkRangeErr[]; /* base of the nav-link out-of-range error format strings */

extern u8 lbl_802C8680[];
extern void drawTexture(void* texture, f32 x, f32 y, u8 alpha, u16 scale);
extern void gameTextFn_80016810(int a, int b, int c);
extern void* gameTextGetBox(int box);
extern void gameTextShow(int a);
extern void gameTextShowStr(char* text, int box, int arg2, int arg3);
extern void gameTextSetColor(int r, int g, int b, int a);
extern void MWTRACE(int boxId);
extern int getHudHiddenFrameCount(void);
extern void padGetAnalogInput(int pad, s8* x, s8* y);
extern void padClearAnalogInputY(int port);
extern void padClearAnalogInputX(int port);
extern void buttonDisable(int port, u32 mask);


extern void fn_8001BDD4(int mode); /* mode 3: free the three subtitle textures */
extern void fn_8001BE2C(int mode); /* mode 3: (re)load the three subtitle textures */
extern void* memcpy(void* dst, const void* src, int size);
extern void padFn_80014b18(int value);

typedef struct LinkMenuItemDB
{
    u16 textId;
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
    u16 flags;
    u8 pad18[2];
    u8 field1A;
    u8 pad1B[3];
    s8 state;
    s8 slots[LINK_ITEM_SLOTS];
    s8 field38;
    u8 pad39[3];
} LinkMenuItemDB;

void titleScreenFn_80130464(u8 v) { linkFlag_803dd8f8 = v; }
void setLinkNotRotated(void) { linkIsRotated = 0; }
void setLinkIsRotated(void) { linkIsRotated = 1; }
u8 Link_func0C(void) { return linkCount_803dd90e; }
#pragma scheduling off
#pragma peephole off
void Link_func0A(int idx, int v) { extern LinkMenuItemDB gTumbleweedBushItems[40];  gTumbleweedBushItems[idx].state = v; }
#pragma peephole reset
s32 Link_func09(int idx) { extern LinkMenuItemDB gTumbleweedBushItems[40];  return gTumbleweedBushItems[idx].state; }
#pragma scheduling reset
void Link_setOpacity(u8 v) { linkItemOpacity = v; }
#pragma peephole off
void Link_setSelected(int v) { linkSelected = v; }
#pragma peephole reset
s32 Link_getSelected(void) { return linkSelected; }

#pragma scheduling off
u16 fn_80130124(void)
{
    extern LinkMenuItemDB gTumbleweedBushItems[40];
    return gTumbleweedBushItems[linkSelected].itemId;
}
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off
void linkInitTextures(LinkMenuItemDB* item)
{
    int budget;
    int i;

    budget = item->field14;
    for (i = 0; i < LINK_ITEM_SLOTS; i++)
    {
        item->slots[i] = -1;
    }
    item->slots[(i = 1) - 1] = 0;
    budget -= linkTextures[6] + linkTextures[14];
    while (budget != 0)
    {
        if (budget >= 80)
        {
            item->slots[i] = randomGetRange(2, 5);
        }
        else if (budget >= 40)
        {
            item->slots[i] = randomGetRange(4, 5);
        }
        else
        {
            item->slots[i] = 5;
        }
        budget -= linkTextures[item->slots[i] * 8 + 6];
        i++;
    }
    item->slots[i++] = 1;
    if (i >= LINK_ITEM_SLOTS)
    {
        OSReport(sTumbleweedBushSlotOverflowErr);
    }
}
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off
void Link_func0F(void)
{
    extern s8 gTumbleweedBushItemCount; /* #57 */
    extern LinkMenuItemDB gTumbleweedBushItems[40];
    int i;

    for (i = 0; i < gTumbleweedBushItemCount; i++)
    {
        gTumbleweedBushItems[i].field38 = 4;
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
void Link_copy(u8* srcArg)
{
    extern u8 gTumbleweedBushItemCount; /* #57 */
    extern LinkMenuItemDB gTumbleweedBushItems[40];
    LinkMenuItemDB* dst;
    LinkMenuItemDB* src;
    int i;

    i = 0;
    for (; i < (s8)gTumbleweedBushItemCount; i++)
    {
        dst = &gTumbleweedBushItems[i];
        src = &((LinkMenuItemDB*)srcArg)[i];
        dst->flags = src->flags;
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
    }
}
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off
void Link_func0B(u8* srcArg)
{
    extern s8 gTumbleweedBushItemCount; /* #57 */
    extern LinkMenuItemDB gTumbleweedBushItems[40];
    LinkMenuItemDB* src;
    int i;

    src = (LinkMenuItemDB*)srcArg;
    for (i = 0; i < gTumbleweedBushItemCount; i++)
    {
        gTumbleweedBushItems[i].textId = src[i].textId;
        gTumbleweedBushItems[i].itemId = src[i].itemId;
        gTumbleweedBushItems[i].field38 = 2;
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
    s8 slots[LINK_ITEM_SLOTS];
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
    extern LinkMenuItemDA gTumbleweedBushItems[40]; /* #57 */
    extern s8 gTumbleweedBushItemCount; /* #57 */
    LinkMenuItemDA* item;
    int i;
    int slotIndex;
    LinkMenuItemDA* drawItem;
    int textureIndex;
    int opacity;
    int alpha;
    s16 red;
    s16 green;
    s16 blue;
    u16 textId;
    int x;
    int y;
    s8 timer;

    for (i = 0; i < gTumbleweedBushItemCount; i++)
    {
        item = &gTumbleweedBushItems[i];
        drawItem = item;

        if ((item->flags & LINK_FLAG_HIDDEN) == 0)
        {
            if ((item->flags & LINK_FLAG_FADE_TIMER_ONLY) != 0)
            {
                timer = (item->timer -= 1);
                if (timer < 0)
                {
                    item->timer = 0;
                }
            }
            else
            {
                if (item->state != -1)
                {
                    drawItem = &gTumbleweedBushItems[item->state];
                }

                if ((drawItem->flags & LINK_FLAG_DRAW_SLOTS) != 0)
                {
                    slotIndex = 0;
                    x = drawItem->x;
                    y = drawItem->y;
                    while (drawItem->slots[slotIndex] != -1 && slotIndex < LINK_ITEM_SLOTS)
                    {
                        textureIndex = drawItem->slots[slotIndex];
                        drawTexture(((LinkTextureSlot*)linkTextures)[textureIndex].texture, x, y, 0xff, 0x100);
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
                *(u8*)((char*)gameTextGetBox(drawItem->boxId) + 0x1e) = alpha;

                if ((drawItem->flags & LINK_FLAG_DRAW_BLACK_SHADOW) != 0)
                {
                    gameTextSetColor(0, 0, 0, (u8)(((linkCount_803dd90e + 1) * linkItemOpacity) >> 8));
                    gameTextFn_80016810(drawItem->textId, 2, 2);
                }

                if ((drawItem->flags & LINK_FLAG_SELECTED_COLOR) != 0)
                {
                    if (linkSelected == i)
                    {
                        red = gTumbleweedBushBaseColorR + ((linkCount_803dd90e * (gTumbleweedBushSelColorR - gTumbleweedBushBaseColorR)) >> 8);
                        green = gTumbleweedBushBaseColorG + ((linkCount_803dd90e * (gTumbleweedBushSelColorG - gTumbleweedBushBaseColorG)) >> 8);
                        blue = gTumbleweedBushBaseColorB + ((linkCount_803dd90e * (gTumbleweedBushSelColorB - gTumbleweedBushBaseColorB)) >> 8);
                        if ((drawItem->flags & LINK_FLAG_DIM_OPACITY) != 0)
                        {
                            alpha = linkItemOpacity * 200 >> 8;
                        }
                        else
                        {
                            alpha = linkItemOpacity * 256 >> 8;
                        }
                        gameTextSetColor((u8)red, (u8)green, (u8)blue, (u8)alpha);
                    }
                    else
                    {
                        gameTextSetColor((u8)gTumbleweedBushBaseColorR, (u8)gTumbleweedBushBaseColorG, (u8)gTumbleweedBushBaseColorB,
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
                        drawTexture(drawItem->texture, (f32)(drawItem->x + 11), drawItem->y, alpha, 0x100);
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
                        drawTexture(drawItem->texture, drawItem->x, drawItem->y, alpha, 0x100);
                    }
                }

                timer = (drawItem->timer -= 1);
                if (timer < 0)
                {
                    drawItem->timer = 0;
                }
            }
        }
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
    s8 slots[LINK_ITEM_SLOTS];
    s8 timer;
    u8 pad39[3];
} LinkMenuItem;

#define LINK_FLAG_DISABLE_NAV_TO 0x1000
#define LINK_FLAG_NO_ACCEPT      0x0020
#define LINK_FLAG_INHERIT_X      0x0008
#define LINK_FLAG_NO_SLOTS       0x0010
#define LINK_FLAG_CENTRE         0x0400
#define LINK_IS_NAVIGABLE(index) ((gTumbleweedBushItems[(index)].flags & LINK_FLAG_DISABLE_NAV_TO) == 0)

#pragma peephole off
#pragma opt_propagation off
u32 Link_update(void)
{
    extern LinkMenuItem gTumbleweedBushItems[40]; /* #57 */
    extern s8 gTumbleweedBushItemCount; /* #57 */
    int result;
    LinkMenuItem* item;
    u32 buttons;
    u8 acceptPressed;
    s8 horizontalInput;
    s8 verticalInput;

    item = &gTumbleweedBushItems[linkSelected];
    if ((s8)gTumbleweedBushItemCount == 0)
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
            item = &gTumbleweedBushItems[item->state];
            if ((horizontalInput < 0) && (item->leftLink != -1))
            {
                padClearAnalogInputX(0);
                gTumbleweedBushItems[linkSelected].state = item->leftLink;
                linkCount_803dd90e = 0xff;
            }
            else if ((horizontalInput > 0) && (item->rightLink != -1))
            {
                padClearAnalogInputX(0);
                gTumbleweedBushItems[linkSelected].state = item->rightLink;
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
            linkSelected = (s8)(gTumbleweedBushItemCount - 1);
        }
        if ((s8)linkSelected >= gTumbleweedBushItemCount)
        {
            linkSelected = 0;
        }
    }

    if (gTumbleweedBushInputEnabled != 0)
    {
        buttons = getButtonsJustPressed(0);
        acceptPressed = 0;
        if ((int)(buttons & 0x1100) != 0)
        {
            acceptPressed = 1;
        }
        if (acceptPressed)
        {
            if (((gTumbleweedBushItems[linkSelected].flags & LINK_FLAG_NO_ACCEPT) == 0) &&
                (GameBit_Get(0x44f) == 0))
            {
                buttonDisable(0, 0x1100);
                result = 1;
            }
        }
        else if ((int)(buttons & 0x200) != 0)
        {
            buttonDisable(0, 0x200);
            result = 0;
        }
    }

    if (gTumbleweedBushPulseDir != 0)
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
        gTumbleweedBushPulseDir = (s8)(*(s8*)&gTumbleweedBushPulseDir ^ 1);
    }
    else if (linkCount_803dd90e < 0)
    {
        linkCount_803dd90e = (s16) - linkCount_803dd90e;
        gTumbleweedBushPulseDir = (s8)(*(s8*)&gTumbleweedBushPulseDir ^ 1);
    }

    gTumbleweedBushInputEnabled = 1;
    linkDrawFn_801302c0();
    linkDrawFn_80130484();
    return result;
}
#pragma opt_propagation reset
#pragma peephole reset

/* ===== EN v1.0 retargeted leaves ========================================= */

/* EN v1.0 0x80131570  size: 12b  Read changed bit from item->flags. */

/* EN v1.0 0x8013157C  size: 20b  Set item->value and item->frameDelay = 2. */

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
    extern LinkMenuItem gTumbleweedBushItems[40]; /* #57 */
    extern s8 gTumbleweedBushItemCount; /* #57 */
    int i;
    LinkMenuItem* item;
    const char* defaultText;
    const char* errBase;

    errBase = sTumbleweedBushNavLinkRangeErr;
    defaultText = errBase;
    if (count <= 40)
    {
        gTumbleweedBushItemCount = count;
        linkCount_803dd90e = 0xff;
        linkSelected = selected;
        gTumbleweedBushPulseDir = 0;
        gTumbleweedBushInputEnabled = 0;

        memcpy(gTumbleweedBushItems, items, count * sizeof(LinkMenuItem));

        for (i = 0; i < count; i++)
        {
            item = &gTumbleweedBushItems[i];
            if ((item->upLink < -1) || (item->upLink >= count))
            {
                OSReport(errBase + 0xa4, item->upLink);
            }

            if ((item->downLink < -1) || (item->downLink >= count))
            {
                OSReport(errBase + 0xb8, item->downLink);
            }

            if ((item->leftLink < -1) || (item->leftLink >= count))
            {
                OSReport(errBase + 0xd0, item->leftLink);
            }

            if ((item->rightLink < -1) || (item->rightLink >= count))
            {
                OSReport(errBase + 0xe8, item->rightLink);
            }

            if (items[i].textureAssetId != -1)
            {
                item->texture = textureLoadAsset(items[i].textureAssetId);
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

            if ((item->leftLink != -1) && ((item->flags & LINK_FLAG_INHERIT_X) != 0))
            {
                LinkMenuItem* linked = &gTumbleweedBushItems[item->leftLink];
                item->x = linked->x + linked->field14;
                item->field04 = linked->field04 + linked->field14;
            }

            if ((item->flags & LINK_FLAG_CENTRE) != 0)
            {
                item->x -= item->field14 >> 1;
                item->field04 = item->x;
            }

            item->timer = 4;
        }

        gTumbleweedBushBaseColorR = baseRed;
        gTumbleweedBushBaseColorG = baseGreen;
        gTumbleweedBushBaseColorB = baseBlue;
        gTumbleweedBushSelColorR = selectedRed;
        gTumbleweedBushSelColorG = selectedGreen;
        gTumbleweedBushSelColorB = selectedBlue;
        if (defaultMessage != NULL)
        {
            defaultText = defaultMessage;
        }
        gTumbleweedBushDefaultText = defaultText;
    }
}
#pragma peephole reset

void Link_free(void)
{
    extern LinkMenuItem gTumbleweedBushItems[40]; /* #57 */
    extern s8 gTumbleweedBushItemCount; /* #57 */
    int i;

    for (i = 0; i < gTumbleweedBushItemCount; i++)
    {
        if (gTumbleweedBushItems[i].texture != NULL)
        {
            textureFree(gTumbleweedBushItems[i].texture);
        }
    }
    gTumbleweedBushItemCount = 0;
}

#pragma peephole off
void linkDrawFn_801302c0(void)
{
    extern s8 gTumbleweedBushItemCount; /* #57 */
    extern LinkMenuItemDB gTumbleweedBushItems[40];
    LinkMenuItemDB* sel;
    int four;
    void* tex;
    int i;
    int selLeft;
    int selRight;
    int itemLeft;
    int itemRight;
    int w;

    four = 4;
    gTumbleweedBushItems[linkSelected].field38 = four;
    sel = &gTumbleweedBushItems[linkSelected];
    if (((sel->flags & 4) != 0) && ((s8)sel->slots[0] != -1))
    {
        tex = *(void**)(linkTextures + sel->slots[0] * 8);
    }
    else
    {
        tex = sel->texture;
    }
    if (tex != NULL)
    {
        w = ((Texture*)tex)->height;
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
    for (i = 0; i < gTumbleweedBushItemCount; i++)
    {
        if (i != linkSelected)
        {
            if (((gTumbleweedBushItems[i].flags & 4) != 0) && ((s8)gTumbleweedBushItems[i].slots[0] != -1))
            {
                tex = *(void**)(linkTextures + gTumbleweedBushItems[i].slots[0] * 8);
            }
            else
            {
                tex = gTumbleweedBushItems[i].texture;
            }
            if (tex != NULL)
            {
                w = ((Texture*)tex)->height;
                itemLeft = gTumbleweedBushItems[i].field0C;
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
                itemLeft = gTumbleweedBushItems[i].field06 - 2;
            }
            itemRight = itemLeft + w;
            if (itemLeft < selRight && itemRight > selLeft)
            {
                gTumbleweedBushItems[i].field38 = four;
            }
        }
    }
}

void linkDrawFn_80130484(void)
{
    extern s8 gTumbleweedBushItemCount; /* #57 */
    extern LinkMenuItemDB gTumbleweedBushItems[40];
    LinkMenuItemDB* p;
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
    for (; i < gTumbleweedBushItemCount; i++)
    {
        p = &gTumbleweedBushItems[i];
        if (((p->flags & 4) != 0) && ((s8)p->slots[0] != -1))
        {
            tex = *(void**)(linkTextures + p->slots[0] * 8);
        }
        else
        {
            tex = p->texture;
        }
        if (tex != NULL)
        {
            w = ((Texture*)tex)->height;
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
    }
}
#pragma peephole reset
