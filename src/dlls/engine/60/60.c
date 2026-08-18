#include "dlls/object_descriptor.h"
#include "dolphin/os/OSReport.h"
#include "main/dll/dll_003C_link.h"
#include "string.h"
#include "track/intersect_hud_api.h"
#include "main/gametext_box_api.h"
#include "main/gametext_command_api.h"
#include "main/dll/dll_003C_link_api.h"
#include "main/gametext_show_api.h"
#include "main/gametext_show_str_api.h"
#include "main/hud_visibility_api.h"
#include "main/texture.h"
#include "main/gamebits.h"
#include "main/pad.h"
#include "main/textrender_api.h"
#include "main/frame_timing.h"
#include "main/dll/dll_0035_saveselectscreen.h"
#include "main/dll/FRONT/title_menu.h"
#include "main/gametext_color_api.h"
#include "main/gametext_internal.h"
#include "main/vecmath.h"
#include "dolphin/pad.h"

#define LINK_ITEM_SLOTS 25

typedef struct LinkTextureSlot
{
    void* texture;
    s16 assetId;
    u8 width;
} LinkTextureSlot;

extern LinkTextureSlot linkTextures[6];
s8 gLinkInputEnabled;
s8 linkSelected;
s8 gLinkItemCount;
s8 gLinkPulseDir;
s16 gLinkPulse;
s16 linkItemOpacity;
const char* gLinkDefaultText;
s16 gLinkBaseColorR;
s16 gLinkBaseColorG;
s16 gLinkBaseColorB;
s16 gLinkSelColorR;
s16 gLinkSelColorG;
s16 gLinkSelColorB;
u8 linkIsRotated;
u8 gLinkNavigationEnabled;
extern char sLinkSlotOverflowErr[];
extern char sLinkNavLinkRangeErr[];

#define PAD_ACCEPT_MASK  (PAD_BUTTON_A | PAD_BUTTON_START)


typedef struct LinkMenuItem
{
    u16 textId;
    u16 boxId;
    s16 rightX;
    s16 textTop;
    s16 slotWidth;
    s16 x;
    s16 y;
    u8 pad0E[2];

    union
    {
        int textureAssetId;
        void* texture;
    };

    u16 width;
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
STATIC_ASSERT(sizeof(LinkMenuItem) == 0x3C);
STATIC_ASSERT(offsetof(LinkMenuItem, rightX) == 0x04);
STATIC_ASSERT(offsetof(LinkMenuItem, x) == 0x0A);
STATIC_ASSERT(offsetof(LinkMenuItem, y) == 0x0C);
STATIC_ASSERT(offsetof(LinkMenuItem, textureAssetId) == 0x10);
STATIC_ASSERT(offsetof(LinkMenuItem, flags) == 0x16);
STATIC_ASSERT(offsetof(LinkMenuItem, upLink) == 0x1A);
#define LINK_FLAG_DRAW_SLOTS        0x0004

extern LinkMenuItem gLinkMenuItems[40];

void linkInitTextures(LinkMenuItem* item);
void Link_resetTimers(void);
void Link_copy(u8* srcArg);
u8 Link_getPulse(void);
void Link_updateItems(u8* srcArg);
void Link_setItemState(int idx, int v);
s32 Link_getItemState(int idx);
void Link_setOpacity(u8 v);
void Link_setSelected(int v);
s32 Link_getSelected(void);
void Link_render(void);
void Link_free(void);
void Link_setup(LinkMenuItem* items, int count, int selected, const char* defaultMessage, int unused1, int unused2,
                int baseRed, int baseGreen, int baseBlue, int selectedRed, int selectedGreen, int selectedBlue);
void Link_release(void);
void Link_initialise(void);

u16 linkGetSelectedItemId(void)
{
    return gLinkMenuItems[linkSelected].boxId;
}
void linkInitTextures(LinkMenuItem* item)
{
    int budget;
    int i;

    budget = item->width;
    for (i = 0; i < LINK_ITEM_SLOTS; i++)
    {
        item->slots[i] = -1;
    }
    item->slots[(i = 1) - 1] = 0;
    budget -= linkTextures[0].width + linkTextures[1].width;
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
        budget -= linkTextures[item->slots[i]].width;
        i++;
    }
    item->slots[i++] = 1;
    if (i >= LINK_ITEM_SLOTS)
    {
        OSReport(sLinkSlotOverflowErr);
    }
}
void Link_refreshOverlappingItemTimers(void)
{
    LinkMenuItem* sel;
    int resetTimer;
    Texture* iconTex;
    int i;
    int selTop;
    int selBottom;
    int itemTop;
    int itemBottom;
    int iconHeight;

    resetTimer = 4;
    gLinkMenuItems[linkSelected].timer = resetTimer;
    sel = &gLinkMenuItems[linkSelected];
    if (((sel->flags & LINK_FLAG_DRAW_SLOTS) != 0) && (sel->slots[0] != -1))
    {
        iconTex = (Texture*)linkTextures[sel->slots[0]].texture;
    }
    else
    {
        iconTex = (Texture*)(sel->texture);
    }
    if (iconTex != NULL)
    {
        iconHeight = iconTex->height;
        selTop = sel->y;
    }
    else
    {
        if (getCurLanguage() == 4)
        {
            iconHeight = gGameTextFontMetrics[0].lineHeight + 2;
        }
        else
        {
            iconHeight = gGameTextFontMetrics[4].lineHeight + 2;
        }
        selTop = sel->textTop - 2;
    }
    selBottom = selTop + iconHeight;
    for (i = 0; i < gLinkItemCount; i++)
    {
        if (i != linkSelected)
        {
            if (((gLinkMenuItems[i].flags & LINK_FLAG_DRAW_SLOTS) != 0) &&
                (gLinkMenuItems[i].slots[0] != -1))
            {
                iconTex = (Texture*)linkTextures[gLinkMenuItems[i].slots[0]].texture;
            }
            else
            {
                iconTex = (Texture*)(gLinkMenuItems[i].texture);
            }
            if (iconTex != NULL)
            {
                iconHeight = iconTex->height;
                itemTop = gLinkMenuItems[i].y;
            }
            else
            {
                if (getCurLanguage() == 4)
                {
                    iconHeight = gGameTextFontMetrics[0].lineHeight + 2;
                }
                else
                {
                    iconHeight = gGameTextFontMetrics[4].lineHeight + 2;
                }
                itemTop = gLinkMenuItems[i].textTop - 2;
            }
            itemBottom = itemTop + iconHeight;
            if (itemTop < selBottom && itemBottom > selTop)
            {
                gLinkMenuItems[i].timer = resetTimer;
            }
        }
    }
}

void Link_setNavigationEnabled(u8 v)
{
    gLinkNavigationEnabled = v;
}
void setLinkNotRotated(void)
{
    linkIsRotated = 0;
}
void setLinkIsRotated(void)
{
    linkIsRotated = 1;
}

void Link_scanItemVerticalBounds(void)
{
    LinkMenuItem* item;
    Texture* iconTex;
    int i;
    int minY;
    int maxY;
    int iconHeight;
    int top;
    int bottom;

    minY = 480;
    maxY = 0;
    i = 0;
    for (; i < gLinkItemCount; i++)
    {
        item = &gLinkMenuItems[i];
        if (((item->flags & LINK_FLAG_DRAW_SLOTS) != 0) && (item->slots[0] != -1))
        {
            iconTex = (Texture*)linkTextures[item->slots[0]].texture;
        }
        else
        {
            iconTex = (Texture*)(item->texture);
        }
        if (iconTex != NULL)
        {
            iconHeight = iconTex->height;
            top = item->y;
        }
        else
        {
            if (getCurLanguage() == 4)
            {
                iconHeight = gGameTextFontMetrics[0].lineHeight + 2;
            }
            else
            {
                iconHeight = gGameTextFontMetrics[4].lineHeight + 2;
            }
            top = item->textTop - 2;
        }
        bottom = top + iconHeight;
        if (top < minY)
        {
            minY = top;
        }
        if (bottom > maxY)
        {
            maxY = bottom;
        }
    }
}
void Link_resetTimers(void)
{
    int i;

    for (i = 0; i < gLinkItemCount; i++)
    {
        gLinkMenuItems[i].timer = 4;
    }
}
void Link_copy(u8* srcArg)
{
    LinkMenuItem* dst;
    LinkMenuItem* src;
    int i;

    i = 0;
    for (; i < gLinkItemCount; i++)
    {
        dst = &gLinkMenuItems[i];
        src = &((LinkMenuItem*)srcArg)[i];
        dst->flags = src->flags;
        dst->upLink = src->upLink;
        dst->rightX = src->rightX;
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
                textureFree((Texture*)(dst->texture));
            }
            dst->texture = NULL;
        }
    }
}

u8 Link_getPulse(void)
{
    return gLinkPulse;
}
void Link_updateItems(u8* srcArg)
{
    LinkMenuItem* src;
    int i;

    src = (LinkMenuItem*)srcArg;
    for (i = 0; i < gLinkItemCount; i++)
    {
        gLinkMenuItems[i].textId = src[i].textId;
        gLinkMenuItems[i].boxId = src[i].boxId;
        gLinkMenuItems[i].timer = 2;
    }
}
void Link_setItemState(int idx, int v)
{
    gLinkMenuItems[idx].state = v;
}

s32 Link_getItemState(int idx)
{
    return gLinkMenuItems[idx].state;
}
void Link_setOpacity(u8 v)
{
    linkItemOpacity = v;
}

#define LINK_FLAG_DRAW_BLACK_SHADOW 0x0100
#define LINK_FLAG_DIM_OPACITY       0x0800
#define LINK_FLAG_FADE_TIMER_ONLY   0x1040
#define LINK_FLAG_HIDDEN            0x4000
#define LINK_FLAG_SELECTED_COLOR    0x0080

void Link_setSelected(int v)
{
    linkSelected = v;
}

#define LINK_FLAG_DISABLE_NAV_TO 0x1000
#define LINK_FLAG_NO_ACCEPT      0x0020
#define LINK_FLAG_INHERIT_X      0x0008
#define LINK_FLAG_NO_SLOTS       0x0010
#define LINK_FLAG_CENTRE         0x0400
#define LINK_IS_NAVIGABLE(index) ((gLinkMenuItems[(index)].flags & LINK_FLAG_DISABLE_NAV_TO) == 0)

s32 Link_getSelected(void)
{
    return linkSelected;
}

void Link_render(void)
{
    LinkMenuItem* item;
    int i;
    int slotIndex;
    LinkMenuItem* drawItem;
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

    for (i = 0; i < gLinkItemCount; i++)
    {
        item = (LinkMenuItem*)&gLinkMenuItems[i];
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
                    drawItem = (LinkMenuItem*)&gLinkMenuItems[item->state];
                }

                if ((drawItem->flags & LINK_FLAG_DRAW_SLOTS) != 0)
                {
                    slotIndex = 0;
                    x = drawItem->x;
                    y = drawItem->y;
                    while (drawItem->slots[slotIndex] != -1 && slotIndex < LINK_ITEM_SLOTS)
                    {
                        textureIndex = drawItem->slots[slotIndex];
                        drawTexture(linkTextures[textureIndex].texture, x, y, 0xff, 0x100);
                        x += linkTextures[drawItem->slots[slotIndex]].width;
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

                gameTextSetWindowById(drawItem->boxId);
                if (linkSelected == i)
                {
                    alpha = opacity;
                }
                else
                {
                    alpha = (((int)((u32)opacity >> 31)) + opacity) >> 1;
                }
                ((TextSlot*)gameTextGetBox(drawItem->boxId))->alpha = alpha;

                if ((drawItem->flags & LINK_FLAG_DRAW_BLACK_SHADOW) != 0)
                {
                    gameTextSetColor(0, 0, 0, (u8)(((gLinkPulse + 1) * linkItemOpacity) >> 8));
                    gameTextShowAt(drawItem->textId, 2, 2);
                }

                if ((drawItem->flags & LINK_FLAG_SELECTED_COLOR) != 0)
                {
                    if (linkSelected == i)
                    {
                        red = gLinkBaseColorR +
                              ((gLinkPulse * (gLinkSelColorR - gLinkBaseColorR)) >> 8);
                        green = gLinkBaseColorG +
                                ((gLinkPulse * (gLinkSelColorG - gLinkBaseColorG)) >> 8);
                        blue = gLinkBaseColorB +
                               ((gLinkPulse * (gLinkSelColorB - gLinkBaseColorB)) >> 8);
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
                        gameTextSetColor((u8)gLinkBaseColorR, (u8)gLinkBaseColorG,
                                         (u8)gLinkBaseColorB,
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
                    gameTextShowStr(saveFileSelect_saveSlots[textId].name, drawItem->boxId, 0, 0);
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
                        drawTexture(drawItem->texture, (f32)(drawItem->x + 11), drawItem->y, alpha & 0xff, 0x100);
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
                        drawTexture(drawItem->texture, drawItem->x, drawItem->y, alpha & 0xff, 0x100);
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

    gameTextSetWindowById(0xff);
}

u32 Link_update(void)
{
    int result;
    LinkMenuItem* item;
    u32 buttons;
    u8 acceptPressed;
    s8 horizontalInput;
    s8 verticalInput;

    item = &gLinkMenuItems[linkSelected];
    if (gLinkItemCount == 0)
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
        verticalInput = (s8)-oldHorizontal;
    }

    if (verticalInput != 0)
    {
        horizontalInput = 0;
    }

    if (((horizontalInput != 0) || (verticalInput != 0)) && (gLinkNavigationEnabled != 0))
    {
        if ((verticalInput < 0) && (item->downLink != -1) && LINK_IS_NAVIGABLE(item->downLink))
        {
            padClearAnalogInputY(0);
            linkSelected = item->downLink;
            gLinkPulse = 0xff;
        }
        else if ((verticalInput > 0) && (item->upLink != -1) && LINK_IS_NAVIGABLE(item->upLink))
        {
            padClearAnalogInputY(0);
            linkSelected = item->upLink;
            gLinkPulse = 0xff;
        }

        if (item->state != -1)
        {
            item = &gLinkMenuItems[item->state];
            if ((horizontalInput < 0) && (item->leftLink != -1))
            {
                padClearAnalogInputX(0);
                gLinkMenuItems[linkSelected].state = item->leftLink;
                gLinkPulse = 0xff;
            }
            else if ((horizontalInput > 0) && (item->rightLink != -1))
            {
                padClearAnalogInputX(0);
                gLinkMenuItems[linkSelected].state = item->rightLink;
                gLinkPulse = 0xff;
            }
        }
        else
        {
            if ((horizontalInput < 0) && (item->leftLink != -1) && LINK_IS_NAVIGABLE(item->leftLink))
            {
                padClearAnalogInputX(0);
                linkSelected = item->leftLink;
                gLinkPulse = 0xff;
            }
            else if ((horizontalInput > 0) && (item->rightLink != -1) && LINK_IS_NAVIGABLE(item->rightLink))
            {
                padClearAnalogInputX(0);
                linkSelected = item->rightLink;
                gLinkPulse = 0xff;
            }
        }

        if (linkSelected < 0)
        {
            linkSelected = (s8)(gLinkItemCount - 1);
        }
        if (linkSelected >= gLinkItemCount)
        {
            linkSelected = 0;
        }
    }

    if (gLinkInputEnabled != 0)
    {
        buttons = getButtonsJustPressed(0);
        acceptPressed = 0;
        if ((int)(buttons & PAD_ACCEPT_MASK) != 0)
        {
            acceptPressed = 1;
        }
        if (acceptPressed)
        {
            if (((gLinkMenuItems[linkSelected].flags & LINK_FLAG_NO_ACCEPT) == 0) &&
                (mainGetBit(GAMEBIT_MenuRelated044F) == 0))
            {
                buttonDisable(0, PAD_ACCEPT_MASK);
                result = 1;
            }
        }
        else if ((int)(buttons & PAD_BUTTON_B) != 0)
        {
            buttonDisable(0, PAD_BUTTON_B);
            result = 0;
        }
    }

    if (gLinkPulseDir != 0)
    {
        gLinkPulse = (s16)(gLinkPulse + framesThisStep * 5);
    }
    else
    {
        gLinkPulse = (s16)(gLinkPulse - framesThisStep * 5);
    }

    if (gLinkPulse > 0xff)
    {
        gLinkPulse = (s16)(0xff - (gLinkPulse - 0xff));
        gLinkPulseDir = (s8)(*(s8*)&gLinkPulseDir ^ 1);
    }
    else if (gLinkPulse < 0)
    {
        gLinkPulse = (s16)-gLinkPulse;
        gLinkPulseDir = (s8)(*(s8*)&gLinkPulseDir ^ 1);
    }

    gLinkInputEnabled = 1;
    Link_refreshOverlappingItemTimers();
    Link_scanItemVerticalBounds();
    return result;
}


void Link_free(void)
{
    int i;

    for (i = 0; i < gLinkItemCount; i++)
    {
        if (gLinkMenuItems[i].texture != NULL)
        {
            textureFree((Texture*)(gLinkMenuItems[i].texture));
        }
    }
    gLinkItemCount = 0;
}
void Link_setup(LinkMenuItem* items, int count, int selected, const char* defaultMessage, int unused1, int unused2,
                int baseRed, int baseGreen, int baseBlue, int selectedRed, int selectedGreen, int selectedBlue)
{
    int i;
    LinkMenuItem* item;
    const char* defaultText;
    const char* errBase;

    errBase = sLinkNavLinkRangeErr;
    defaultText = errBase;
    if (count <= 40)
    {
        gLinkItemCount = count;
        gLinkPulse = 0xff;
        linkSelected = selected;
        gLinkPulseDir = 0;
        gLinkInputEnabled = 0;

        memcpy(gLinkMenuItems, items, count * sizeof(LinkMenuItem));

        for (i = 0; i < count; i++)
        {
            item = &gLinkMenuItems[i];
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
                item->width = 0;
                item->slotWidth = 0;
            }

            if ((item->flags & LINK_FLAG_DRAW_SLOTS) != 0)
            {
                linkInitTextures(item);
            }

            if ((item->leftLink != -1) && ((item->flags & LINK_FLAG_INHERIT_X) != 0))
            {
                LinkMenuItem* linked = &gLinkMenuItems[item->leftLink];
                item->x = linked->x + linked->width;
                item->rightX = linked->rightX + linked->width;
            }

            if ((item->flags & LINK_FLAG_CENTRE) != 0)
            {
                item->x -= item->width >> 1;
                item->rightX = item->x;
            }

            item->timer = 4;
        }

        gLinkBaseColorR = baseRed;
        gLinkBaseColorG = baseGreen;
        gLinkBaseColorB = baseBlue;
        gLinkSelColorR = selectedRed;
        gLinkSelColorG = selectedGreen;
        gLinkSelColorB = selectedBlue;
        if (defaultMessage != NULL)
        {
            defaultText = defaultMessage;
        }
        gLinkDefaultText = defaultText;
    }
}

void Link_release(void)
{
    int i;

    for (i = 0; i < 6; i++)
    {
        textureFree((Texture*)(linkTextures[i].texture));
    }
    subtitleFreeBoxTextures(3);
}
void Link_initialise(void)
{
    int i;

    for (i = 0; i < 6; i++)
    {
        linkTextures[i].texture = textureLoadAsset(linkTextures[i].assetId);
    }

    padSetStickRepeatDelay(10);
    linkItemOpacity = 0xff;
    subtitleLoadBoxTextures(3);
    linkIsRotated = 0;
    gLinkNavigationEnabled = 1;
}

LinkMenuItem gLinkMenuItems[40];

char sLinkNavLinkRangeErr[] = {
    0x00, 0x00, 0x00, 0xF9, 0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x03, 0x71,
};

LinkTextureSlot linkTextures[6] = {
    {NULL, 0x314, 0x28}, {NULL, 0x315, 0x28}, {NULL, 0x317, 0x50},
    {NULL, 0x319, 0x50}, {NULL, 0x318, 0x28}, {NULL, 0x31A, 0x14},
};

struct LinkObjDescriptor
{
    u32 reserved0;
    u32 reserved1;
    u32 reserved2;
    u32 slotCountAndFlags;
    void* initialise;
    void* release;
    void* slot02;
    void* setup;
    void* free;
    void* update;
    void* render;
    void* getSelected;
    void* setSelected;
    void* getItemState;
    void* setItemState;
    void* updateItems;
    void* getPulse;
    void* copy;
    void* setOpacity;
    void* resetTimers;
};

struct LinkObjDescriptor Link_funcs = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_16_SLOTS,
    Link_initialise,
    Link_release,
    NULL,
    Link_setup,
    Link_free,
    Link_update,
    Link_render,
    Link_getSelected,
    Link_setSelected,
    Link_getItemState,
    Link_setItemState,
    Link_updateItems,
    Link_getPulse,
    Link_copy,
    Link_setOpacity,
    Link_resetTimers,
};

char sLinkSlotOverflowErr[] = {
    0x50, 0x49, 0x43, 0x4D, 0x45, 0x4E, 0x55, 0x3A, 0x20, 0x74, 0x65, 0x78, 0x20, 0x6F, 0x76, 0x65, 0x72,
    0x66, 0x6C, 0x6F, 0x77, 0x0A, 0x00, 0x00, 0x55, 0x50, 0x4C, 0x49, 0x4E, 0x4B, 0x20, 0x6F, 0x76, 0x65,
    0x72, 0x66, 0x6C, 0x6F, 0x77, 0x3D, 0x25, 0x64, 0x0A, 0x00, 0x44, 0x4F, 0x57, 0x4E, 0x4C, 0x49, 0x4E,
    0x4B, 0x20, 0x6F, 0x76, 0x65, 0x72, 0x66, 0x6C, 0x6F, 0x77, 0x3D, 0x25, 0x64, 0x0A, 0x00, 0x00, 0x00,
    0x4C, 0x45, 0x46, 0x54, 0x4C, 0x49, 0x4E, 0x4B, 0x20, 0x6F, 0x76, 0x65, 0x72, 0x66, 0x6C, 0x6F, 0x77,
    0x3D, 0x25, 0x64, 0x0A, 0x00, 0x00, 0x00, 0x52, 0x49, 0x47, 0x48, 0x54, 0x4C, 0x49, 0x4E, 0x4B, 0x20,
    0x6F, 0x76, 0x65, 0x72, 0x66, 0x6C, 0x6F, 0x77, 0x3D, 0x25, 0x64, 0x0A, 0x00, 0x00,
};

