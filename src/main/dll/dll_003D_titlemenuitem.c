/*
 * titlemenuitem (DLL 0x3D) - one entry of the title / options menu.
 *
 * A TitleMenuItem comes in three kinds (TitleMenuItem.kind):
 *   0 = slider (textId graphic dragged along a track by the stick),
 *   1 = on/off toggle (A button flips item->value, distinct on/off textures),
 *   2 = text window (a gameText phrase whose variant tracks item->value).
 * Per-item state lives in item->flags (TITLE_MENU_FLAG_*). _update reads the
 * pad each frame, moves item->value within [minValue, maxValue] (wrapping when
 * TITLE_MENU_FLAG_WRAP is set), plays the menu sfx, and previews the master
 * volume / music track for the audio options. _render draws the item's
 * textures / text. The six shared menu textures are cached in lbl_803A9DB8 and
 * loaded by id from lbl_8031C2A8; _initialise / _release manage that cache.
 *
 * Slider drag accumulator state (lbl_803DD918/91C/920) and the smoothing
 * constants (lbl_803E21F0/F4/F8) live in the front-menu DLL.
 */
#include "main/audio/sfx_ids.h"
#include "main/dll/titlemenuitem_struct.h"
#include "main/pad.h"
#include "main/texture.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_trigger_ids.h"

#define TITLE_MENU_FLAG_ENABLED        0x01
#define TITLE_MENU_FLAG_WRAP           0x02
#define TITLE_MENU_FLAG_MOVED_LEFT     0x04
#define TITLE_MENU_FLAG_MOVED_RIGHT    0x08
#define TITLE_MENU_FLAG_CHANGED        0x10
#define TITLE_MENU_FLAG_A_TOGGLE_PENDING       0x20
#define TITLE_MENU_FLAG_VOLUME_PREVIEW 0x40
#define TITLE_MENU_FLAG_MUSIC_PREVIEW  0x80

#define TITLE_MENU_KIND_SLIDER 0
#define TITLE_MENU_KIND_TOGGLE 1
#define TITLE_MENU_KIND_WINDOW 2

#define PAD_BUTTON_A 0x100

/* count of shared title-menu-item textures (and their asset-id table) */
#define TITLE_MENU_ITEM_TEXTURE_COUNT 6

extern u8 padGetStickX(int port);
extern s16 lbl_803DD918;
extern f32 lbl_803DD91C;
extern s8 lbl_803DD920;
extern f32 lbl_803E21F0;
extern f32 lbl_803E21F4;
extern f32 lbl_803E21F8;
extern void* lbl_803A9DB8[TITLE_MENU_ITEM_TEXTURE_COUNT];   /* cached menu textures */
extern s16 lbl_8031C2A8[TITLE_MENU_ITEM_TEXTURE_COUNT];     /* texture asset ids for the cache */



extern void Music_PlayTrackByIndex(int index);
extern void drawTexture(void* texture, f32 x, f32 y, u8 alpha, u16 scale);
extern void* gameTextGetPhrase(int textId, int phraseIndex);
extern void gameTextSetColor(int r, int g, int b, int a);
extern void gameTextSetWindowStrPos(int windowId, int x, int y);
extern void gameTextAppendStr(char* str, int arg2);
extern void mm_free(void);
extern void* mmAlloc(int size, int type, int flag);

int TitleMenuItem_isChanged(TitleMenuItem* item)
{
    return item->flags & TITLE_MENU_FLAG_CHANGED;
}

void TitleMenuItem_setVal(TitleMenuItem* item, int val)
{
    item->value = val;
    item->frameDelay = 2;
}

/* EN v1.0 0x80131590  size: 8b   Getter for item->value. */
s16 TitleMenuItem_getVal(TitleMenuItem* item)
{
    return item->value;
}

/* EN v1.0 0x80131598  size: 116b  Toggle enabled bit on item->flags. */
void TitleMenuItem_setEnabled(TitleMenuItem* item, int flag)
{
    if (flag != 0)
    {
        if ((item->flags & TITLE_MENU_FLAG_ENABLED) == 0)
        {
            lbl_803DD918 = 0;
            lbl_803DD91C = item->value;
        }
        item->flags = (u8)(item->flags | TITLE_MENU_FLAG_ENABLED);
    }
    else
    {
        item->flags = (u8)(item->flags & ~TITLE_MENU_FLAG_ENABLED);
    }
}

/* EN v1.0 0x8013160C  size: 12b  Read enabled bit from item->flags. */
int TitleMenuItem_isEnabled(TitleMenuItem* item)
{
    return item->flags & TITLE_MENU_FLAG_ENABLED;
}

/* EN v1.0 0x80131618  size: 808b  Render title menu item. */
void TitleMenuItem_render(TitleMenuItem* item, int unused, int alpha)
{
    void* texture;
    void* phrase;
    int textureIndex;
    int drawAlpha;
    f32 markerX;

    switch (item->kind)
    {
    case TITLE_MENU_KIND_SLIDER:
        drawTexture(lbl_803A9DB8[1], item->x, item->y,
                    (u8)(((u8)alpha * 0xb4) >> 8), 0x100);

        texture = lbl_803A9DB8[0];
        markerX = (f32)(int)((f32)item->extra.textId *
            ((f32)(item->value - item->minValue) /
                (f32)(item->maxValue - item->minValue)) +
            item->x - (f32)(*(u16*)((u8*)texture + 0xa) >> 1));
        drawTexture(texture, markerX, (f32)(item->y - 4),
                    (u8)(((u8)alpha * 0xff) >> 8), 0x100);
        break;
    case TITLE_MENU_KIND_TOGGLE:
        if ((item->flags & TITLE_MENU_FLAG_ENABLED) != 0)
        {
            if (item->value != 0)
            {
                textureIndex = 2;
            }
            else
            {
                textureIndex = 4;
            }
        }
        else if (item->value != 0)
        {
            textureIndex = 3;
        }
        else
        {
            textureIndex = 5;
        }

        if ((item->flags & TITLE_MENU_FLAG_A_TOGGLE_PENDING) != 0)
        {
            drawAlpha = (u8)alpha >> 1;
        }
        else
        {
            drawAlpha = (u8)alpha;
        }
        drawTexture(lbl_803A9DB8[textureIndex], item->x, item->y,
                    drawAlpha, 0x100);
        break;
    case TITLE_MENU_KIND_WINDOW:
        phrase = gameTextGetPhrase(item->extra.window.phraseId,
                                   (item->flags & TITLE_MENU_FLAG_MUSIC_PREVIEW) != 0 ? 0 : item->value);
        gameTextSetColor(0, 0, 0, (u8)(((u8)alpha * 0x96) >> 8));
        gameTextSetWindowStrPos(item->extra.window.windowId, 2, 2);
        gameTextAppendStr(phrase, item->extra.window.windowId);
        gameTextSetColor(0xff, 0xff, 0xff, alpha);
        gameTextSetWindowStrPos(item->extra.window.windowId, 0, 0);
        gameTextAppendStr(phrase, item->extra.window.windowId);
        break;
    }

    if (--item->frameDelay < 0)
    {
        item->frameDelay = 0;
    }
}

/* EN v1.0 0x80131940  size: 948b  Update title menu item input state. */
void TitleMenuItem_update(TitleMenuItem* item)
{
    s16 oldValue;
    s8 stickX;
    s16 move;
    s16 gatedMove;
    int sliderDelta;
    s16 previewVolume;

    if ((item->flags & TITLE_MENU_FLAG_ENABLED) == 0)
    {
        return;
    }

    item->flags = (u8)(item->flags & ~(TITLE_MENU_FLAG_MOVED_LEFT |
        TITLE_MENU_FLAG_MOVED_RIGHT |
        TITLE_MENU_FLAG_CHANGED));
    oldValue = item->value;
    item->frameDelay = 4;

    switch (item->kind)
    {
    case TITLE_MENU_KIND_WINDOW:
        stickX = padGetStickX(0);
        if (stickX > 0x23)
        {
            move = 1;
        }
        else if (stickX < -0x23)
        {
            move = -1;
        }
        else
        {
            move = 0;
        }

        gatedMove = move;
        if (lbl_803DD920 != 0)
        {
            gatedMove = 0;
        }
        lbl_803DD920 = move;

        if (gatedMove < 0)
        {
            Sfx_PlayFromObject(0, SFXsp_sa_def01);
            item->value--;
            item->flags = (u8)(item->flags | TITLE_MENU_FLAG_MOVED_LEFT);
        }
        else if (gatedMove > 0)
        {
            Sfx_PlayFromObject(0, SFXsp_sa_def01);
            item->value++;
            item->flags = (u8)(item->flags | TITLE_MENU_FLAG_MOVED_RIGHT);
        }
        break;
    case TITLE_MENU_KIND_SLIDER:
        stickX = padGetStickX(0);
        sliderDelta = (s16)(stickX / 16) * 0xa0;

        if (((s16)sliderDelta != 0) &&
            (!(lbl_803DD91C < item->minValue) || ((s16)sliderDelta >= 0)) &&
            (!(lbl_803DD91C > item->maxValue) || ((s16)sliderDelta <= 0)))
        {
            lbl_803DD918 = (s16)(lbl_803E21F0 * (f32)(s16)(sliderDelta - lbl_803DD918) +
                lbl_803DD918);
            Sfx_KeepAliveLoopedObjectSound(0, SFXTRIG_pda_compassbeep);
        }
        else
        {
            lbl_803DD918 = 0;
        }

        lbl_803DD91C += lbl_803DD918 / lbl_803E21F4;
        item->value = (s16)(lbl_803E21F8 + lbl_803DD91C);

        if ((item->flags & TITLE_MENU_FLAG_VOLUME_PREVIEW) != 0)
        {
            previewVolume = item->value;
            if ((previewVolume > 0x7f ? 0x7f : previewVolume) < 0)
            {
                previewVolume = 0;
            }
            else if (previewVolume > 0x7f)
            {
                previewVolume = 0x7f;
            }
            Sfx_SetObjectSfxVolume(0, SFXTRIG_pda_compassbeep, previewVolume, lbl_803E21F8);
        }
        break;
    default:
        if (((item->flags & TITLE_MENU_FLAG_A_TOGGLE_PENDING) == 0) &&
            ((getButtonsJustPressed(0) & PAD_BUTTON_A) != 0))
        {
            Sfx_PlayFromObject(0, SFXsp_sa_def02);
            item->value = (s16)(item->value ^ 1);
        }
        break;
    }

    if (item->value > item->maxValue)
    {
        if ((item->flags & TITLE_MENU_FLAG_WRAP) != 0)
        {
            item->value = 0;
        }
        else
        {
            item->value = item->maxValue;
        }
    }
    else if (item->value < item->minValue)
    {
        if ((item->flags & TITLE_MENU_FLAG_WRAP) != 0)
        {
            item->value = item->maxValue;
        }
        else
        {
            item->value = item->minValue;
        }
    }

    if (oldValue != item->value)
    {
        item->flags = (u8)(item->flags | TITLE_MENU_FLAG_CHANGED);
    }

    if (((item->flags & TITLE_MENU_FLAG_MUSIC_PREVIEW) != 0) &&
        ((item->flags & TITLE_MENU_FLAG_CHANGED) != 0))
    {
        Music_PlayTrackByIndex(item->value);
    }
}

void TitleMenuItem_setAButtonToggle(TitleMenuItem* item, int flag)
{
    if (flag != 0)
    {
        item->flags = (u8)(item->flags & ~TITLE_MENU_FLAG_A_TOGGLE_PENDING);
    }
    else
    {
        item->flags = (u8)(item->flags | TITLE_MENU_FLAG_A_TOGGLE_PENDING);
    }
}

/* EN v1.0 0x80131CF4  size: 32b  Wrapper for mm_free. */
void TitleMenuItem_free(void)
{
    mm_free();
}

/* EN v1.0 0x80131FE0  size: 40b  Zero 6 u32s at lbl_803A9DB8. */
void TitleMenuItem_initialise(void)
{
    void** slots = lbl_803A9DB8;
    slots[0] = NULL;
    slots[1] = NULL;
    slots[2] = NULL;
    slots[3] = NULL;
    slots[4] = NULL;
    slots[5] = NULL;
}

/* EN v1.0 0x80131D14  size: 168b  Create text-window title menu item. */
TitleMenuItem* TitleMenuItem_createWithWindow(int phraseId, int windowId, s16 minValue,
                                              s16 maxValue, s16 value)
{
    TitleMenuItem* item;

    if (value < minValue)
    {
        value = minValue;
    }
    if (value > maxValue)
    {
        value = maxValue;
    }

    item = (TitleMenuItem*)mmAlloc(0x12, 5, 0);
    item->kind = TITLE_MENU_KIND_WINDOW;
    item->extra.window.phraseId = phraseId;
    item->extra.window.windowId = windowId;
    item->value = value;
    item->minValue = minValue;
    item->maxValue = maxValue;
    item->flags = TITLE_MENU_FLAG_WRAP;
    item->frameDelay = 4;
    return item;
}

/* EN v1.0 0x80131DBC  size: 164b  Create simple title menu item. */
TitleMenuItem* TitleMenuItem_create(s16 x, s16 y, s16 minValue, s16 maxValue, s16 value)
{
    TitleMenuItem* item;

    if (value < minValue)
    {
        value = minValue;
    }
    if (value > maxValue)
    {
        value = maxValue;
    }

    item = (TitleMenuItem*)mmAlloc(0xe, 5, 0);
    item->kind = TITLE_MENU_KIND_TOGGLE;
    item->value = value;
    item->minValue = minValue;
    item->maxValue = maxValue;
    item->x = x;
    item->y = y;
    item->flags = 0;
    item->frameDelay = 4;
    return item;
}

/* EN v1.0 0x80131E60  size: 172b  Create text-backed title menu item. */
TitleMenuItem* TitleMenuItem_createWithText(s16 x, s16 y, s16 minValue, s16 maxValue,
                                            s16 value, int textId)
{
    TitleMenuItem* item;

    if (value < minValue)
    {
        value = minValue;
    }
    if (value > maxValue)
    {
        value = maxValue;
    }

    item = (TitleMenuItem*)mmAlloc(0x10, 5, 0);
    item->kind = TITLE_MENU_KIND_SLIDER;
    item->value = value;
    item->minValue = minValue;
    item->maxValue = maxValue;
    item->x = x;
    item->y = y;
    item->flags = 0;
    item->frameDelay = 4;
    item->extra.textId = textId;
    return item;
}

void fn_80131F0C(void)
{
    int i;

    for (i = 0; i < TITLE_MENU_ITEM_TEXTURE_COUNT; i++)
    {
        if (lbl_803A9DB8[i] == NULL)
        {
            lbl_803A9DB8[i] = textureLoadAsset(lbl_8031C2A8[i]);
        }
    }
}

void TitleMenuItem_release(void)
{
    int i;

    for (i = 0; i < TITLE_MENU_ITEM_TEXTURE_COUNT; i++)
    {
        textureFree(lbl_803A9DB8[i]);
        lbl_803A9DB8[i] = NULL;
    }
}
