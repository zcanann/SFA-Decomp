#include "main/audio/sfx_ids.h"
#include "main/dll/titlemenuitem_struct.h"
#include "main/dll/baddie/dll_003C_TumbleweedBush.h"

#define TITLE_MENU_FLAG_ENABLED        0x01
#define TITLE_MENU_FLAG_WRAP           0x02
#define TITLE_MENU_FLAG_MOVED_LEFT     0x04
#define TITLE_MENU_FLAG_MOVED_RIGHT    0x08
#define TITLE_MENU_FLAG_CHANGED        0x10
#define TITLE_MENU_FLAG_A_TOGGLE       0x20
#define TITLE_MENU_FLAG_VOLUME_PREVIEW 0x40
#define TITLE_MENU_FLAG_MUSIC_PREVIEW  0x80

extern u32 getButtonsJustPressed(int pad);

/* ===== EN v1.0 retargeted leaves ========================================= */

/* EN v1.0 0x80131570  size: 12b  Read changed bit from item->flags. */
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
extern void drawTexture(void* texture, u8 alpha, f32 x, f32 y, u16 scale);
extern void* gameTextGetPhrase(int textId, int variant);
extern void gameTextSetColor(int r, int g, int b, int a);
extern void gameTextSetWindowStrPos(int windowId, int x, int y);
extern void gameTextAppendStr(void* str, int windowId);
extern s16 lbl_8031C2A8[6];
extern void mm_free(void);
extern void* textureLoadAsset(int id);
extern void textureFree(void* p);
extern void* mmAlloc(int size, int heap, int flags);

int TitleMenuItem_isChanged(TitleMenuItem* item)
{
    return item->flags & TITLE_MENU_FLAG_CHANGED;
}

/* EN v1.0 0x8013157C  size: 20b  Set item->value and item->frameDelay = 2.
 * Logic-only ? target has `extsh r0,r4; sth r0,0xc(r3)` but MWCC -O4
 * strips the redundant extsh before sth (same family as GameUI_func0F /
 * CMenu_SetShouldClose). */
void TitleMenuItem_setVal(TitleMenuItem* item, int val)
{
    item->value = (s16)val;
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
            lbl_803DD91C = (f32)item->value;
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
    case 0:
        drawTexture(lbl_803A9DB8[1], (u8)(((u8)alpha * 0xb4) >> 8),
                    (f32)item->x, (f32)item->y, 0x100);

        texture = lbl_803A9DB8[0];
        markerX = (f32)(int)((f32)item->extra.textId *
            ((f32)(item->value - item->minValue) /
                (f32)(item->maxValue - item->minValue)) +
            (f32)item->x - (f32)(*(u16*)((u8*)texture + 0xa) >> 1));
        drawTexture(texture, (u8)(((u8)alpha * 0xff) >> 8),
                    markerX, (f32)(item->y - 4), 0x100);
        break;
    case 1:
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

        drawAlpha = (u8)alpha;
        if ((item->flags & TITLE_MENU_FLAG_A_TOGGLE) != 0)
        {
            drawAlpha >>= 1;
        }
        drawTexture(lbl_803A9DB8[textureIndex], (u8)drawAlpha,
                    (f32)item->x, (f32)item->y, 0x100);
        break;
    case 2:
        if ((item->flags & TITLE_MENU_FLAG_MUSIC_PREVIEW) != 0)
        {
            phrase = gameTextGetPhrase(item->extra.window.phraseId, 0);
        }
        else
        {
            phrase = gameTextGetPhrase(item->extra.window.phraseId, item->value);
        }
        gameTextSetColor(0, 0, 0, (u8)((alpha * 0x96) >> 8));
        gameTextSetWindowStrPos(item->extra.window.windowId, 2, 2);
        gameTextAppendStr(phrase, item->extra.window.windowId);
        gameTextSetColor(0xff, 0xff, 0xff, alpha);
        gameTextSetWindowStrPos(item->extra.window.windowId, 0, 0);
        gameTextAppendStr(phrase, item->extra.window.windowId);
        break;
    }

    item->frameDelay--;
    if (item->frameDelay < 0)
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
    s16 sliderDelta;
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
    case 2:
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
        lbl_803DD920 = (s8)move;

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
    case 0:
        stickX = padGetStickX(0);
        sliderDelta = (s16)((s8)stickX / 16) * 0xa0;

        if ((sliderDelta == 0) ||
            ((lbl_803DD91C < (f32)item->minValue) && (sliderDelta < 0)) ||
            (((f32)item->maxValue < lbl_803DD91C) && (sliderDelta > 0)))
        {
            lbl_803DD918 = 0;
        }
        else
        {
            lbl_803DD918 = (s16)(lbl_803E21F0 * (f32)(s16)(sliderDelta - lbl_803DD918) +
                (f32)lbl_803DD918);
            Sfx_KeepAliveLoopedObjectSound(0, 0x3b9);
        }

        lbl_803DD91C += (f32)lbl_803DD918 / lbl_803E21F4;
        item->value = (s16)(lbl_803E21F8 + lbl_803DD91C);

        if ((item->flags & TITLE_MENU_FLAG_VOLUME_PREVIEW) != 0)
        {
            previewVolume = item->value;
            if (previewVolume > 0x7f)
            {
                previewVolume = 0x7f;
            }
            if (previewVolume < 0)
            {
                previewVolume = 0;
            }
            else if (previewVolume > 0x7f)
            {
                previewVolume = 0x7f;
            }
            Sfx_SetObjectSfxVolume(0, 0x3b9, (u8)previewVolume, lbl_803E21F8);
        }
        break;
    default:
        if (((item->flags & TITLE_MENU_FLAG_A_TOGGLE) == 0) &&
            ((getButtonsJustPressed(0) & 0x100) != 0))
        {
            Sfx_PlayFromObject(0, SFXsp_sa_def02);
            item->value = (s16)(item->value ^ 1);
        }
        break;
    }

    if (item->value > item->maxValue)
    {
        if ((item->flags & TITLE_MENU_FLAG_WRAP) == 0)
        {
            item->value = item->maxValue;
        }
        else
        {
            item->value = 0;
        }
    }
    else if (item->value < item->minValue)
    {
        if ((item->flags & TITLE_MENU_FLAG_WRAP) == 0)
        {
            item->value = item->minValue;
        }
        else
        {
            item->value = item->maxValue;
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

/* EN v1.0 0x80132008  size: 8b   Trivial 1-returner. */
int Dummy3E_func05_ret_1(void);

/* EN v1.0 0x80132010  size: 4b   Empty no-op. */

/* EN v1.0 0x80132014  size: 8b   Trivial 0-returner. */

/* EN v1.0 0x8013201C  size: 4b   Empty no-op. */

/* EN v1.0 0x80132020  size: 4b   Empty no-op. */

/* EN v1.0 0x80131540  size: 48b  Toggle A-button bit of item->flags. */
void TitleMenuItem_setAButtonToggle(TitleMenuItem* item, int flag)
{
    if (flag != 0)
    {
        item->flags = (u8)(item->flags & ~TITLE_MENU_FLAG_A_TOGGLE);
    }
    else
    {
        item->flags = (u8)(item->flags | TITLE_MENU_FLAG_A_TOGGLE);
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
    slots[0] = 0;
    slots[1] = 0;
    slots[2] = 0;
    slots[3] = 0;
    slots[4] = 0;
    slots[5] = 0;
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
    item->kind = 2;
    item->extra.window.phraseId = phraseId;
    item->extra.window.windowId = windowId;
    item->value = value;
    item->minValue = minValue;
    item->maxValue = maxValue;
    item->flags = 2;
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
    item->kind = 1;
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
    item->kind = 0;
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

    for (i = 0; i < 6; i++)
    {
        if (lbl_803A9DB8[i] == NULL)
        {
            lbl_803A9DB8[i] = textureLoadAsset(lbl_8031C2A8[i]);
        }
    }
}

void Link_release(void);

void TitleMenuItem_release(void)
{
    int i;

    for (i = 0; i < 6; i++)
    {
        textureFree(lbl_803A9DB8[i]);
        lbl_803A9DB8[i] = NULL;
    }
}

void Link_free(void);
