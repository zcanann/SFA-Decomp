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
extern undefined8 FUN_80130434();
extern undefined4 FUN_80130588();
extern undefined4 FUN_8013074c();
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
extern u8 linkIsRotated;
extern u8 linkFlag_803dd8f8;
extern s16 linkCount_803dd90e;
extern s8 lbl_803DD910;
extern s8 lbl_803DD911;
extern s8 linkSelected;
extern s8 lbl_803DD913;
extern LinkMenuItem lbl_803A9458[40];

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
int Dummy3E_func05_ret_1(void) { return 1; }

/* EN v1.0 0x80132010  size: 4b   Empty no-op. */
void Dummy3E_func04_nop(void)
{
}

/* EN v1.0 0x80132014  size: 8b   Trivial 0-returner. */
int Dummy3E_func03_ret_0(void) { return 0; }

/* EN v1.0 0x8013201C  size: 4b   Empty no-op. */
void Dummy3E_release(void)
{
}

/* EN v1.0 0x80132020  size: 4b   Empty no-op. */
void Dummy3E_initialise(void)
{
}

extern u8 linkTextures[0x30];
extern s16 lbl_8031C2A8[6];
extern void mm_free(void);
extern void fn_8001BDD4(int);

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

/* Drift-recovery: add new fns with v1.0 names. */
extern void* textureLoadAsset(int id);
extern void textureFree(void* p);
extern void fn_8001BE2C(int mode);
extern void* mmAlloc(int size, int heap, int flags);
extern void* memcpy(void* dst, const void* src, int size);
extern void OSReport(const char* fmt, ...);
extern void padFn_80014b18(int value);
extern s16 linkItemOpacity;
extern s16 lbl_803DD8FA;
extern s16 lbl_803DD8FC;
extern s16 lbl_803DD8FE;
extern s16 lbl_803DD900;
extern s16 lbl_803DD902;
extern s16 lbl_803DD904;
extern const char* lbl_803DD908;
extern char lbl_8031C1A8[];
extern void linkInitTextures(LinkMenuItem* item);


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
    void** p;
    s16* assetIds;
    int i;

    i = 0;
    p = lbl_803A9DB8;
    assetIds = (s16*)lbl_8031C2A8;
    for (; i < 6; i++)
    {
        if (*p == 0)
        {
            *p = textureLoadAsset(*assetIds);
        }
        p++;
        assetIds++;
    }
}

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

void TitleMenuItem_release(void)
{
    void** p;
    int i;

    i = 0;
    p = lbl_803A9DB8;
    for (; i < 6; i++)
    {
        textureFree(*p);
        *p = NULL;
        p++;
    }
}

void Link_free(void)
{
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

