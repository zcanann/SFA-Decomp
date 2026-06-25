/*
 * In-game HUD / pause-status DLL. Draws and animates the on-screen
 * status overlay over a single shared HUD block at lbl_803A87F0
 * (modeled here as PauseMenuHud):
 *   - hudDrawMagicBar   : segmented magic-meter bar (current + drain ghost).
 *   - hudDrawCounter    : right-edge numeric counters (score/progress).
 *   - pauseMenuDrawStatus: per-frame status latch + fade-in/out of each HUD
 *       element (health, magic, money, keys, scarabs, spirits), driven off
 *       game bits and the pause/screen-fade/camera state; sets the new-item
 *       "got" game bits (0xB98..0xD97) and plays pickup sfx.
 *   - hudDrawButtons    : C-menu item ring + A/B/Y button-prompt icons.
 *   - cMenuUpdateAnims  : C-menu open/close slide and fade animation.
 *   - minimapFn_8012310c: minimap reveal/fade animation.
 *   - trickyBitFn_801241cc: counts active Tricky-HUD item entries by game bit.
 */
#include "main/audio/sfx.h"
#include "main/dll/maybeTemplate.h"
#include "main/camera_interface.h"
#include "main/gamebits.h"
#include "main/mapEventTypes.h"
#include "main/screen_transition.h"
#include "main/dll/player_status.h"
#include "main/gameplay_runtime.h"
#include "dolphin/gx/GXCull.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/printf.h"
#include "sfa_light_decls.h"

#define GCMENU_ITEM_ICON_COUNT 7
#define PAUSE_MENU_HUD_ITEM_COUNT 13

extern int objIsCurModelNotZero(void* obj);
extern int playerGetMoney(void* player);

extern s8 lbl_803DD7A0;
extern short lbl_803DD7A2;
extern u8 framesThisStep;
extern short lbl_803DD8D2;
extern short gMinimapRevealMax;
extern short lbl_803DBA6E;
extern u8 lbl_803DBA65;
extern short gCMenuScrollTimer;
extern short lbl_803DD78E;
extern u8 cMenuOpen;
extern short cMenuFadeCounter;
extern short gCMenuOpenAnim;
extern short gCMenuOpenAnimMax;
extern int gTrickyHudItemMask;
extern short gCMenuStaffAbilities[];
extern void pauseMenuDrawElement(int tex, f32 x, f32 y, int a, int b, int c, int d);
extern void drawPartialTexture(int tex, f32 x, f32 y, int alpha, int arg, int w, int h, int off, int m);
extern void drawFn_8011eb3c(int tex, f32 x, f32 y, int a, int b, int c, int w, int h, int m);
extern void drawFn_8011e8d8(int tex, f32 x, f32 y, int a, int b, int w, int h, int off, int m);
extern void drawScaledTexture(int texture, f32 x, f32 y, int alpha, int arg, int w, int h, int mode);
extern void drawTexture(int texture, f32 x, f32 y, int alpha, int arg);
extern int hudTextures[];
extern int lbl_803A9364[];
extern int lbl_803DBAD0;
extern int lbl_803DBAD4;
extern int lbl_803DBAD8;
extern int lbl_803DBADC;
extern u8 lbl_803DD7B3;

extern void gameTextSetCharset(int charset, int flags);
extern void gameTextSetColor(int r, int g, int b, int a);
extern void gameTextShowStr(char* text, int box, int arg2, int arg3);

extern char sTemplateProgressCounterFormat[];
extern char lbl_803DBB48;
extern char lbl_803DBB50;
extern char lbl_803DBB58;
extern u32 lbl_803E1E1C;
extern u32 lbl_803E1E24;
extern f32 lbl_803E1E68;
extern f32 lbl_803E1E70;
extern f32 lbl_803E1F9C;
extern f32 lbl_803E1FA8;
extern f32 lbl_803E1FB8;
extern int lbl_803A87F0[];
extern f32 lbl_803DD83C;
extern u8 lbl_803DD75B;
extern u8 lbl_803DD792;
extern u8 lbl_803DD840;
extern f32 lbl_803DD844;
extern u8 pauseMenuState;
extern u8 cMenuEnabled;
extern int airMeter;
extern f32 hudElementOpacity;
extern f32 timeDelta;
extern f32 lbl_803E1E3C;
extern f32 lbl_803E1FA0;
extern f32 lbl_803E1FBC;
extern f32 lbl_803E1FC0;
extern f32 lbl_803E1FC4;
extern f32 lbl_803E1FC8;
extern void hudDrawCMenu(int a, int b, int c);
extern int gameTextGet();
extern void gameTextMeasureFn_800163c4(char* str, int boxIdx, int x, int y, int* outMaxX, int* outMaxY, int* outMinX, int* outMinY);
extern void textureFree(int texture);
extern int textureLoadAsset(int id);
extern void fn_8005D118(int a, int b, int c, int d, int e);
extern int gCMenuItemCount;
extern s16 gCMenuSelIndex;
extern s8 gCMenuCurSection;
extern u8 gCMenuItemIcons[GCMENU_ITEM_ICON_COUNT];
extern u8 lbl_803DD8D4;
extern int hudYButtonItemIconTexture;
extern s16 yButtonItemTextureId;
extern s16 gHudYButtonItemTextureCache;
extern s16 aButtonIcon;
extern s16 prevAButtonIcon;
extern u8 bButtonIcon;
extern u8 gHudPrevBButtonIcon;
extern u8 gHudAButtonFlashTimer;
extern u8 gHudBButtonFlashTimer;
extern u8 gYButtonInUse;
extern f32 gYButtonIconAnim;
extern f32 gHudYButtonIconScale;
extern f32 lbl_803DBA74;
extern f32 lbl_803DBA78;
extern f32 lbl_803DBA7C;
extern f32 lbl_803DBA80;
extern f32 lbl_803DBA84;
extern s16 gCMenuRowFadeInThreshold;
extern s16 gCMenuRowFadeOutThreshold;
extern u8 gHudButtonIcons[];
extern char lbl_803DBB5C;
extern u32 lbl_803E1E18;
extern f64 lbl_803E1EA8;
extern f32 lbl_803E1FB4;
extern f32 lbl_803E1FCC;
extern f32 lbl_803E1FD0;
extern f32 lbl_803E1FD4;
extern f32 lbl_803E1FD8;
extern f32 lbl_803E1FDC;
extern f32 lbl_803E1FE0;
extern f32 lbl_803E1FE4;
extern f32 lbl_803E1FE8;
extern f32 lbl_803E1FEC;
extern f32 lbl_803E1FF0;
extern f32 lbl_803E1FF4;
extern f32 lbl_803E1FF8;
extern f32 lbl_803E1FFC;
extern f32 lbl_803E2000;
extern f32 lbl_803E2004;
extern f32 lbl_803E200C;
extern f32 lbl_803E2008;
extern f32 lbl_803E2010;
extern f32 lbl_803E2014;
extern f32 lbl_803E2018;

/* File-local overlay for the pause/status HUD block at lbl_803A87F0 (accessed
 * as a raw u8* base here). Only the pure-constant scalar fields are named; the
 * indexed/per-slot arrays in this region are left as raw casts. The lower
 * offsets (<0x244) are modeled file-locally elsewhere (CMenuHud in
 * dll_0000_gameui.c). */
typedef struct PauseMenuHud
{
    u8 _pad0[0x244];
    int texHandle;       /* 0x244 */
    u8 _pad248[0xB00 - 0x248];
    f32 magicCur;        /* 0xB00 */
    u8 _padB04[0xB08 - 0xB04];
    f32 moneyAnim;       /* 0xB08 */
    f32 healthAnim;      /* 0xB0C */
    u8 _padB10[0xB24 - 0xB10];
    f32 keyAnim;         /* 0xB24 */
    f32 scarabAnim;      /* 0xB28 */
    f32 spiritAnim;      /* 0xB2C */
    u8 _padB30[0xB38 - 0xB30];
    int magicValue;      /* 0xB38 */
    u8 _padB3C[0xB50 - 0xB3C];
    int maxMagicValue;   /* 0xB50 */
    u8 _padB54[0xB58 - 0xB54];
    int spiritBitState;  /* 0xB58 */
    u8 _padB5C[0xB7C - 0xB5C];
    int magicLatch;      /* 0xB7C */
    u8 _padB80[0xB94 - 0xB80];
    int maxMagicLatch;   /* 0xB94 */
} PauseMenuHud;

STATIC_ASSERT(offsetof(PauseMenuHud, texHandle) == 0x244);
STATIC_ASSERT(offsetof(PauseMenuHud, magicCur) == 0xB00);
STATIC_ASSERT(offsetof(PauseMenuHud, moneyAnim) == 0xB08);
STATIC_ASSERT(offsetof(PauseMenuHud, healthAnim) == 0xB0C);
STATIC_ASSERT(offsetof(PauseMenuHud, keyAnim) == 0xB24);
STATIC_ASSERT(offsetof(PauseMenuHud, scarabAnim) == 0xB28);
STATIC_ASSERT(offsetof(PauseMenuHud, spiritAnim) == 0xB2C);
STATIC_ASSERT(offsetof(PauseMenuHud, magicValue) == 0xB38);
STATIC_ASSERT(offsetof(PauseMenuHud, maxMagicValue) == 0xB50);
STATIC_ASSERT(offsetof(PauseMenuHud, spiritBitState) == 0xB58);
STATIC_ASSERT(offsetof(PauseMenuHud, magicLatch) == 0xB7C);
STATIC_ASSERT(offsetof(PauseMenuHud, maxMagicLatch) == 0xB94);

void hudDrawMagicBar(int alpha, int unk2, u32 flags)
{
    int t13;
    int total;
    int current;
    int seg1;
    int rem1;
    int seg2;
    int seg3;
    int seg4;
    int rem4;
    int w8;
    int tmp;
    int tex;

    total = lbl_803A9364[8];
    t13 = total - 0xd;
    current = lbl_803A9364[2];
    seg1 = (current > 7) ? 7 : current;
    if (seg1 != 0)
    {
        seg1++;
    }
    rem1 = 8 - seg1;
    seg2 = current - 7;
    if (t13 < seg2)
    {
        seg2 = t13;
    }
    if (seg2 > 0)
    {
    }
    else
    {
        seg2 = 0;
    }
    seg3 = t13 - seg2;
    tmp = (current - 7) - t13;
    if (tmp > 5)
    {
        tmp = 5;
    }
    if (tmp > 0)
    {
        seg4 = tmp;
    }
    else
    {
        seg4 = 0;
    }
    if (current == total)
    {
        seg4 = 7;
    }
    rem4 = 0x10 - seg4;
    tex = hudTextures[0x27];
    if ((u8)flags)
    {
        pauseMenuDrawElement(tex, lbl_803DBAD0, lbl_803DBAD4, unk2, alpha, 0x100, 0);
    }
    else
    {
        drawTexture(tex, lbl_803DBAD8, lbl_803DBADC, alpha, 0x100);
    }
    if (seg1 != 0)
    {
        tex = hudTextures[0x28];
        if ((u8)flags)
        {
            drawFn_8011eb3c(tex, (f32)(lbl_803DBAD0 + 0x1c), lbl_803DBAD4, unk2, alpha, 0x100, seg1, 0x12,
                            0);
        }
        else
        {
            drawScaledTexture(tex, (f32)(lbl_803DBAD8 + 0x1c), lbl_803DBADC, alpha, 0x100, seg1, 0x12,
                              0);
        }
    }
    if (rem1 != 0)
    {
        tex = hudTextures[0x29];
        if ((u8)flags)
        {
            drawFn_8011e8d8(tex, (f32)(seg1 + lbl_803DBAD0 + 0x1c), lbl_803DBAD4, unk2, alpha, rem1, 0x12,
                            seg1, 0);
        }
        else
        {
            drawPartialTexture(tex, (f32)(seg1 + lbl_803DBAD8 + 0x1c), lbl_803DBADC, alpha, 0x100, rem1,
                               0x12, seg1, 0);
        }
    }
    if (seg2 != 0)
    {
        tex = hudTextures[0x2A];
        if ((u8)flags)
        {
            drawFn_8011eb3c(tex, (f32)(lbl_803DBAD0 + 0x24), lbl_803DBAD4, unk2, alpha, 0x100, seg2, 0x12,
                            0);
        }
        else
        {
            drawScaledTexture(tex, (f32)(lbl_803DBAD8 + 0x24), lbl_803DBADC, alpha, 0x100, seg2, 0x12,
                              0);
        }
    }
    if (seg3 != 0)
    {
        tex = hudTextures[0x2B];
        if ((u8)flags)
        {
            drawFn_8011eb3c(tex, (f32)(seg2 + lbl_803DBAD0 + 0x24), lbl_803DBAD4, unk2, alpha, 0x100,
                            seg3, 0x12, 0);
        }
        else
        {
            drawScaledTexture(tex, (f32)(seg2 + lbl_803DBAD8 + 0x24), lbl_803DBADC, alpha, 0x100, seg3,
                              0x12, 0);
        }
    }
    if (seg4 != 0)
    {
        tex = hudTextures[0x2C];
        if ((u8)flags)
        {
            drawFn_8011eb3c(tex, (f32)(t13 + lbl_803DBAD0 + 0x24), lbl_803DBAD4, unk2, alpha, 0x100, seg4,
                            0x12, 0);
        }
        else
        {
            drawScaledTexture(tex, (f32)(t13 + lbl_803DBAD8 + 0x24), lbl_803DBADC, alpha, 0x100, seg4,
                              0x12, 0);
        }
    }
    if (rem4 != 0)
    {
        tex = hudTextures[0x2D];
        if ((u8)flags)
        {
            drawFn_8011e8d8(tex, (f32)(t13 + seg4 + lbl_803DBAD0 + 0x24), lbl_803DBAD4, unk2, alpha, rem4,
                            0x12, seg4, 0);
        }
        else
        {
            drawPartialTexture(tex, (f32)(t13 + seg4 + lbl_803DBAD8 + 0x24), lbl_803DBADC, alpha, 0x100,
                               rem4, 0x12, seg4, 0);
        }
    }
    current = current - lbl_803DD7B3;
    if (current < 0)
    {
        current = 0;
    }
    if (current != 0)
    {
        current++;
    }
    if (current == total)
    {
        current++;
    }
    w8 = current;
    if (current > 8)
    {
        w8 = 8;
    }
    seg1 = seg1 - w8;
    rem1 = current - 8;
    if (t13 < current - 8)
    {
        rem1 = t13;
    }
    if (rem1 < 1)
    {
        rem1 = 0;
    }
    seg2 = seg2 - rem1;
    current = (current - 8) - t13;
    if (current > 8)
    {
        current = 8;
    }
    if (current < 1)
    {
        current = 0;
    }
    seg4 = seg4 - current;
    if (seg1 != 0)
    {
        tex = hudTextures[0x31];
        if ((u8)flags)
        {
            drawFn_8011e8d8(tex, (f32)(w8 + lbl_803DBAD0 + 0x1c), lbl_803DBAD4, unk2, alpha, seg1, 0x12,
                            w8, 0);
        }
        else
        {
            drawPartialTexture(tex, (f32)(w8 + lbl_803DBAD8 + 0x1c), lbl_803DBADC, alpha, 0x100, seg1,
                               0x12, w8, 0);
        }
    }
    if (seg2 != 0)
    {
        tex = hudTextures[0x32];
        if ((u8)flags)
        {
            drawFn_8011eb3c(tex, (f32)(rem1 + lbl_803DBAD0 + 0x24), lbl_803DBAD4, unk2, alpha, 0x100,
                            seg2, 0x12, 0);
        }
        else
        {
            drawScaledTexture(tex, (f32)(rem1 + lbl_803DBAD8 + 0x24), lbl_803DBADC, alpha, 0x100, seg2,
                              0x12, 0);
        }
    }
    if (seg4 != 0)
    {
        tex = hudTextures[0x33];
        if ((u8)flags)
        {
            drawFn_8011eb3c(tex, (f32)(t13 + current + lbl_803DBAD0 + 0x24), lbl_803DBAD4, unk2, alpha,
                            0x100, seg4, 0x12, 0);
        }
        else
        {
            drawScaledTexture(tex, (f32)(t13 + current + lbl_803DBAD8 + 0x24), lbl_803DBADC, alpha,
                              0x100, seg4, 0x12, 0);
        }
    }
}

typedef struct CounterText
{
    u32 raw[2];
} CounterText;

void hudDrawCounter(int idx, s16 value, s16 target, int alpha, int timer, int* yPos, u8 showTarget)
{
    int prevCharset;
    int tex;
    CounterText buf1;
    CounterText buf2;
    f32 width;

    buf1 = *(CounterText*)&lbl_803E1E1C;
    buf2 = *(CounterText*)&lbl_803E1E24;
    if ((u8)alpha != 0)
    {
        if (((f32)timer < lbl_803E1F9C) || ((f32)timer > lbl_803E1FA8) || ((timer & 8) != 0) ||
            (idx == 30))
        {
            tex = hudTextures[idx];
            drawTexture(tex, (f32)(575 - *yPos), lbl_803E1FB8, alpha, 256);
            if (idx == 30)
            {
                if (showTarget != 0)
                {
                    sprintf((char*)&buf1, sTemplateProgressCounterFormat, value < 0 ? -value : value, target);
                    sprintf((char*)&buf2, &lbl_803DBB48, value < 0 ? -value : value);
                }
                else
                {
                    sprintf((char*)&buf1, &lbl_803DBB50, value);
                }
            }
            else
            {
                sprintf((char*)&buf1, &lbl_803DBB58, value);
            }
            prevCharset = gameTextGetCharset();
            gameTextSetCharset(3, 3);
            gameTextMeasureString((u8*)&buf1, lbl_803E1E68, &width, NULL, NULL, NULL, -1);
            if ((showTarget == 0) && (value >= target))
            {
                gameTextSetColor(0, 0xFF, 0, alpha);
            }
            else
            {
                gameTextSetColor(0xFF, 0xFF, 0xFF, alpha);
            }
            gameTextShowStr((char*)&buf1, 0x93, (int)-(lbl_803E1E70 * width - (f32)(591 - *yPos)), 0x1A9);
            if (showTarget != 0)
            {
                if (value >= 0)
                {
                    gameTextSetColor(0, 0xFF, 0, alpha);
                }
                else
                {
                    gameTextSetColor(0xFF, 0, 0, alpha);
                }
                gameTextShowStr((char*)&buf2, 0x93, (int)-(lbl_803E1E70 * width - (f32)(591 - *yPos)), 0x1A9);
            }
            gameTextSetCharset(prevCharset, 3);
        }
        *yPos = *yPos + 0x28;
    }
}

#define PMDS_TRICKY_ENERGY_PTR() \
  (*gMapEventInterface)->getTrickyEnergy()
#define PMDS_SCREEN_GET_FADE() \
  (*gScreenTransitionInterface)->getProgress()
#define PMDS_CAMERA_GET_STATE() \
  (*gCameraInterface)->getMode()

void pauseMenuDrawStatus(void)
{
    u8* player;
    u8* trickyStatus;
    u8* base;
    int delta;
    s8 negDelta;
    f32* op;
    u8* bp;
    int* dp;
    int bit;
    u8 i;
    u8 j;
    u32 ji;
    int off;
    int cur;
    int sv;
    f32 thresh;
    f32 prev;
    f32 newOp;
    int statuses[PAUSE_MENU_HUD_ITEM_COUNT];

    base = (u8*)lbl_803A87F0;
    player = Obj_GetPlayerObject();
    getTrickyObject();
    trickyStatus = PMDS_TRICKY_ENERGY_PTR();
    statuses[0] = Player_GetCurrentHealth((int)player);
    statuses[7] = Player_GetMaxHealth((int)player);
    statuses[1] = GameBit_Get(0xC1);
    if (((PauseMenuHud*)base)->magicValue - Player_GetCurrentMagic((int)player) < 0)
    {
        delta = -1;
    }
    else if (((PauseMenuHud*)base)->magicValue - Player_GetCurrentMagic((int)player) > 0)
    {
        delta = 1;
    }
    else
    {
        delta = 0;
    }
    statuses[2] = ((PauseMenuHud*)base)->magicValue - delta;
    if (((PauseMenuHud*)base)->maxMagicValue - Player_GetMaxMagic((int)player) < 0)
    {
        delta = -1;
    }
    else if (((PauseMenuHud*)base)->maxMagicValue - Player_GetMaxMagic((int)player) > 0)
    {
        delta = 1;
    }
    else
    {
        delta = 0;
    }
    negDelta = -delta;
    statuses[8] = ((PauseMenuHud*)base)->maxMagicValue + negDelta;
    if ((negDelta != 0) && (lbl_803DD83C != lbl_803E1E3C) &&
        (objIsCurModelNotZero(player) != 0) && (GameBit_Get(0xEB1) != 0))
    {
        Sfx_KeepAliveLoopedObjectSound(0, 0x3F0);
    }
    ((PauseMenuHud*)base)->magicLatch = statuses[2];
    ((PauseMenuHud*)base)->maxMagicLatch = statuses[8];
    statuses[4] = GameBit_Get(0x66C);
    statuses[10] = GameBit_Get(0x13D);
    if (statuses[10] != ((PauseMenuHud*)base)->spiritBitState)
    {
        u8 flag = 0;
        if (statuses[10] == 0)
        {
            flag = 1;
        }
        GameBit_Set(0x967, flag);
    }
    statuses[11] = GameBit_Get(0x86A);
    statuses[12] = GameBit_Get(0x3F5);
    statuses[3] = playerGetMoney(player);
    statuses[9] = *trickyStatus;
    if ((((lbl_803DD792 & 1) != 0) ||
            ((lbl_803E1E3C == PMDS_SCREEN_GET_FADE()) && (PMDS_CAMERA_GET_STATE() != 0x44) &&
                ((*(u16*)(player + 0xB0) & 0x1000) == 0) && (getHudHiddenFrameCount() == 0) &&
                (lbl_803DD75B == 0))) &&
        (pauseMenuState == 0))
    {
        lbl_803DD83C = lbl_803E1FA0 * timeDelta + lbl_803DD83C;
        if (lbl_803DD83C > *(f32*)&hudElementOpacity)
        {
            lbl_803DD83C = hudElementOpacity;
        }
    }
    else
    {
        lbl_803DD83C = -(lbl_803E1FA0 * timeDelta - lbl_803DD83C);
        if (lbl_803DD83C < lbl_803E1E3C)
        {
            lbl_803DD83C = *(f32 *)&lbl_803E1E3C;
        }
    }
    if ((cMenuEnabled == 0) && (GameBit_Get(0xA7B) != 0))
    {
        cMenuEnabled = 1;
    }
    for (i = 0; i < PAUSE_MENU_HUD_ITEM_COUNT; i++)
    {
        switch (i)
        {
        case 1:
        case 3:
        case 4:
        case 10:
        case 11:
        case 12:
            off = i * 4;
            if (((((f32*)(base + 0xAFC))[i] >= lbl_803E1E3C) &&
                    ((*(u16*)(player + 0xB0) & 0x1000) == 0) && (pauseMenuState == 0) &&
                    ((u32)airMeter == 0) && (getHudHiddenFrameCount() == 0) &&
                    (PMDS_CAMERA_GET_STATE() != 0x44)) ||
                ((i == 3) && ((lbl_803DD792 & 2) != 0)))
            {
                op = (f32*)(base + 0xAC8) + i;
                thresh = lbl_803E1FA0 * timeDelta + *op;
                *op = thresh;
                if (thresh > hudElementOpacity)
                {
                    *op = hudElementOpacity;
                }
            }
            else
            {
                op = (f32*)(base + 0xAC8) + i;
                thresh = -(lbl_803E1FA0 * timeDelta - *op);
                *op = thresh;
                if (thresh < lbl_803E1E3C)
                {
                    *op = *(f32 *)&lbl_803E1E3C;
                }
            }
            break;
        }
    }
    i = 0;
    statuses[6] = 0;
    if ((lbl_803DD840 & 1) != 0)
    {
        lbl_803DD840 = lbl_803DD840 & ~1;
        for (j = 0; j < PAUSE_MENU_HUD_ITEM_COUNT; j++)
        {
            ((int*)(base + 0xB74))[j] = statuses[j];
            ((int*)(base + 0xB30))[j] = statuses[j];
            ((f32*)(base + 0xAFC))[j] = lbl_803E1FBC;
        }
        if ((GameBit_Get(0xB98) != 0) || (statuses[4] != 0))
        {
            ((PauseMenuHud*)base)->healthAnim = lbl_803E1FC0;
        }
        if ((GameBit_Get(0xB99) != 0) || (statuses[1] != 0))
        {
            ((PauseMenuHud*)base)->magicCur = lbl_803E1FC0;
        }
        if ((GameBit_Get(0xB9A) != 0) || (statuses[10] != 0))
        {
            ((PauseMenuHud*)base)->keyAnim = lbl_803E1FC0;
        }
        if ((GameBit_Get(0xB9B) != 0) || (statuses[11] != 0))
        {
            ((PauseMenuHud*)base)->scarabAnim = lbl_803E1FC0;
        }
        if ((GameBit_Get(0xB9C) != 0) || (statuses[3] != 0))
        {
            ((PauseMenuHud*)base)->moneyAnim = lbl_803E1FC0;
        }
        if ((GameBit_Get(0xD97) != 0) || (statuses[12] != 0))
        {
            ((PauseMenuHud*)base)->spiritAnim = lbl_803E1FC0;
        }
        lbl_803DD844 = lbl_803E1E3C;
    }
    else
    {
        thresh = lbl_803E1FA8;
        for (; i < PAUSE_MENU_HUD_ITEM_COUNT; i++)
        {
            ji = i;
            op = ((f32*)(base + 0xAFC)) + ji;
            prev = *op;
            newOp = prev - timeDelta;
            *op = newOp;
            if ((prev > thresh) && (newOp <= thresh))
            {
                switch (ji)
                {
                case 3:
                    Sfx_PlayFromObject(0, 0x38D);
                    dp = ((int*)(base + 0xB74)) + ji;
                    cur = *dp;
                    sv = statuses[ji];
                    if (cur > sv)
                    {
                        *dp = cur - 1;
                    }
                    else
                    {
                        *dp = cur + 1;
                    }
                    if (*dp != sv)
                    {
                        *op = lbl_803E1FC4;
                    }
                    break;
                default:
                    ((int*)(base + 0xB74))[ji] = statuses[ji];
                    break;
                }
            }
            if (statuses[ji] != 0)
            {
                bp = base + ji;
                bp += 0xB64;
                if (*bp == 0)
                {
                    bit = 0;
                    switch (i)
                    {
                    case 3:
                        bit = 0xB9C;
                        break;
                    case 4:
                        bit = 0xB98;
                        break;
                    case 1:
                        bit = 0xB99;
                        break;
                    case 10:
                        bit = 0xB9A;
                        break;
                    case 11:
                        bit = 0xB9B;
                        break;
                    case 12:
                        bit = 0xD97;
                        break;
                    }
                    if (bit != 0)
                    {
                        GameBit_Set(bit, 1);
                        *bp = 1;
                    }
                }
            }
            if (statuses[ji] != ((int*)(base + 0xB30))[ji])
            {
                ((int*)(base + 0xB30))[ji] = statuses[ji];
                if (*op <= lbl_803E1FA8)
                {
                    *op = lbl_803E1FC8 - timeDelta;
                }
            }
            switch (i)
            {
            case 1:
            case 3:
            case 4:
            case 10:
            case 11:
            case 12:
                if ((prev > lbl_803E1E3C) && (*op <= lbl_803E1E3C))
                {
                    *op = lbl_803E1FC0;
                }
                break;
            default:
                if (*op < lbl_803E1FBC)
                {
                    *op = lbl_803E1FBC;
                }
                break;
            }
        }
    }
}

void minimapFn_8012310c(void)
{
    if (lbl_803DD7A0 != '\0')
    {
        lbl_803DD7A2 = lbl_803DD7A2 + framesThisStep * 0x20;
        if (0xff < lbl_803DD7A2)
        {
            lbl_803DD7A2 = 0xff;
        }
    }
    else
    {
        if (lbl_803DD8D2 == 0)
        {
            lbl_803DD7A2 = lbl_803DD7A2 - framesThisStep * 0x20;
            if (lbl_803DD7A2 < 0)
            {
                lbl_803DD7A2 = 0;
            }
        }
    }
    if ((lbl_803DD7A0 != '\0') && (lbl_803DD7A2 == 0xff))
    {
        lbl_803DD8D2 = lbl_803DD8D2 + framesThisStep * 4;
        if (lbl_803DD8D2 > gMinimapRevealMax)
        {
            lbl_803DD8D2 = gMinimapRevealMax;
        }
    }
    else
    {
        lbl_803DD8D2 = lbl_803DD8D2 - framesThisStep * 4;
        if (lbl_803DD8D2 < 0)
        {
            lbl_803DD8D2 = 0;
        }
    }
    if (lbl_803DD7A2 != 0)
    {
        return;
    }
    lbl_803DBA6E = 0xffff;
    return;
}

void hudDrawButtons(int unk1, int unk2, int unk3)
{
    char slots[68];
    u32 label;
    int ax0;
    int ax1;
    int ay0;
    int ay1;
    int bx0;
    int bx1;
    int by0;
    int by1;
    int am3;
    int am2;
    int am1;
    int am0;
    int bm3;
    int bm2;
    int bm1;
    int bm0;
    u8* base;
    void* player;
    u8* gp;
    s16 fade;
    int slotCount;
    int sel;
    int k;
    int i;
    int yOff;
    u8* iconPtr;
    s16 alpha;
    s16 rowFade;
    s16 a16;
    int prevCharset;
    int prevCharset2;
    int textObj;
    int textPtr;
    u32 glyph;
    int wid;
    u8 bi;
    int icon;
    f32 scaleT;
    f64 dv;

    base = (u8*)lbl_803A87F0;
    player = Obj_GetPlayerObject();
    label = lbl_803E1E18;
    icon = 0;
    if ((cMenuFadeCounter != 0) && (cMenuEnabled != 0))
    {
        slotCount = 3;
        sel = 1;
        for (i = 0; i < gCMenuItemCount; i++)
        {
            slots[i] = 0;
        }
        for (i = gCMenuItemCount; i < 3; i++)
        {
            slots[i] = 1;
        }
        if (gCMenuItemCount < 3)
        {
            gCMenuItemCount = 3;
        }
        if (gCMenuScrollTimer > 0)
        {
            sel = 2;
            slotCount = 4;
            if (gCMenuScrollTimer > 0x32)
            {
                sel = 3;
            }
        }
        else if ((gCMenuScrollTimer < 0) && (slotCount = 4, gCMenuScrollTimer < -0x32))
        {
            sel = 0;
        }
        k = gCMenuSelIndex - sel;
        if (k < 0)
        {
            k = k + gCMenuItemCount;
        }
        if (k >= gCMenuItemCount)
        {
            k = k - gCMenuItemCount;
        }
        fade = cMenuFadeCounter;
        iconPtr = gCMenuItemIcons;
        for (i = 0; i < GCMENU_ITEM_ICON_COUNT; i++)
        {
            ((int*)(base + 0xBD4))[i] = 0;
            iconPtr[i] = 0;
            ((int*)(base + 0xBB8))[i] = 0;
        }
        for (i = 0; i < slotCount; i++)
        {
            if (slots[k] == 0)
            {
                GXSetScissor(0, 0, 0x280, 0x1E0);
                ((int*)(base + 0xBD4))[(i + 3) - sel] = ((int*)(base + 0x9C8))[k];
                ((int*)(base + 0xBB8))[(i + 3) - sel] = ((u8*)(base + 0x488))[k];
                if (((u8*)(base + 0x448))[k] > 1)
                {
                    gCMenuItemIcons[(i + 3) - sel] = ((u8*)(base + 0x448))[k];
                }
            }
            k++;
            if (k >= gCMenuItemCount)
            {
                k = k - gCMenuItemCount;
            }
        }
        GXSetScissor(0, 0, 0x280, 0x1E0);
        hudDrawCMenu(unk1, unk2, unk3);
        i = 0;
        yOff = i;
        do
        {
            if (*iconPtr > 1)
            {
                alpha = fade;
                rowFade = gCMenuScrollTimer + yOff;
                if (rowFade < gCMenuRowFadeInThreshold)
                {
                    alpha = fade + (rowFade - gCMenuRowFadeInThreshold) * 8;
                }
                if (rowFade > gCMenuRowFadeOutThreshold)
                {
                    alpha = alpha - (rowFade - gCMenuRowFadeOutThreshold) * 8;
                }
                if (alpha < 0)
                {
                    alpha = 0;
                }
                if (alpha > 0xFF)
                {
                    alpha = 0xFF;
                }
                a16 = alpha * lbl_803DD8D4 / 0xFF;
                GXSetScissor(0, 0, 0x280, 0x1E0);
                sprintf((char*)&label, &lbl_803DBB58, *iconPtr);
                gameTextSetColor(0, 0, 0, a16 & 0xFF);
                gameTextShowStr((char*)&label, 0x93, 0x247, 0x2B + yOff + gCMenuScrollTimer);
                gameTextSetColor(0xFF, 0xFF, 0xFF, (u8)a16);
                gameTextShowStr((char*)&label, 0x93, 0x246, 0x2A + yOff + gCMenuScrollTimer);
            }
            iconPtr++;
            yOff += 0x32;
            i++;
        }
        while (i < GCMENU_ITEM_ICON_COUNT);
        drawTexture(((PauseMenuHud*)base)->texHandle, lbl_803E1FCC, lbl_803E1FD0, fade * lbl_803DD8D4 / 0xFF & 0xFF, 0x100);
        drawScaledTexture(((PauseMenuHud*)base)->texHandle, lbl_803E1FD4, lbl_803E1FD0, fade * lbl_803DD8D4 / 0xFF & 0xFF, 0x100,
                          0x12, 10, 1);
        drawScaledTexture(((PauseMenuHud*)base)->texHandle, lbl_803E1FCC, lbl_803E1FD8, fade * lbl_803DD8D4 / 0xFF & 0xFF, 0x100,
                          0x12, 10, 2);
        drawScaledTexture(((PauseMenuHud*)base)->texHandle, lbl_803E1FD4, lbl_803E1FD8, fade * lbl_803DD8D4 / 0xFF & 0xFF, 0x100,
                          0x12, 10, 3);
        if ((player != NULL) && (objIsCurModelNotZero(player) != 0))
        {
            switch (gCMenuCurSection)
            {
            case 2:
                icon = 0x58;
                break;
            case 0:
                icon = 0x59;
                break;
            case 1:
                icon = 0x5A;
                break;
            }
            drawTexture(((int*)(base + 0x1C0))[icon], lbl_803E1FDC, lbl_803E1FB4, fade * lbl_803DD8D4 / 0xFF & 0xFF,
                        0x100);
        }
    }
    if (((u32)hudYButtonItemIconTexture != 0) && (gHudYButtonItemTextureCache != yButtonItemTextureId))
    {
        textureFree(hudYButtonItemIconTexture);
        gHudYButtonItemTextureCache = -1;
        hudYButtonItemIconTexture = 0;
    }
    if (((u32)hudYButtonItemIconTexture == 0) && (yButtonItemTextureId > 0))
    {
        gHudYButtonItemTextureCache = yButtonItemTextureId;
        hudYButtonItemIconTexture = textureLoadAsset(yButtonItemTextureId);
    }
    if (lbl_803DD83C != lbl_803E1E3C)
    {
        drawTexture(((int*)(base + 0x1C0))[0], lbl_803E1FE0, lbl_803E1F9C, lbl_803DD83C, 0x100);
        drawTexture(((int*)(base + 0x1C0))[1], lbl_803E1FE4, lbl_803E1FE8, lbl_803DD83C, 0x100);
        drawTexture(((int*)(base + 0x1C0))[2], lbl_803E1FEC, lbl_803E1FF0, lbl_803DD83C, 0x100);
        if ((gHudAButtonFlashTimer & 8) == 0)
        {
            drawTexture(((int*)(base + 0x1C0))[9], lbl_803E1FF4, lbl_803E1FF8, lbl_803DD83C, 0x100);
        }
        if ((aButtonIcon != 0) && (aButtonIcon != 0x1C))
        {
            if (aButtonIcon != prevAButtonIcon)
            {
                gHudAButtonFlashTimer = 0x3F;
            }
            if (gHudAButtonFlashTimer != 0)
            {
                gHudAButtonFlashTimer--;
            }
            if (gHudAButtonFlashTimer & 8)
            {
                gameTextSetColor(0x32, 0x32, 0xFF, lbl_803DD83C);
            }
            else
            {
                gameTextSetColor(200, 0xE6, 0xFF, lbl_803DD83C);
            }
            prevCharset = gameTextGetCharset();
            gameTextSetCharset(3, 3);
            if (aButtonIcon > 0x3E8)
            {
                textObj = gameTextGet();
                icon = 1;
            }
            else
            {
                for (bi = 0; bi < 0x1D; bi++)
                {
                    if (aButtonIcon == gHudButtonIcons[bi * 2])
                    {
                        icon = bi;
                    }
                }
                textObj = gameTextGet(0x2AD);
            }
            if (icon != 0 && (void*)textObj != NULL && *(u16*)(textObj + 2) > *(gp = gHudButtonIcons + icon * 2 + 1))
            {
                textPtr = *(int*)(*(int*)(textObj + 8) + *gp * 4);
                prevCharset2 = gameTextGetCharset();
                gameTextSetCharset(3, 3);
                gameTextMeasureFn_800163c4((char*)textPtr, 8, 0, 0, &am0, &am1, &am2, &am3);
                gameTextShowStr((char*)textPtr, 8, 0, 0);
                gameTextSetCharset(prevCharset2, 3);
                gameTextMeasureFn_800163c4(*(char**)(*(int*)(textObj + 8) + *gp * 4), 8, 0, 0, &ax0, &ax1, &ay0, &ay1);
                wid = (ax1 - ax0) + -0x19;
                if (wid < 1)
                {
                    wid = 1;
                }
                drawScaledTexture(((int*)(base + 0x1C0))[8], (f32)(0x219 - wid), lbl_803E1FFC, lbl_803DD83C, 0x100,
                                  wid, 0x16, 0);
                drawTexture(((int*)(base + 0x1C0))[7], (f32)(0x20D - wid), lbl_803E1FFC, lbl_803DD83C, 0x100);
            }
            else
            {
                drawTexture(((int*)(base + 0x1C0))[7], lbl_803E2000, lbl_803E1FFC, lbl_803DD83C, 0x100);
            }
            prevAButtonIcon = aButtonIcon;
            drawTexture(((int*)(base + 0x1C0))[5], lbl_803E1FCC, lbl_803E1FFC, lbl_803DD83C, 0x100);
            gameTextSetCharset(prevCharset, 3);
        }
        else
        {
            drawTexture(((int*)(base + 0x1C0))[3], lbl_803E1FCC, lbl_803E1FFC, lbl_803DD83C, 0x100);
            prevAButtonIcon = 0;
            gHudAButtonFlashTimer = 0;
        }
        if (bButtonIcon != 0)
        {
            if (bButtonIcon != gHudPrevBButtonIcon)
            {
                gHudBButtonFlashTimer = 0x3F;
            }
            if (gHudBButtonFlashTimer != 0)
            {
                gHudBButtonFlashTimer--;
            }
            if (gHudBButtonFlashTimer & 8)
            {
                gameTextSetColor(0x32, 0x32, 0xFF, lbl_803DD83C);
            }
            else
            {
                gameTextSetColor(200, 0xE6, 0xFF, lbl_803DD83C);
            }
            icon = 0;
            for (bi = icon; bi < 0x1D; bi++)
            {
                if (bButtonIcon == gHudButtonIcons[bi * 2])
                {
                    icon = bi;
                }
            }
            prevCharset = gameTextGetCharset();
            gameTextSetCharset(3, 3);
            textObj = gameTextGet(0x2AD);
            if (icon != 0 && (void*)textObj != NULL && *(u16*)(textObj + 2) > *(gp = gHudButtonIcons + icon * 2 + 1))
            {
                textPtr = *(int*)(*(int*)(textObj + 8) + *gp * 4);
                prevCharset2 = gameTextGetCharset();
                gameTextSetCharset(3, 3);
                gameTextMeasureFn_800163c4((char*)textPtr, 9, 0, 0, &bm0, &bm1, &bm2, &bm3);
                gameTextShowStr((char*)textPtr, 9, 0, 0);
                gameTextSetCharset(prevCharset2, 3);
                gameTextMeasureFn_800163c4(*(char**)(*(int*)(textObj + 8) + *gp * 4), 9, 0, 0, &bx0, &bx1, &by0, &by1);
                wid = (bx1 - bx0) + -7;
                if (wid < 1)
                {
                    wid = 1;
                }
                drawScaledTexture(((int*)(base + 0x1C0))[8], (f32)(0x219 - wid), lbl_803E2004, lbl_803DD83C, 0x100,
                                  wid, 0x16, 0);
                drawTexture(((int*)(base + 0x1C0))[7], (f32)(0x20D - wid), lbl_803E2004, lbl_803DD83C, 0x100);
            }
            else
            {
                drawTexture(((int*)(base + 0x1C0))[7], lbl_803E2008, lbl_803E2004, lbl_803DD83C, 0x100);
            }
            gHudPrevBButtonIcon = bButtonIcon;
            drawTexture(((int*)(base + 0x1C0))[6], lbl_803E1FCC, lbl_803E200C, lbl_803DD83C, 0x100);
            gameTextSetCharset(prevCharset, 3);
        }
        else
        {
            drawTexture(((int*)(base + 0x1C0))[4], lbl_803E1FCC, lbl_803E200C, lbl_803DD83C, 0x100);
            gHudPrevBButtonIcon = 0;
        }
        if ((u32)hudYButtonItemIconTexture != 0)
        {
            if (gYButtonInUse != 0)
            {
                scaleT = lbl_803E2010;
            }
            else
            {
                scaleT = lbl_803E1E68;
            }
            if (gHudYButtonIconScale > scaleT)
            {
                dv = gHudYButtonIconScale - lbl_803E1EA8;
                if (scaleT > dv)
                {
                    dv = scaleT;
                }
                gHudYButtonIconScale = dv;
            }
            else
            {
                dv = lbl_803E1EA8 + gHudYButtonIconScale;
                if (scaleT < dv)
                {
                    dv = scaleT;
                }
                gHudYButtonIconScale = dv;
            }
            gYButtonIconAnim = gYButtonIconAnim -
                (lbl_803DBA74 + (timeDelta * (gYButtonIconAnim - lbl_803DBA74)) / lbl_803DBA84);
            if (gYButtonIconAnim > lbl_803E1E3C)
            {
                gHudYButtonIconScale = lbl_803E1E68;
            }
            if (!(*(f32*)&gYButtonIconAnim > *(f32*)&lbl_803E1E3C))
            {
                gYButtonIconAnim = lbl_803E1E3C;
            }
            drawTexture(hudYButtonItemIconTexture, lbl_803DBA78 * gYButtonIconAnim + lbl_803E2014,
                        lbl_803DBA7C * gYButtonIconAnim + lbl_803E1F9C, (int)(gHudYButtonIconScale * lbl_803DD83C),
                        (int)(lbl_803DBA80 * gYButtonIconAnim + lbl_803E2018));
        }
        else
        {
            gameTextSetColor(0xFF, 0xFF, 0xFF, lbl_803DD83C);
            prevCharset = gameTextGetCharset();
            gameTextSetCharset(3, 3);
            gameTextShowStr(&lbl_803DBB5C, 0x93, 0x216, 0x22);
            gameTextSetCharset(prevCharset, 3);
        }
    }
    fn_8005D118(0, 0xFF, 0xFF, 0xFF, 0xFF);
}

void cMenuUpdateAnims(void)
{
    s8 s;
    u8 b;

    s = lbl_803DBA65;
    if (s >= 0)
    {
        gCMenuScrollTimer = gCMenuScrollTimer - framesThisStep * s;
        if (gCMenuScrollTimer < 0)
        {
            gCMenuScrollTimer = 0;
            lbl_803DBA65 = 0;
            lbl_803DD78E = 0;
        }
    }
    else
    {
        gCMenuScrollTimer = gCMenuScrollTimer + framesThisStep * (-s);
        if (gCMenuScrollTimer > 0)
        {
            gCMenuScrollTimer = 0;
            lbl_803DBA65 = 0;
            lbl_803DD78E = 0;
        }
    }
    b = cMenuOpen;
    if ((s8)b != 0)
    {
        cMenuFadeCounter = cMenuFadeCounter + framesThisStep * 8;
        if (cMenuFadeCounter > 0xff)
        {
            cMenuFadeCounter = 0xff;
        }
    }
    else
    {
        if (gCMenuOpenAnim == 0)
        {
            cMenuFadeCounter = cMenuFadeCounter - framesThisStep * 8;
            if (cMenuFadeCounter < 0)
            {
                cMenuFadeCounter = 0;
            }
        }
    }
    if ((s8)b != 0 && cMenuFadeCounter > 0x40)
    {
        gCMenuOpenAnim = gCMenuOpenAnim + framesThisStep * 16;
        if (gCMenuOpenAnim > gCMenuOpenAnimMax)
        {
            gCMenuOpenAnim = gCMenuOpenAnimMax;
        }
    }
    else
    {
        gCMenuOpenAnim = gCMenuOpenAnim - framesThisStep * 16;
        if (gCMenuOpenAnim < 0)
        {
            gCMenuOpenAnim = 0;
        }
    }
    if (cMenuFadeCounter != 0)
    {
        return;
    }
}

int trickyBitFn_801241cc(short* arr, s8 flag)
{
    short* entry;
    int count;
    int mask;

    count = 0;
    if (flag == 0)
    {
        entry = arr;
        while (entry[0] > -1)
        {
            if (GameBit_Get((int)entry[0]) != 0)
            {
                if (arr == gCMenuStaffAbilities)
                {
                    if (entry[2] < 0 || GameBit_Get((int)entry[2]) == 0)
                    {
                        count++;
                    }
                }
                else
                {
                    if (!(entry[1] >= 0 && GameBit_Get((int)entry[1]) != 0))
                    {
                        if (entry[2] < 0 || GameBit_Get((int)entry[2]) == 0)
                        {
                            count++;
                        }
                    }
                }
            }
            entry += 8;
        }
    }
    else
    {
        mask = gTrickyHudItemMask;
        if (mask > 0)
        {
            int i = 0;
            while (arr[i] > -1)
            {
                if (mask != -1 && (mask & arr[i]) != 0)
                {
                    count++;
                }
                i += 8;
            }
        }
    }
    return count;
}
