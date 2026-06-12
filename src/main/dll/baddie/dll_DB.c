#include "main/dll/baddie/dll_DB.h"

extern uint GameBit_Get(int eventId);
extern u32 randomGetRange(int min, int max);
extern int FUN_801244a4();
extern undefined4 FUN_8012dca8();
extern undefined8 FUN_8012e050();
extern undefined8 FUN_8012e2a4();
extern undefined4 FUN_8012ed00();

extern undefined4 DAT_8031c22c;
extern undefined4 DAT_803a98d8;
extern undefined4 DAT_803de3fe;
extern undefined4 DAT_803de413;
extern undefined4 DAT_803de445;

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
extern u8 lbl_803A87F0[];
extern void gameUiResetMenuState(void);
extern void* lbl_803DD7C8;
extern s16 gTrickyHudCachedIconIndex;
extern void* gTrickyHudCachedIconTexture;
extern void textureFree(void* p);

#pragma scheduling off
#pragma peephole off
void textureFreeFn_8012fcec(void)
{
    u8 i;

    gameUiResetMenuState();
    for (i = 0; i < 64; i++)
    {
        if (*(void**)(lbl_803A87F0 + 2504 + i * 4) != NULL)
        {
            textureFree(*(void**)(lbl_803A87F0 + 2504 + i * 4));
            *(void**)(lbl_803A87F0 + 2504 + i * 4) = NULL;
        }
        *(s16*)(lbl_803A87F0 + 2376 + i * 2) = -1;
        lbl_803A87F0[1096 + i] = 1;
    }
    if (lbl_803DD7C8 != NULL)
    {
        textureFree(lbl_803DD7C8);
        lbl_803DD7C8 = NULL;
    }
    if (gTrickyHudCachedIconTexture != NULL)
    {
        textureFree(gTrickyHudCachedIconTexture);
    }
    gTrickyHudCachedIconIndex = -1;
    gTrickyHudCachedIconTexture = NULL;
}
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
void FUN_8012fdac(undefined8 param_1, double param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  int param_9)
{
    int iVar1;
    int iVar2;
    short sVar3;
    uint uVar4;
    char cVar5;

    iVar2 = FUN_801244a4(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
    sVar3 = (&DAT_8031c22c)[param_9 * 8];
    uVar4 = 0;
    cVar5 = '\x01';
    while (true)
    {
        if (iVar2 << 1 <= (int)(uVar4 & 0xff))
        {
            return;
        }
        iVar1 = (int)sVar3;
        if (((&DAT_803a98d8)[iVar1] != '\0') && ((cVar5 != '\0' || (iVar2 <= (int)(uVar4 & 0xff)))))
            break;
        sVar3 = sVar3 + 1;
        if (iVar2 <= sVar3)
        {
            sVar3 = 0;
        }
        uVar4 = uVar4 + 1;
        cVar5 = (&DAT_803a98d8)[iVar1];
    }
    (&DAT_8031c22c)[param_9 * 8] = sVar3;
    return;
}

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
undefined4
FUN_8012fe70(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8)
{
    undefined8 uVar1;

    if (DAT_803de445 != '\0')
    {
        if (DAT_803de3fe != '\0')
        {
            FUN_8012dca8(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
        }
        uVar1 = FUN_8012e050();
        if (DAT_803de413 != '\0')
        {
            uVar1 = FUN_8012e2a4(uVar1, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
        }
        FUN_8012ed00(uVar1, param_2, param_3, param_4, param_5, param_6, param_7, param_8);
    }
    return 0;
}


/* ===== EN v1.0 retargeted leaves ========================================= */

extern u8 pauseDisabled;
extern u8 pauseMenuFrameCounter;
extern s16 cMenuFadeCounter;
extern s8 lbl_803DD8F0;
extern s16 lbl_803DD8F2;
extern s8 lbl_803DD8F4;
extern s8 lbl_803DD8F5;
extern s8 lbl_803DD8E8;
extern u8 linkFlag_803dd8f8;
extern u8 linkIsRotated;
extern s16 linkItemOpacity;
extern s16 linkCount_803dd90e;
extern s8 linkSelected;
extern u8 linkTextures[0x30];
extern int getScreenResolution(void);
extern void* textureLoadAsset(int id);
extern void* hudTextures[];
extern s16 gHudTextureIds[];
extern u8 lbl_803A9398[];
extern s8 lbl_803DD896;
extern s16 lbl_803DD894;
extern s16 lbl_803DD8C2;
extern u8 lbl_803DD8B8;
extern int lbl_803DD744;
extern int lbl_803DD740;
extern void* lbl_803DD8C4;
extern int lbl_803DD82C;
extern int lbl_803DD828;
extern f32 lbl_803E1E3C;
extern s16 yButtonState;
extern int airMeter;

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


void Pause_SetDisabled(u8 v) { pauseDisabled = v; }
void Pause_ResetMenuFrameCounter(void) { pauseMenuFrameCounter = 60; }
void CMenu_SetFadeCounter(s16 v) { cMenuFadeCounter = v; }
s32 Menu_func0B(void) { return lbl_803DD8F0; }
#pragma peephole off
void Menu_func0A(int v) { lbl_803DD8E8 = (s8)v; }
#pragma peephole reset
void Menu_func09_nop(void)
{
}
#pragma peephole off
void Menu_func07(int v) { lbl_803DD8F4 = (s8)v; }
#pragma peephole reset
#pragma scheduling off
#pragma peephole off
void Menu_func03(int v)
{
    lbl_803DD8F2 = (s16)v;
    lbl_803DD8F0 = 0;
    lbl_803DD8F4 = -1;
}
#pragma peephole reset
#pragma scheduling reset
void Menu_release(void)
{
}

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
void GameUI_initialise(void)
{
    int res;
    int height;
    int width;
    int i;
    void* p;

    lbl_803DD896 = -1;
    lbl_803DD894 = -1;
    lbl_803DD8C2 = -1;
    lbl_803DD8B8 = 0;
    gTrickyHudCachedIconIndex = -1;
    res = getScreenResolution();
    lbl_803DD744 = res;
    height = res >> 16;
    lbl_803DD740 = height;
    width = res & 0xffff;
    lbl_803DD744 = width;
    lbl_803DD744 = width - 320;
    lbl_803DD740 = height - 240;
    for (i = 0; i < 102; i++)
    {
        hudTextures[i] = textureLoadAsset(gHudTextureIds[i]);
    }
    p = textureLoadAsset(1280);
    lbl_803DD8C4 = p;
    *(short*)((char*)p + 20) = 40;
    lbl_803DD82C = 0x80000;
    lbl_803DD828 = 0;
    *(int*)(lbl_803A9398 + 4) = -1;
    *(short*)(lbl_803A9398 + 12) = 0;
    *(int*)(lbl_803A9398 + 0) = 0;
    *(float*)(lbl_803A9398 + 8) = lbl_803E1E3C;
    yButtonState = 0;
    airMeter = 0;
}
#pragma peephole reset
#pragma scheduling reset
extern int getHudHiddenFrameCount(void);
extern void padGetAnalogInput(int pad, s8* y, s8* x);
extern int getButtonsJustPressed(int pad);
extern f32 lbl_803DD8EC;
extern f32 lbl_803E21D8;
extern f32 timeDelta;
#pragma scheduling off
#pragma peephole off
int Menu_func08(int* sel)
{
    s8 yInput;
    s8 xInput;
    int input;
    f32 timer;

    if (getHudHiddenFrameCount() != 0)
    {
        return -1;
    }
    timer = lbl_803DD8EC + timeDelta;
    lbl_803DD8EC = timer;
    if (timer > lbl_803E21D8)
    {
        lbl_803DD8EC = timer - lbl_803E21D8;
    }
    padGetAnalogInput(0, &yInput, &xInput);
    if (xInput < 0)
    {
        *sel = *sel + 1;
    }
    else if (xInput > 0)
    {
        *sel = *sel - 1;
    }
    if (*sel < 0)
    {
        *sel = (s8)lbl_803DD8F0 - 1;
    }
    if (*sel >= (s8)lbl_803DD8F0)
    {
        *sel = 0;
    }
    if (lbl_803DD8E8 != 0)
    {
        input = getButtonsJustPressed(0);
        if (((input & 0x1100) != 0) && (GameBit_Get(1103) == 0))
        {
            return lbl_803DD8F5;
        }
        if ((input & 0x200) != 0)
        {
            return lbl_803DD8F4;
        }
    }
    lbl_803DD8E8 = 1;
    return -1;
}
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off
void Menu_func05(int arg1, int unused2, int arg3, int arg4)
{
    if (arg4 == (s32)lbl_803DD8F0)
    {
        lbl_803DD8F5 = (s8)arg1;
    }
    lbl_803DD8F2 = (s16)((s32)lbl_803DD8F2 + arg3);
    lbl_803DD8F0++;
}

void Menu_func06(int arg1, int unused2, int unused3, int arg4, int arg5)
{
    if (arg5 == (s32)lbl_803DD8F0)
    {
        lbl_803DD8F5 = (s8)arg1;
    }
    lbl_803DD8F2 = (s16)((s32)lbl_803DD8F2 + arg4);
    lbl_803DD8F0++;
}
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off
void Menu_func04(int unused, int v)
{
    getScreenResolution();
    lbl_803DD8F2 = (s16)v;
    lbl_803DD8F0 = 0;
    lbl_803DD8F4 = -1;
}
#pragma peephole reset
#pragma scheduling reset
void Menu_initialise(void)
{
    lbl_803DD8F0 = 0;
    lbl_803DD8F2 = 0;
    lbl_803DD8F4 = 0;
    lbl_803DD8F5 = 0;
    lbl_803DD8E8 = 0;
}
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
extern u8 lbl_803DD911;
#pragma scheduling off
#pragma peephole off
void linkDrawFn_801302c0(void)
{
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
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off
void linkDrawFn_80130484(void)
{
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
#pragma peephole reset
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off
void Link_func0F(void)
{
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
