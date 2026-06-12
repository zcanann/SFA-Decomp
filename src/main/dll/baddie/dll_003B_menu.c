#include "main/dll/baddie/dll_003B_menu.h"

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


void Pause_SetDisabled(u8 v);
void Pause_ResetMenuFrameCounter(void);
void CMenu_SetFadeCounter(s16 v);
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

void titleScreenFn_80130464(u8 v);
void setLinkNotRotated(void);
void setLinkIsRotated(void);
u8 Link_func0C(void);
void Link_func0A(int idx, int v);
s32 Link_func09(int idx);
void Link_setOpacity(u8 v);
#pragma peephole off
void Link_setSelected(int v);
#pragma peephole reset
s32 Link_getSelected(void);

/* Stubs added to align function set with v1.0 asm. Source had many Ghidra
 * FUN_xxx splits at wrong addresses; these stubs (no body yet) ensure the
 * asm symbol set is fully present so future hunters can fill bodies. */
#pragma scheduling off
#pragma peephole off
void GameUI_initialise(void);
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
u16 fn_80130124(void);
#pragma scheduling reset
extern void OSReport(const char* fmt, ...);
extern char lbl_8031C234[];
#pragma scheduling off
#pragma peephole off
void linkInitTextures(LinkMenuItemDB* item);
#pragma peephole reset
#pragma scheduling reset
extern int getCurLanguage(void);
extern u8 lbl_802C8680[];
extern u8 lbl_803DD911;
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
void Link_func0F(void);
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
void Link_copy(u8* srcArg);
#pragma scheduling reset
#pragma scheduling off
#pragma peephole off
void Link_func0B(u8* srcArg);
#pragma peephole reset
#pragma scheduling reset
