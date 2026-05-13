#include "ghidra_import.h"
#include "main/dll/FRONT/frontend_control.h"

extern u32 getButtonsHeld(int port);
extern u32 getButtonsJustPressed(int port);
extern void Sfx_PlayFromObject(int sfx, int id);
extern void drawTexture(void *tex, int p2, f32 x, f32 y, int alpha);
extern void gameTextSetColor(int r, int g, int b, int a);
extern void gameTextShowStr(void *str, int id, int p3, int p4);
extern int sprintf(char *buf, const char *fmt, ...);

typedef struct FrontendSaveSlot {
    char name[4];
    u8 completionPercent;
    u8 magicCount;
    u8 lifeCount;
    u8 pad07;
    u32 playTimeSeconds;
    u8 pad0C[0x21 - 0x0C];
    u8 cheatFlag;
    u8 pad22[0x24 - 0x22];
} FrontendSaveSlot;

extern u8 lbl_803DD6BC;
extern u8 lbl_803DD6BD;
extern u8 lbl_803DD6BE;
extern s8 lbl_803DD6A4;
extern u8 lbl_803DD6A5;
extern FrontendSaveSlot *lbl_803DD6A8;
extern FrontendSaveSlot *lbl_803DD6B0;
extern u8 enableDebugText;
extern u16 lbl_8031A814[6];
extern u16 lbl_8031A820[6];
extern void *lbl_803A8680[4];
extern f32 lbl_803E1D58;
extern f32 lbl_803E1D5C;
extern f32 lbl_803E1D60;
extern char sFrontendTimeFormat[];
extern char sFrontendCompletionPercentFormat[];
extern char sFrontendSingleDigitFormat[];

/*
 * --INFO--
 *
 * Function: saveFileSelect_checkCheatCodes
 * EN v1.0 Address: 0x80119C20
 * EN v1.0 Size: 436b
 */
#pragma peephole off
#pragma scheduling off
void saveFileSelect_checkCheatCodes(void)
{
    u32 held;
    u32 pressed;
    u32 nibbles;
    u32 hi;
    u32 midHi;
    u32 low;
    u32 midLow;

    if (lbl_803DD6BC != 0 || lbl_803DD6BD != 0) {
        int inc = lbl_803DD6BE + 1;
        lbl_803DD6BE = inc;
        if ((u8)inc > 0xF) {
            lbl_803DD6BC = 0;
            lbl_803DD6BD = 0;
            lbl_803DD6BE = 0;
        }
    }
    held = getButtonsHeld(0);
    if ((held & 0x10) == 0) return;

    if (lbl_803DD6BD == 0) {
        pressed = (u16)getButtonsJustPressed(0);
        hi = (int)(pressed & 0xF000) >> 8;
        midHi = (pressed & 0xF00) << 4;
        low = (pressed & 0xF) << 8;
        midLow = (int)(pressed & 0xF0) >> 4;
        nibbles = hi | (midHi | (low | midLow));
        if ((int)(nibbles & lbl_8031A814[lbl_803DD6BC]) != 0) {
            lbl_803DD6BC++;
            lbl_803DD6BE = 0;
        }
        if (lbl_803DD6BC == 5) {
            enableDebugText = 1;
            Sfx_PlayFromObject(0, 0x58);
        }
    }
    if (lbl_803DD6BC != 0) return;

    {
        pressed = (u16)getButtonsJustPressed(0);
        hi = (int)(pressed & 0xF000) >> 8;
        midHi = (pressed & 0xF00) << 4;
        low = (pressed & 0xF) << 8;
        midLow = (int)(pressed & 0xF0) >> 4;
        nibbles = hi | (midHi | (low | midLow));
        if ((int)(nibbles & lbl_8031A820[lbl_803DD6BD]) != 0) {
            lbl_803DD6BD++;
            lbl_803DD6BE = 0;
        }
        if (lbl_803DD6BD == 5) {
            lbl_803DD6B0[(int)lbl_803DD6A4].cheatFlag = 5;
            lbl_803DD6A5 = 1;
            Sfx_PlayFromObject(0, 0x58);
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: saveSelect_drawText
 * EN v1.0 Address: 0x80119DD4
 * EN v1.0 Size: 472b
 */
#pragma peephole off
#pragma scheduling off
void saveSelect_drawText(int param_1, int param_2)
{
    char buf[20];

    drawTexture(lbl_803A8680[1], param_2, lbl_803E1D58, lbl_803E1D5C, 0x100);
    drawTexture(lbl_803A8680[2], param_2, lbl_803E1D60, lbl_803E1D5C, 0x100);
    gameTextSetColor(0xff, 0xff, 0xff, param_2);

    lbl_803DD6B0 = lbl_803DD6A8;
    gameTextShowStr(&lbl_803DD6B0[(int)lbl_803DD6A4], 0x41, 0, 0);

    sprintf(buf, sFrontendCompletionPercentFormat,
            (u32)lbl_803DD6B0[(int)lbl_803DD6A4].completionPercent);
    gameTextShowStr(buf, 0x42, 0, 0);

    {
        u32 secs = lbl_803DD6B0[(int)lbl_803DD6A4].playTimeSeconds;
        u32 mins = secs / 0xe10;
        int rem = secs - mins * 0xe10;
        int m_in_h = rem / 0x3c;
        int s_in_m = rem - m_in_h * 0x3c;
        sprintf(buf, sFrontendTimeFormat, mins, (u32)(u8)m_in_h, (u32)(u8)s_in_m);
        gameTextShowStr(buf, 0x43, 0, 0);
    }

    sprintf(buf, sFrontendSingleDigitFormat, (u32)lbl_803DD6B0[(int)lbl_803DD6A4].lifeCount);
    gameTextShowStr(buf, 0x44, 0, 0);

    sprintf(buf, sFrontendSingleDigitFormat, (u32)lbl_803DD6B0[(int)lbl_803DD6A4].magicCount);
    gameTextShowStr(buf, 0x45, 0, 0);
}
#pragma scheduling reset
#pragma peephole reset
