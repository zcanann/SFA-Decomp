#include "ghidra_import.h"
#include "main/dll/FRONT/frontend_control.h"

extern u32 getButtonsHeld(int port);
extern u32 getButtonsJustPressed(int port);
extern void Sfx_PlayFromObject(int sfx, int id);
extern void drawTexture(void *tex, int p2, f32 x, f32 y, int alpha);
extern void gameTextSetColor(u8 r, u8 g, u8 b, u8 a);
extern void gameTextShowStr(void *str, int id, int p3, int p4);
extern int sprintf(char *buf, const char *fmt, ...);

extern u8 lbl_803DD6BC;
extern u8 lbl_803DD6BD;
extern u8 lbl_803DD6BE;
extern s8 lbl_803DD6A4;
extern u8 lbl_803DD6A5;
extern int lbl_803DD6A8;
extern int lbl_803DD6B0;
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
 * Function: fn_80119C20
 * EN v1.0 Address: 0x80119C20
 * EN v1.0 Size: 436b
 */
#pragma peephole off
#pragma scheduling off
void fn_80119C20(void)
{
    u32 held;
    u32 pressed;
    u32 nibbles;

    if (lbl_803DD6BC != 0 || lbl_803DD6BD != 0) {
        u8 inc = lbl_803DD6BE + 1;
        lbl_803DD6BE = inc;
        if (inc > 0xF) {
            lbl_803DD6BC = 0;
            lbl_803DD6BD = 0;
            lbl_803DD6BE = 0;
        }
    }
    held = getButtonsHeld(0);
    if ((held & 0x10) == 0) return;

    if (lbl_803DD6BD == 0) {
        pressed = (u16)getButtonsJustPressed(0);
        nibbles = (int)(pressed & 0xF000) >> 8;
        nibbles |= (pressed & 0xF00) << 4;
        nibbles |= (pressed & 0xF) << 8;
        nibbles |= (int)(pressed & 0xF0) >> 4;
        if ((int)(nibbles & lbl_8031A814[lbl_803DD6BC]) != 0) {
            lbl_803DD6BC = lbl_803DD6BC + 1;
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
        nibbles = (int)(pressed & 0xF000) >> 8;
        nibbles |= (pressed & 0xF00) << 4;
        nibbles |= (pressed & 0xF) << 8;
        nibbles |= (int)(pressed & 0xF0) >> 4;
        if ((int)(nibbles & lbl_8031A820[lbl_803DD6BD]) != 0) {
            lbl_803DD6BD = lbl_803DD6BD + 1;
            lbl_803DD6BE = 0;
        }
        if (lbl_803DD6BD == 5) {
            *(u8 *)(lbl_803DD6B0 + (int)lbl_803DD6A4 * 0x24 + 0x21) = 5;
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
    gameTextShowStr((void *)(lbl_803DD6B0 + (int)lbl_803DD6A4 * 0x24), 0x41, 0, 0);

    sprintf(buf, sFrontendCompletionPercentFormat,
            (u32) * (u8 *)(lbl_803DD6B0 + (int)lbl_803DD6A4 * 0x24 + 4));
    gameTextShowStr(buf, 0x42, 0, 0);

    {
        u32 secs = *(u32 *)(lbl_803DD6B0 + (int)lbl_803DD6A4 * 0x24 + 8);
        u32 mins = secs / 0xe10;
        u32 rem = secs - mins * 0xe10;
        u32 m_in_h = rem / 0x3c;
        u32 s_in_m = rem - m_in_h * 0x3c;
        sprintf(buf, sFrontendTimeFormat, (u32)(u8)mins, (u32)(u8)m_in_h, (u32)(u8)s_in_m);
        gameTextShowStr(buf, 0x43, 0, 0);
    }

    sprintf(buf, sFrontendSingleDigitFormat,
            (u32) * (u8 *)(lbl_803DD6B0 + (int)lbl_803DD6A4 * 0x24 + 6));
    gameTextShowStr(buf, 0x44, 0, 0);

    sprintf(buf, sFrontendSingleDigitFormat,
            (u32) * (u8 *)(lbl_803DD6B0 + (int)lbl_803DD6A4 * 0x24 + 5));
    gameTextShowStr(buf, 0x45, 0, 0);
}
#pragma scheduling reset
#pragma peephole reset
