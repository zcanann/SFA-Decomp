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

extern u8 saveFileSelect_debugCheatProgress;
extern u8 saveFileSelect_saveCheatProgress;
extern u8 saveFileSelect_cheatInputTimer;
extern s8 saveFileSelect_currentSlotIndex;
extern u8 saveFileSelect_saveDirty;
extern FrontendSaveSlot *saveFileSelect_saveSlotsBase;
extern FrontendSaveSlot *saveFileSelect_saveSlots;
extern u8 enableDebugText;
extern u16 saveFileSelect_debugCheatSequence[6];
extern u16 saveFileSelect_slotCheatSequence[6];
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

    if (saveFileSelect_debugCheatProgress != 0 || saveFileSelect_saveCheatProgress != 0) {
        int inc = saveFileSelect_cheatInputTimer + 1;
        saveFileSelect_cheatInputTimer = inc;
        if ((u8)inc > 0xF) {
            saveFileSelect_debugCheatProgress = 0;
            saveFileSelect_saveCheatProgress = 0;
            saveFileSelect_cheatInputTimer = 0;
        }
    }
    held = getButtonsHeld(0);
    if ((held & 0x10) == 0) return;

    if (saveFileSelect_saveCheatProgress == 0) {
        pressed = (u16)getButtonsJustPressed(0);
        hi = (int)(pressed & 0xF000) >> 8;
        midHi = (pressed & 0xF00) << 4;
        low = (pressed & 0xF) << 8;
        midLow = (int)(pressed & 0xF0) >> 4;
        nibbles = hi | (midHi | (low | midLow));
        if ((int)(nibbles & saveFileSelect_debugCheatSequence[saveFileSelect_debugCheatProgress]) != 0) {
            saveFileSelect_debugCheatProgress++;
            saveFileSelect_cheatInputTimer = 0;
        }
        if (saveFileSelect_debugCheatProgress == 5) {
            enableDebugText = 1;
            Sfx_PlayFromObject(0, 0x58);
        }
    }
    if (saveFileSelect_debugCheatProgress != 0) return;

    {
        pressed = (u16)getButtonsJustPressed(0);
        hi = (int)(pressed & 0xF000) >> 8;
        midHi = (pressed & 0xF00) << 4;
        low = (pressed & 0xF) << 8;
        midLow = (int)(pressed & 0xF0) >> 4;
        nibbles = hi | (midHi | (low | midLow));
        if ((int)(nibbles & saveFileSelect_slotCheatSequence[saveFileSelect_saveCheatProgress]) != 0) {
            saveFileSelect_saveCheatProgress++;
            saveFileSelect_cheatInputTimer = 0;
        }
        if (saveFileSelect_saveCheatProgress == 5) {
            saveFileSelect_saveSlots[(int)saveFileSelect_currentSlotIndex].cheatFlag = 5;
            saveFileSelect_saveDirty = 1;
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

    saveFileSelect_saveSlots = saveFileSelect_saveSlotsBase;
    gameTextShowStr(&saveFileSelect_saveSlots[(int)saveFileSelect_currentSlotIndex], 0x41, 0, 0);

    sprintf(buf, sFrontendCompletionPercentFormat,
            (u32)saveFileSelect_saveSlots[(int)saveFileSelect_currentSlotIndex].completionPercent);
    gameTextShowStr(buf, 0x42, 0, 0);

    {
        u32 secs = saveFileSelect_saveSlots[(int)saveFileSelect_currentSlotIndex].playTimeSeconds;
        u32 mins = secs / 0xe10;
        int rem = secs - mins * 0xe10;
        int m_in_h = rem / 0x3c;
        int s_in_m = rem - m_in_h * 0x3c;
        sprintf(buf, sFrontendTimeFormat, mins, (u32)(u8)m_in_h, (u32)(u8)s_in_m);
        gameTextShowStr(buf, 0x43, 0, 0);
    }

    sprintf(buf, sFrontendSingleDigitFormat, (u32)saveFileSelect_saveSlots[(int)saveFileSelect_currentSlotIndex].lifeCount);
    gameTextShowStr(buf, 0x44, 0, 0);

    sprintf(buf, sFrontendSingleDigitFormat, (u32)saveFileSelect_saveSlots[(int)saveFileSelect_currentSlotIndex].magicCount);
    gameTextShowStr(buf, 0x45, 0, 0);
}
#pragma scheduling reset
#pragma peephole reset
