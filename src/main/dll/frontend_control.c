/*
 * frontend_control - save-file-select screen behaviour for the front end.
 *
 * saveFileSelect_checkCheatCodes() watches controller 0 while a button
 * (mask 0x10) is held and matches input against two nibble-packed button
 * sequences: a debug-text unlock sequence and a per-slot save cheat. Each
 * sequence is 5 entries long; a 16-frame input timer resets a partial
 * match. Completing the debug sequence sets enableDebugText; completing
 * the save sequence stamps cheatFlag=5 on the current save slot.
 *
 * saveSelect_drawText() renders the selected slot's summary: the two side
 * textures, the slot name, completion percent, formatted play time
 * (HH:MM:SS derived from playTimeSeconds), life count and magic count.
 */
#include "main/audio/sfx_ids.h"
#include "main/dll/FRONT/frontend_control.h"
#include "main/engine_shared.h"

extern void drawTexture(void* tex, f32 x, f32 y, int p2, int alpha);

extern u8 saveFileSelect_debugCheatProgress;
extern u8 saveFileSelect_saveCheatProgress;
extern u8 saveFileSelect_cheatInputTimer;
extern s8 saveFileSelect_currentSlotIndex;
extern u8 saveFileSelect_saveDirty;
extern FrontendSaveSlot* saveFileSelect_saveSlotsBase;
extern FrontendSaveSlot* saveFileSelect_saveSlots;
extern u8 enableDebugText;
extern u16 saveFileSelect_debugCheatSequence[6];
extern u16 saveFileSelect_slotCheatSequence[6];
extern void* lbl_803A8680[4];
extern f32 lbl_803E1D58;
extern f32 lbl_803E1D5C;
extern f32 lbl_803E1D60;
extern char sFrontendTimeFormat[];
__declspec(section ".sdata") extern char sFrontendCompletionPercentFormat[];
__declspec(section ".sdata") extern char sFrontendSingleDigitFormat[];

#define CHEAT_SEQUENCE_LEN 5
#define CHEAT_INPUT_TIMEOUT 0xF
#define SECONDS_PER_HOUR 3600
#define SECONDS_PER_MINUTE 60

#define PAD_TRIGGER_Z 0x10

void saveFileSelect_checkCheatCodes(void)
{
    u32 held;
    u32 pressed;
    u32 nibbles;
    u32 hi;
    u32 midHi;
    u32 low;
    u32 midLow;

    if (saveFileSelect_debugCheatProgress != 0 || saveFileSelect_saveCheatProgress != 0)
    {
        saveFileSelect_cheatInputTimer++;
        if (saveFileSelect_cheatInputTimer > CHEAT_INPUT_TIMEOUT)
        {
            saveFileSelect_debugCheatProgress = 0;
            saveFileSelect_saveCheatProgress = 0;
            saveFileSelect_cheatInputTimer = 0;
        }
    }
    held = getButtonsHeld(0);
    if ((held & PAD_TRIGGER_Z) == 0) return;

    if (saveFileSelect_saveCheatProgress == 0)
    {
        pressed = (u16)getButtonsJustPressed(0);
        hi = (int)(pressed & 0xF000) >> 8;
        midHi = (pressed & 0xF00) << 4;
        low = (pressed & 0xF) << 8;
        midLow = (int)(pressed & 0xF0) >> 4;
        nibbles = hi | (midHi | (low | midLow));
        if ((int)(nibbles & saveFileSelect_debugCheatSequence[saveFileSelect_debugCheatProgress]) != 0)
        {
            saveFileSelect_debugCheatProgress++;
            saveFileSelect_cheatInputTimer = 0;
        }
        if (saveFileSelect_debugCheatProgress == CHEAT_SEQUENCE_LEN)
        {
            enableDebugText = 1;
            Sfx_PlayFromObject(0, SFXen_waterblock_stop);
        }
    }
    if (saveFileSelect_debugCheatProgress != 0) return;

    pressed = (u16)getButtonsJustPressed(0);
    hi = (int)(pressed & 0xF000) >> 8;
    midHi = (pressed & 0xF00) << 4;
    low = (pressed & 0xF) << 8;
    midLow = (int)(pressed & 0xF0) >> 4;
    nibbles = hi | (midHi | (low | midLow));
    if ((int)(nibbles & saveFileSelect_slotCheatSequence[saveFileSelect_saveCheatProgress]) != 0)
    {
        saveFileSelect_saveCheatProgress++;
        saveFileSelect_cheatInputTimer = 0;
    }
    if (saveFileSelect_saveCheatProgress == CHEAT_SEQUENCE_LEN)
    {
        saveFileSelect_saveSlots[saveFileSelect_currentSlotIndex].cheatFlag = 5;
        saveFileSelect_saveDirty = 1;
        Sfx_PlayFromObject(0, SFXen_waterblock_stop);
    }
}

void saveSelect_drawText(int unused, int alpha)
{
    char buf[16];
    u32 secs;
    u32 hours;
    int rem;
    int minutes;
    int seconds;

    drawTexture(lbl_803A8680[1], lbl_803E1D58, lbl_803E1D5C, alpha, 0x100);
    drawTexture(lbl_803A8680[2], lbl_803E1D60, lbl_803E1D5C, alpha, 0x100);
    gameTextSetColor(0xff, 0xff, 0xff, alpha);

    saveFileSelect_saveSlots = saveFileSelect_saveSlotsBase; /* retail draw path resets the working slot pointer to the base */
    gameTextShowStr((char*)&saveFileSelect_saveSlots[saveFileSelect_currentSlotIndex], 0x41, 0, 0);

    sprintf(buf, sFrontendCompletionPercentFormat,
            saveFileSelect_saveSlots[saveFileSelect_currentSlotIndex].completionPercent);
    gameTextShowStr(buf, 0x42, 0, 0);

    secs = saveFileSelect_saveSlots[saveFileSelect_currentSlotIndex].playTimeSeconds;
    hours = secs / SECONDS_PER_HOUR;
    rem = secs - hours * SECONDS_PER_HOUR;
    minutes = rem / SECONDS_PER_MINUTE;
    minutes = (u8)minutes; /* truncation must persist into the seconds remainder below */
    seconds = rem - minutes * SECONDS_PER_MINUTE;
    sprintf(buf, sFrontendTimeFormat, hours, (u32)(u8)minutes, (u32)(u8)seconds);
    gameTextShowStr(buf, 0x43, 0, 0);

    sprintf(buf, sFrontendSingleDigitFormat,
            saveFileSelect_saveSlots[saveFileSelect_currentSlotIndex].lifeCount);
    gameTextShowStr(buf, 0x44, 0, 0);

    sprintf(buf, sFrontendSingleDigitFormat,
            saveFileSelect_saveSlots[saveFileSelect_currentSlotIndex].magicCount);
    gameTextShowStr(buf, 0x45, 0, 0);
}
