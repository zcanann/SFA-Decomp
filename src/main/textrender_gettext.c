#include "main/gametext_api.h"
#include "main/gametext_shared_internal.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/printf.h"
#include "main/frame_timing.h"
#include "main/textrender_internal.h"
#include "main/rcp_dolphin_api.h"
#include "main/dll/dll_0015_save_settings.h"
#include "main/lightmap.h"
#include "main/textrender_api.h"

void* gameTextGetPhrase(int textId, int phraseIndex)
{
    char* strings;
    GameTextDef* entry;

    strings = gGameTextFontData;
    if (gameTextFonts->status != 2)
    {
        gGameTextBufferIndex += 1;
        if (gGameTextBufferIndex >= 8)
        {
            gGameTextBufferIndex = 0;
        }
        gGameTextLastEntry = sGameTextFallbackDefs + gGameTextBufferIndex * 0xc;
        gCurTextBuffer = (char*)*(int*)*(int**)(gGameTextLastEntry + 8);
        *(u16*)gGameTextLastEntry = 0xffff;
        gGameTextFallbackBuf = (f32*)(sGameTextFallbackBufSlots + gGameTextBufferIndex * 4);
        switch (gameTextFonts->status)
        {
        case 0:
            sprintf(gCurTextBuffer, strings + 0xec4);
            break;
        case 1:
            sprintf(gCurTextBuffer, strings + 0xed4);
            break;
        case 3:
            sprintf(gCurTextBuffer, strings + 0xee0);
            break;
        case 4:
            sprintf(gCurTextBuffer, strings + 0xef0);
            break;
        }
        return gGameTextLastEntry;
    }

    entry = gameTextGet(textId);
    if (entry->identifier == 0xffff)
    {
        gGameTextBufferIndex += 1;
        if (gGameTextBufferIndex >= 8)
        {
            gGameTextBufferIndex = 0;
        }
        gGameTextLastEntry = sGameTextFallbackDefs + gGameTextBufferIndex * 0xc;
        gCurTextBuffer = (char*)*(int*)*(int**)(gGameTextLastEntry + 8);
        *(u16*)gGameTextLastEntry = 0xffff;
        gGameTextFallbackBuf = (f32*)(sGameTextFallbackBufSlots + gGameTextBufferIndex * 4);
        sprintf(gCurTextBuffer, strings + 0xefc, textId,
                sMapDirectoryNameTable[curGameTextDir]);
        return gGameTextLastEntry;
    }

    if (phraseIndex >= entry->count)
    {
        gGameTextBufferIndex += 1;
        if (gGameTextBufferIndex >= 8)
        {
            gGameTextBufferIndex = 0;
        }
        gGameTextLastEntry = sGameTextFallbackDefs + gGameTextBufferIndex * 0xc;
        gCurTextBuffer = (char*)*(int*)*(int**)(gGameTextLastEntry + 8);
        *(u16*)gGameTextLastEntry = 0xffff;
        gGameTextFallbackBuf = (f32*)(sGameTextFallbackBufSlots + gGameTextBufferIndex * 4);
        sprintf(gCurTextBuffer, strings + 0xf10, textId, phraseIndex);
        return gGameTextLastEntry;
    }

    return entry->strings[phraseIndex];
}

void* gameTextGetStr(int textId)
{
    char* strings;
    GameTextDef* textEntry;

    strings = gGameTextFontData;
    if (gameTextFonts->status != 2)
    {
        gGameTextBufferIndex += 1;
        if (gGameTextBufferIndex >= 8)
        {
            gGameTextBufferIndex = 0;
        }
        gGameTextLastEntry = sGameTextFallbackDefs + gGameTextBufferIndex * 0xc;
        gCurTextBuffer = (char*)*(int*)*(int**)(gGameTextLastEntry + 8);
        *(u16*)gGameTextLastEntry = 0xffff;
        gGameTextFallbackBuf = (f32*)(sGameTextFallbackBufSlots + gGameTextBufferIndex * 4);
        switch (gameTextFonts->status)
        {
        case 0:
            sprintf(gCurTextBuffer, strings + 0xec4);
            break;
        case 1:
            sprintf(gCurTextBuffer, strings + 0xed4);
            break;
        case 3:
            sprintf(gCurTextBuffer, strings + 0xee0);
            break;
        case 4:
            sprintf(gCurTextBuffer, strings + 0xef0);
            break;
        }
        return gGameTextLastEntry;
    }
    textEntry = gameTextGet(textId);
    return *textEntry->strings;
}

void* gameTextGet(int textId)
{
    u8* gameTextBase;
    char* strings;
    TextFont* fonts;
    GameTextDef* entry;
    int count;
    int slotIndex;
    GameTextDef* cachedEntry;
    f32 zero;
    f32* cachedAlpha;
    u8* p;

    gameTextBase = gGameTextBase;
    strings = gGameTextFontData;
    fonts = gameTextFonts;

    if (fonts->status != 2)
    {
        gGameTextBufferIndex++;
        if (gGameTextBufferIndex >= 8)
        {
            gGameTextBufferIndex = 0;
        }
        p = gameTextBase + gGameTextBufferIndex * 0xc;
        gGameTextLastEntry = p + 0x40;
        gCurTextBuffer = (char*)*(int*)*(int**)(gGameTextLastEntry + 8);
        *(u16*)gGameTextLastEntry = 0xffff;
        p = gameTextBase + gGameTextBufferIndex * 4;
        gGameTextFallbackBuf = (f32*)(p + 0x20);

        switch (gameTextFonts->status)
        {
        case 0:
            sprintf(gCurTextBuffer, strings + 0xec4);
            break;
        case 1:
            sprintf(gCurTextBuffer, strings + 0xed4);
            break;
        case 3:
            sprintf(gCurTextBuffer, strings + 0xee0);
            break;
        case 4:
            sprintf(gCurTextBuffer, strings + 0xef0);
            break;
        }
        return gGameTextLastEntry;
    }

    entry = fonts->entries;
    count = fonts->entryCount;
    while (count != 0)
    {
        if (entry->identifier == textId)
        {
            return entry;
        }
        entry++;
        count--;
    }

    slotIndex = 8;
    cachedEntry = (GameTextDef*)(gameTextBase + 0xa0);
    while (cachedEntry--, slotIndex-- != 0)
    {
        if (cachedEntry->identifier == textId)
        {
            zero = lbl_803DE704;
            *(f32*)(gameTextBase + slotIndex * 4) = zero;
            cachedAlpha = (f32*)(gameTextBase + 0x20 + slotIndex * 4);
            if (zero < gGameTextFadeLimit)
            {
                f32 av = zero + timeDelta;
                *cachedAlpha = av;
                if (av >= gGameTextFadeLimit)
                {
                    sprintf((char*)*(int*)cachedEntry->strings, strings + 0xefc, textId,
                            sMapDirectoryNameTable[curGameTextDir]);
                }
            }
            return cachedEntry;
        }
    }

    gGameTextBufferIndex++;
    if (gGameTextBufferIndex >= 8)
    {
        gGameTextBufferIndex = 0;
    }
    p = gameTextBase + gGameTextBufferIndex * 0xc;
    gGameTextLastEntry = p + 0x40;
    gCurTextBuffer = (char*)*(int*)*(int**)(gGameTextLastEntry + 8);
    *(u16*)gGameTextLastEntry = 0xffff;
    p = gameTextBase + gGameTextBufferIndex * 4;
    gGameTextFallbackBuf = (f32*)(p + 0x20);
    sprintf(gCurTextBuffer, sGameTextBlankFormat, textId, sMapDirectoryNameTable[curGameTextDir]);
    *(u16*)gGameTextLastEntry = textId;
    *gGameTextFallbackBuf = lbl_803DE704;
    return gGameTextLastEntry;
}

void gameTextResetCursor(int flags)
{
    if (flags & 1)
    {
        gGameTextCursorX = 0;
        gGameTextCursorY = 0;
    }
    if (flags & 2)
    {
        GameTextCommand* p = &gGameTextCommandSlots[gGameTextCommandCount++].opcode;
        *p = GAMETEXT_COMMAND_RESET_CURSOR;
    }
}

void gameTextSetCursor(u16 x, u16 y, int flags)
{
    if (flags & 1)
    {
        gGameTextCursorX = x;
        gGameTextCursorY = y;
    }
    if (flags & 2)
    {
        int i = gGameTextCommandCount;
        GameTextSlot* cmd;
        gGameTextCommandCount = i + 1;
        cmd = &gGameTextCommandSlots[i];
        cmd->opcode = 0xa;
        cmd->arg0 = x;
        cmd->arg1 = y;
    }
}

void gameTextSetWindowStrPos(int idx, int x, int y)
{
    if (gameTextDrawFunc != NULL)
    {
        gTextBoxes[idx].cursorX = x;
        gTextBoxes[idx].cursorY = y;
    }
    else
    {
        int i = gGameTextCommandCount;
        GameTextSlot* cmd;
        gGameTextCommandCount = i + 1;
        cmd = &gGameTextCommandSlots[i];
        cmd->opcode = 4;
        cmd->arg0 = idx;
        cmd->arg1 = x;
        cmd->arg2 = y;
    }
}

void gameTextSetColor(u8 r, u8 g, u8 b, u8 a)
{
    if (gameTextDrawFunc != NULL)
    {
        gGameTextColorR = r;
        gGameTextColorG = g;
        gGameTextColorB = b;
        gGameTextColorA = a;
    }
    else
    {
        int i = gGameTextCommandCount;
        GameTextSlot* cmd;
        gGameTextCommandCount = i + 1;
        cmd = &gGameTextCommandSlots[i];
        cmd->opcode = 3;
        cmd->arg0 = r;
        cmd->arg1 = g;
        cmd->arg2 = b;
        cmd->arg3 = a;
    }
}
