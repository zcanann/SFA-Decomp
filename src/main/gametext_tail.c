#include "main/audio/sfx.h"
#include "main/camera.h"
#include "main/frame_timing.h"
#include "main/gametext_api.h"
#include "main/gametext_box_api.h"
#include "main/gametext_command_api.h"
#include "main/gametext_show_api.h"
#include "main/gametext_show_str_api.h"
#include "main/gametext_task_api.h"
#include "main/gametext_internal.h"
#include "main/gametext_shared_internal.h"
#include "main/mm.h"
#include "main/rcp_dolphin_api.h"
#include "main/textrender_api.h"
#include "main/audio/sfx_trigger_ids.h"

/* In-string formatting control codes (Unicode PUA). */
#define TEXT_CTRL_SCALE 0xf8f4
#define TEXT_CTRL_FONT  0xf8f7

/* Language ids; order fixed by sLanguageNameTable[] below. */
#define LANGUAGE_ENGLISH  0
#define LANGUAGE_FRENCH   1
#define LANGUAGE_GERMAN   2
#define LANGUAGE_ITALIAN  3
#define LANGUAGE_JAPANESE 4
#define LANGUAGE_SPANISH  5

int isSpace(u32 c);

void gameTextMeasureFn_800163c4(char* str, int boxIdx, int x, int y, int* outMaxX, int* outMaxY, int* outMinX,
                                int* outMinY)
{
    TextSlot* box = (TextSlot*)gTextBoxes + boxIdx;
    s16 savedX = box->f18;
    s16 savedY = box->f1a;
    lbl_803DC9BC = 1;
    lbl_803DC9B0 = 0x7FFFFFFF;
    lbl_803DC9AC = 0;
    lbl_803DC9B8 = 0x7FFFFFFF;
    lbl_803DC9B4 = 0;
    box->f18 = x;
    box->f1a = y;
    gameTextRenderStrs(str, boxIdx);
    lbl_803DC9BC = 0;
    if (outMinX != NULL)
    {
        *outMinX = lbl_803DC9B8 >> 2;
    }
    if (outMinY != NULL)
    {
        *outMinY = lbl_803DC9B4 >> 2;
    }
    if (outMaxX != NULL)
    {
        *outMaxX = lbl_803DC9B0 >> 2;
    }
    if (outMaxY != NULL)
    {
        *outMaxY = lbl_803DC9AC >> 2;
    }
    box->f18 = savedX;
    box->f1a = savedY;
}

void gameTextMeasureStringBounds(char* str, int boxIdx, int* outMaxX, int* outMaxY, int* outMinX, int* outMinY)
{
    TextSlot* box = (TextSlot*)gTextBoxes + boxIdx;
    s16 savedX = box->f18;
    s16 savedY = box->f1a;
    lbl_803DC9BC = 1;
    lbl_803DC9B0 = 0x7FFFFFFF;
    lbl_803DC9AC = 0;
    lbl_803DC9B8 = 0x7FFFFFFF;
    lbl_803DC9B4 = 0;
    gameTextRenderStrs(str, boxIdx);
    lbl_803DC9BC = 0;
    if (outMinX != NULL)
    {
        *outMinX = lbl_803DC9B8 >> 2;
    }
    if (outMinY != NULL)
    {
        *outMinY = lbl_803DC9B4 >> 2;
    }
    if (outMaxX != NULL)
    {
        *outMaxX = lbl_803DC9B0 >> 2;
    }
    if (outMaxY != NULL)
    {
        *outMaxY = lbl_803DC9AC >> 2;
    }
    box->f18 = savedX;
    box->f1a = savedY;
}

void gameTextFn_8001658c(int a, int b, int c)
{
    GameTextDef* def = (GameTextDef*)gameTextGet(a);
    TextSlot* slot;
    u8 save7 = lbl_803DC9A7;
    u8 save6 = lbl_803DC9A6;
    u8 save5 = lbl_803DC9A5;
    u8 save4 = lbl_803DC9A4;
    int i;

    lbl_803DC9C0 = 1;
    if (gCurTextBox != NULL)
    {
        slot = gCurTextBox;
    }
    else if (def->slotHint == 255)
    {
        slot = (TextSlot*)gTextBoxes + 2;
    }
    else
    {
        slot = (TextSlot*)gTextBoxes + def->slotHint;
    }

    if ((u8*)slot == gTextBoxes + 0x10a0)
    {
        lbl_803DC9A7 = 255;
        lbl_803DC9A6 = 255;
        lbl_803DC9A5 = 255;
        lbl_803DC9A4 = 255;
    }

    if (def->alignH == 0)
    {
        slot->f12 = slot->f10;
    }
    slot->f18 = b;
    slot->f1a = c;

    if (lbl_803DC9BC == 0)
    {
        int mode;
        if (def->alignV == 0)
        {
            mode = slot->f11;
        }
        else
        {
            mode = def->alignV;
        }
        if (mode == 2 || mode == 3)
        {
            int maxX, maxY, minX, minY;
            int v;
            gameTextMeasureById(a, b, c, &maxX, &maxY, &minX, &minY);
            v = slot->f0a - (minY - minX);
            if (mode == 2)
            {
                slot->f1a = (s16)(v / 2);
            }
            else
            {
                slot->f1a = v;
            }
        }
    }

    if (lbl_803DC9BC == 0)
    {
        gameTextDrawBox(def, 0, slot);
    }
    if (gameTextDrawFunc != NULL)
    {
        gxSetScissorRect(0, 0, 0, 0, 640, 480);
    }
    else
    {
        if (slot->f14 < 0)
        {
            slot->f14 = 0;
        }
        if (slot->f16 < 0)
        {
            slot->f16 = 0;
        }
        if (lbl_803DC9BC == 0)
        {
            gxSetScissorRect(0, 0, slot->f14, slot->f16, slot->f14 + slot->f08, slot->f16 + slot->f0a);
        }
    }

    i = 0;
    for (; i < def->count; i++)
    {
        gameTextRenderStrs(def->strings[i], slot - (TextSlot*)gTextBoxes);
    }

    lbl_803DC9C0 = 0;
    if (lbl_803DC9BC == 0)
    {
        Camera_ApplyCurrentViewport(0);
    }
    lbl_803DC9A7 = save7;
    lbl_803DC9A6 = save6;
    lbl_803DC9A5 = save5;
    lbl_803DC9A4 = save4;
}

void gameTextFn_80016810(int a, int b, int c)
{
    int i;
    GameTextSlot* e;
    if (gameTextDrawFunc != NULL)
    {
        gameTextFn_8001658c(a, b, c);
    }
    else
    {
        i = gGameTextCommandCount++;
        e = &gGameTextCommandSlots[i];
        e->opcode = 2;
        e->arg0 = a;
        e->arg1 = b;
        e->arg2 = c;
    }
}

void gameTextShow(int a)
{
    int i;
    GameTextSlot* e;
    if (gameTextDrawFunc != NULL)
    {
        gameTextFn_8001658c(a, 0, 0);
    }
    else
    {
        i = gGameTextCommandCount++;
        e = &gGameTextCommandSlots[i];
        e->opcode = 2;
        e->arg0 = a;
        e->arg1 = 0;
        e->arg2 = 0;
    }
}

void textDisplayFn_800168dc(int textId, TextDisplayState* state)
{
    GameTextDef* def;
    s32 charCount;
    int byteOffset;
    char* lineStr;
    int special;
    u32 ch;
    int charLen;
    int glyphsRemaining;
    int glyphParamCount;
    SpecialGlyph* glyph;
    u8* defAddress;

    if (gameTextFonts->mode == 1)
    {
        return;
    }
    def = gameTextGet(textId);
    defAddress = (u8*)def;
    special = 0;
    if (defAddress >= lbl_803399C0 && defAddress < lbl_803399C0 + 0x60)
    {
        special = 1;
    }
    if (special)
    {
        state->f8 = 1;
        return;
    }
    lineStr = def->strings[state->charIndex];
    charCount = 0;
    byteOffset = charCount;
    if (lineStr == NULL)
    {
        charCount = 0;
    }
    else
    {
        while ((ch = utf8GetNextChar((u8*)(lineStr + byteOffset), &charLen)) != 0)
        {
            byteOffset += charLen;
            if (ch >= 0xe000 && ch <= 0xf8ff)
            {
                glyph = lbl_802C86F0;
                for (glyphsRemaining = 46;
                     glyphsRemaining-- != 0 || (glyphParamCount = 0, 0);)
                {
                    if (glyph->key == ch)
                    {
                        glyphParamCount = glyph->val;
                        break;
                    }
                    glyph++;
                }
                byteOffset += glyphParamCount * 2;
            }
            else
            {
                charCount++;
            }
        }
    }
    if (state->active == 0)
    {
        lbl_803DC998 = 0;
        lbl_803DC994 = lbl_803DE700;
        state->f10 = def->count;
        state->f8 = 0;
        state->active = 1;
    }
    if (lbl_803DE700 == lbl_803DC994)
    {
        Sfx_PlayFromObject(0, SFXTRIG_clock_loop);
    }
    lbl_803DC99C = 1;
    lbl_803DC998 = 0;
    lbl_803DC994 = timeDelta * lbl_803DB3D0 + lbl_803DC994;
    if (lbl_803DC994 >= (f32)(charCount - 2))
    {
        Sfx_StopFromObject(0, SFXTRIG_clock_loop);
    }
    if (state->fC != 0)
    {
        if (lbl_803DC994 < charCount)
        {
            lbl_803DC994 = charCount;
        }
        else
        {
            for (;;)
            {
                if (state->fC > 0)
                {
                    state->charIndex++;
                }
                else
                {
                    state->charIndex--;
                }
                if (state->charIndex < def->count && (u8)def->strings[state->charIndex][0] == 0)
                {
                    continue;
                }
                break;
            }
            if (state->charIndex < 0)
            {
                state->charIndex = 0;
            }
            else if (state->charIndex >= def->count)
            {
                state->charIndex = def->count - 1;
            }
            else
            {
                lbl_803DC994 = lbl_803DE700;
            }
            if (state->charIndex < 0)
            {
                state->charIndex = 0;
            }
            if (state->charIndex == def->count - 1 && (state->fC = 1) != 0 &&
                lbl_803DC994 >= charCount)
            {
                state->f8 = 1;
            }
            else
            {
                state->f8 = 0;
            }
            state->fC = 0;
        }
    }
    gameTextRenderStrs(def->strings[state->charIndex], 0x7c);
}

void gameTextFn_80016c18(int a, int b)
{
    int i = gGameTextCommandCount++;
    GameTextSlot* e = &gGameTextCommandSlots[i];
    e->opcode = 1;
    e->arg0 = a;
    e->arg1 = b;
}

static inline int gameTextCtrlCharLen(u32 c)
{
    SpecialGlyph* p = lbl_802C86F0;
    int i = 46;
    while (i--)
    {
        if (p->key == c)
        {
            return p->val;
        }
        p++;
    }
    return 0;
}

static inline MeasGlyph* gameTextFindGlyph(u32 ch, int langIdx)
{
    MeasGlyph* g;
    int cnt;

    g = gameTextFonts->glyphs;
    cnt = gameTextFonts->glyphCount;
    while (cnt-- != 0)
    {
        if (g->key == ch && g->lang == langIdx)
        {
            return g;
        }
        g++;
    }
    return NULL;
}

void gameTextFreePhrase(int* p)
{
    p[0] = 0;
    p[1] = 0;
    p[2] = 0;
    p[3] = 0;
    if (((void**)p)[5] != NULL)
    {
        mm_free(((void**)p)[5]);
        ((void**)p)[5] = NULL;
    }
}
char** textMeasureFn_80016c9c(char* str, f32 width, f32 height, int* outCount, f32* outLineH)
{
    int cursor;
    int* boundary;
    int langIdx;
    FontSizeEntry* sizeEntry;
    int lineOff;
    int* currentBoundary;
    int lineCount;
    char** lines;
    int breakPos;
    int haveSpace;
    int charPos;
    char* src;
    u8* encodedText;
    int lineIdx;
    char* dst;
    int lineStarts[32];
    int params[8];
    f32 penX;
    int charLen;
    int index;
    int previousCharLen;
    u32 ch;
    char* clearPos;
    lineCount = 0;
    lineOff = 0;
    cursor = 0;
    breakPos = 0;
    haveSpace = 0;
    penX = lbl_803DE704;
    if (gameTextCharset == 2)
    {
        index = 6;
    }
    else
    {
        index = sLanguageNameTable[curLanguage].sizeIdx;
    }
    langIdx = index;
    sizeEntry = &lbl_802C8680[index];

    *outCount = 0;
    if (outLineH != NULL)
    {
        *outLineH = (f32)(u32)sizeEntry->lineHeight * height;
    }
    if (str == NULL)
    {
        return 0;
    }
    encodedText = (u8*)str;
    if (lbl_803DC9AA != 0 || lbl_803DC9A8 != 0)
    {
        width = (f32)(u32)lbl_803DC9AA;
    }

    lineStarts[0] = 0;
    boundary = lineStarts;
    currentBoundary = boundary;

    while ((ch = utf8GetNextChar(encodedText + cursor, &charLen)) != 0)
    {
        cursor += charLen;
        if (ch == 0x20)
        {
            breakPos = cursor;
            haveSpace = 1;
        }
        if (ch >= 0xe000 && ch <= 0xf8ff)
        {
            int parameterCount;
            int remainingSpecials;
            SpecialGlyph* specialGlyph = lbl_802C86F0;
            int updatesLineHeight;
            for (remainingSpecials = 46;
                 remainingSpecials-- != 0 || (parameterCount = 0, 0);)
            {
                if (specialGlyph->key == ch)
                {
                    parameterCount = specialGlyph->val;
                    break;
                }
                specialGlyph++;
            }
            for (index = 0; index < parameterCount; index++)
            {
                int parameterHigh = encodedText[cursor++];
                int parameterLow = encodedText[cursor++];
                params[index] = (parameterHigh << 8) | parameterLow;
            }
            updatesLineHeight = 1;
            switch (ch)
            {
            case TEXT_CTRL_SCALE:
                height = (f32)params[0] * lbl_803DE708;
                break;
            case TEXT_CTRL_FONT:
                langIdx = params[0];
                sizeEntry = &lbl_802C8680[langIdx];
                break;
            default:
                updatesLineHeight = 0;
            }
            if (updatesLineHeight != 0 && langIdx != 5)
            {
                f32 lineHeight = (f32)(u32)sizeEntry->lineHeight * height;
                if (outLineH != NULL && lineHeight > *outLineH)
                {
                    *outLineH = lineHeight;
                }
            }
        }
        else
        {
            MeasGlyph* glyphEntry = gameTextFonts->glyphs;
            MeasGlyph* glyph;
            int glyphsRemaining;
            for (glyphsRemaining = gameTextFonts->glyphCount;
                 glyphsRemaining-- != 0 || (glyph = NULL, 0); glyphEntry++)
            {
                if (glyphEntry->key == ch && glyphEntry->lang == langIdx)
                {
                    glyph = glyphEntry;
                    break;
                }
            }
            if (glyph != NULL)
            {
                int glyphAdvance = (glyph->width + glyph->offsetX) + glyph->advanceX;
                penX += height * (f32)glyphAdvance;
                if (penX >= width)
                {
                    if (haveSpace == 0)
                    {
                        breakPos = cursor - charLen;
                    }
                    currentBoundary++;
                    lineCount++;
                    *(int*)((char*)lineStarts + (lineOff += 4)) = breakPos;
                    if (lineCount > 1 && currentBoundary[0] == currentBoundary[-1])
                    {
                        return 0;
                    }
                    if (lineCount >= 0x1e)
                    {
                        return 0;
                    }
                    penX = lbl_803DE704;
                    cursor = breakPos;
                    haveSpace = 0;
                }
            }
        }
    }

    lineOff = (lineCount = lineCount + 1) << 2;
    *(int*)((char*)lineStarts + lineOff) = cursor;
    *outCount = lineCount;
    if (cursor == 0)
    {
        return 0;
    }
    charLen = cursor + (lineCount + lineOff);
    if (outLineH != NULL)
    {
        lines = mmAllocateFromFBMemoryStore((int)lbl_803DB378, charLen);
    }
    else
    {
        lines = mmAlloc(charLen, 0, 0);
    }
    if (lines == NULL)
    {
        return 0;
    }
    clearPos = (char*)lines;
    index = charLen;
    while (index-- != 0)
    {
        *clearPos++ = 0;
    }

    dst = lines[0] = (char*)lines + lineOff;
    lineIdx = 0;
    charPos = 0;
    src = str;
    while (charPos < cursor)
    {
        *dst++ = *src;
        if (charPos == boundary[1])
        {
            char* lineEnd = --dst;
            do
            {
                int lookback = 6;
                do
                {
                    ch = utf8GetNextChar((u8*)(dst - lookback), &previousCharLen);
                    if (lookback != previousCharLen)
                    {
                        continue;
                    }
                    if (isSpace(ch))
                    {
                        int bytesToClear = previousCharLen;
                        while (bytesToClear-- != 0)
                        {
                            *--dst = 0;
                        }
                        break;
                    }
                    lineEnd[1] = lineEnd[0];
                    lineEnd[0] = 0;
                    dst = lineEnd + 1;
                    lines[lineIdx + 1] = dst++;
                    break;
                } while (--lookback > 0);
            } while (dst <= lineEnd);
            boundary++;
            lineIdx++;
        }
        charPos++;
        src++;
    }
    *dst = 0;
    return lines;
}

void* gameTextGetBox(int box)
{
    return &gTextBoxes[box * 0x20];
}

void* gameTextGetCurBox(void)
{
    return gCurTextBox;
}
