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

int isSpace(u32 c);

void gameTextMeasureFn_800163c4(char* str, int boxIdx, int x, int y, int* outMinX, int* outMaxX, int* outMinY,
                                int* outMaxY)
{
    TextSlot* box = (TextSlot*)gTextBoxes + boxIdx;
    s16 savedX = box->cursorX;
    s16 savedY = box->cursorY;
    gGameTextMeasureOnly = 1;
    gGameTextBoundsMinX = 0x7FFFFFFF;
    gGameTextBoundsMaxX = 0;
    gGameTextBoundsMinY = 0x7FFFFFFF;
    gGameTextBoundsMaxY = 0;
    box->cursorX = x;
    box->cursorY = y;
    gameTextRenderStrs(str, boxIdx);
    gGameTextMeasureOnly = 0;
    if (outMinY != NULL)
    {
        *outMinY = gGameTextBoundsMinY >> 2;
    }
    if (outMaxY != NULL)
    {
        *outMaxY = gGameTextBoundsMaxY >> 2;
    }
    if (outMinX != NULL)
    {
        *outMinX = gGameTextBoundsMinX >> 2;
    }
    if (outMaxX != NULL)
    {
        *outMaxX = gGameTextBoundsMaxX >> 2;
    }
    box->cursorX = savedX;
    box->cursorY = savedY;
}

void gameTextMeasureStringBounds(char* str, int boxIdx, int* outMinX, int* outMaxX, int* outMinY, int* outMaxY)
{
    TextSlot* box = (TextSlot*)gTextBoxes + boxIdx;
    s16 savedX = box->cursorX;
    s16 savedY = box->cursorY;
    gGameTextMeasureOnly = 1;
    gGameTextBoundsMinX = 0x7FFFFFFF;
    gGameTextBoundsMaxX = 0;
    gGameTextBoundsMinY = 0x7FFFFFFF;
    gGameTextBoundsMaxY = 0;
    gameTextRenderStrs(str, boxIdx);
    gGameTextMeasureOnly = 0;
    if (outMinY != NULL)
    {
        *outMinY = gGameTextBoundsMinY >> 2;
    }
    if (outMaxY != NULL)
    {
        *outMaxY = gGameTextBoundsMaxY >> 2;
    }
    if (outMinX != NULL)
    {
        *outMinX = gGameTextBoundsMinX >> 2;
    }
    if (outMaxX != NULL)
    {
        *outMaxX = gGameTextBoundsMaxX >> 2;
    }
    box->cursorX = savedX;
    box->cursorY = savedY;
}

void gameTextRenderById(int a, int b, int c)
{
    GameTextDef* def = (GameTextDef*)gameTextGet(a);
    TextSlot* slot;
    u8 save7 = gGameTextColorR;
    u8 save6 = gGameTextColorG;
    u8 save5 = gGameTextColorB;
    u8 save4 = gGameTextColorA;
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
        gGameTextColorR = 255;
        gGameTextColorG = 255;
        gGameTextColorB = 255;
        gGameTextColorA = 255;
    }

    if (def->alignH == 0)
    {
        slot->alignment = slot->alignH;
    }
    slot->cursorX = b;
    slot->cursorY = c;

    if (gGameTextMeasureOnly == 0)
    {
        int mode;
        if (def->alignV == 0)
        {
            mode = slot->alignV;
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
            v = slot->height - (minY - minX);
            if (mode == 2)
            {
                slot->cursorY = (s16)(v / 2);
            }
            else
            {
                slot->cursorY = v;
            }
        }
    }

    if (gGameTextMeasureOnly == 0)
    {
        gameTextDrawBox(def, 0, slot);
    }
    if (gameTextDrawFunc != NULL)
    {
        gxSetScissorRect(0, 0, 0, 0, 640, 480);
    }
    else
    {
        if (slot->x < 0)
        {
            slot->x = 0;
        }
        if (slot->y < 0)
        {
            slot->y = 0;
        }
        if (gGameTextMeasureOnly == 0)
        {
            gxSetScissorRect(0, 0, slot->x, slot->y, slot->x + slot->width, slot->y + slot->height);
        }
    }

    i = 0;
    for (; i < def->count; i++)
    {
        gameTextRenderStrs(def->strings[i], slot - (TextSlot*)gTextBoxes);
    }

    lbl_803DC9C0 = 0;
    if (gGameTextMeasureOnly == 0)
    {
        Camera_ApplyCurrentViewport(0);
    }
    gGameTextColorR = save7;
    gGameTextColorG = save6;
    gGameTextColorB = save5;
    gGameTextColorA = save4;
}

void gameTextShowAt(int a, int b, int c)
{
    int i;
    GameTextSlot* e;
    if (gameTextDrawFunc != NULL)
    {
        gameTextRenderById(a, b, c);
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
        gameTextRenderById(a, 0, 0);
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

static inline int gameTextCtrlCharLen(u32 c)
{
    SpecialGlyph* p = gGameTextCtrlCodeArgCounts;
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

void gameTextTickReveal(int textId, TextDisplayState* state)
{
    GameTextDef* def;
    s32 charCount;
    int byteOffset;
    char* lineStr;
    int special;
    u32 ch;
    int charLen;
    u8* defAddress;

    if (gameTextFonts->mode == 1)
    {
        return;
    }
    def = gameTextGet(textId);
    defAddress = (u8*)def;
    special = 0;
    if (defAddress >= sGameTextFallbackDefs && defAddress < sGameTextFallbackDefs + 0x60)
    {
        special = 1;
    }
    if (special)
    {
        state->f8 = 1;
        return;
    }
    lineStr = def->strings[state->charIndex];
    byteOffset = charCount = 0;
    if (lineStr == NULL)
    {
        charCount = byteOffset;
    }
    else
    {
        while ((ch = utf8GetNextChar((u8*)(lineStr + byteOffset), &charLen)) != 0)
        {
            byteOffset += charLen;
            if (ch >= 0xe000 && ch <= 0xf8ff)
            {
                byteOffset += gameTextCtrlCharLen(ch) * 2;
            }
            else
            {
                charCount++;
            }
        }
    }
    if (state->active == 0)
    {
        gGameTextDrawnCharIndex = 0;
        gGameTextRevealProgress = lbl_803DE700;
        state->f10 = def->count;
        state->f8 = 0;
        state->active = 1;
    }
    if (lbl_803DE700 == gGameTextRevealProgress)
    {
        Sfx_PlayFromObject(0, SFXTRIG_clock_loop);
    }
    gGameTextRevealActive = 1;
    gGameTextDrawnCharIndex = 0;
    gGameTextRevealProgress = timeDelta * gGameTextRevealSpeed + gGameTextRevealProgress;
    if (gGameTextRevealProgress >= (f32)(charCount - 2))
    {
        Sfx_StopFromObject(0, SFXTRIG_clock_loop);
    }
    if (state->fC != 0)
    {
        if (gGameTextRevealProgress < charCount)
        {
            gGameTextRevealProgress = charCount;
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
                gGameTextRevealProgress = lbl_803DE700;
            }
            if (state->charIndex < 0)
            {
                state->charIndex = 0;
            }
            if (state->charIndex == def->count - 1 && (state->fC = 1) != 0 &&
                gGameTextRevealProgress >= charCount)
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

void gameTextQueueReveal(int a, int b)
{
    int i = gGameTextCommandCount++;
    GameTextSlot* e = &gGameTextCommandSlots[i];
    e->opcode = 1;
    e->arg0 = a;
    e->arg1 = b;
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
    int* bp;
    int lineCount;
    int breakPos;
    int haveSpace;
    int lineIdx;
    char* src;
    int charPos;
    char** buffer;
    char* dst;
    int lineStarts[32];
    int params[8];
    f32 penX;
    int charLen;
    int i;
    int k;
    int charLen2;
    u32 ch;
    lineCount = 0;
    lineOff = 0;
    cursor = 0;
    breakPos = 0;
    haveSpace = 0;
    penX = lbl_803DE704;
    if (gameTextCharset == 2)
    {
        i = 6;
    }
    else
    {
        i = sLanguageNameTable[curLanguage].sizeIdx;
    }
    langIdx = i;
    sizeEntry = &gGameTextFontMetrics[i];

    *outCount = 0;
    if (outLineH != NULL)
    {
        *outLineH = (f32)(u32)sizeEntry->lineHeight * height;
    }
    if (str == NULL)
    {
        return 0;
    }
    if (lbl_803DC9AA != 0 || lbl_803DC9A8 != 0)
    {
        width = (f32)(u32)lbl_803DC9AA;
    }

    lineStarts[0] = 0;
    boundary = lineStarts;
    bp = boundary;

    while ((ch = utf8GetNextChar((u8*)(str + cursor), &charLen)) != 0)
    {
        cursor += charLen;
        if (ch == 0x20)
        {
            breakPos = cursor;
            haveSpace = 1;
        }
        if (ch >= 0xe000 && ch <= 0xf8ff)
        {
            int n;
            int sel;
            n = gameTextCtrlCharLen(ch);
            for (i = 0; i < n; i++)
            {
                int b0 = ((u8*)str)[cursor++];
                int b1 = ((u8*)str)[cursor++];
                params[i] = (b0 << 8) | b1;
            }
            sel = 1;
            switch (ch)
            {
            case TEXT_CTRL_SCALE:
                height = (f32)(int)params[0] * lbl_803DE708;
                break;
            case TEXT_CTRL_FONT:
                langIdx = params[0];
                sizeEntry = &gGameTextFontMetrics[langIdx];
                break;
            default:
                sel = 0;
            }
            if (sel != 0 && langIdx != 5)
            {
                f32 lh = (f32)(u32)sizeEntry->lineHeight * height;
                if (outLineH != NULL && lh > *outLineH)
                {
                    *outLineH = lh;
                }
            }
        }
        else
        {
            MeasGlyph* found = gameTextFindGlyph(ch, langIdx);
            if (found != NULL)
            {
                int advance = (found->width + found->offsetX) + found->advanceX;
                penX += height * (f32)(int)advance;
                if (penX >= width)
                {
                    if (haveSpace == 0)
                    {
                        breakPos = cursor - charLen;
                    }
                    bp++;
                    lineCount++;
                    *(int*)((char*)lineStarts + (lineOff += 4)) = breakPos;
                    if (lineCount > 1 && bp[0] == bp[-1])
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
        buffer = mmAllocateFromFBMemoryStore((int)gGameTextStringStore, charLen);
    }
    else
    {
        buffer = mmAlloc(charLen, 0, 0);
    }
    if (buffer == NULL)
    {
        return 0;
    }
    dst = (char*)buffer;
    i = charLen;
    while (i-- != 0)
    {
        *dst++ = 0;
    }

    {
        char* p = (char*)buffer + lineOff;
        buffer[0] = p;
        dst = p;
    }
    lineIdx = 0;
    charPos = 0;
    src = str;
    while (charPos < cursor)
    {
        *dst++ = *src;
        if (charPos == boundary[1])
        {
            char* q;
            dst--;
            do
            {
                q = dst;
                k = 6;
                do
                {
                    ch = utf8GetNextChar((u8*)(dst - k), &charLen2);
                    if (k != charLen2)
                    {
                        continue;
                    }
                    if (isSpace(ch))
                    {
                        int j = charLen2;
                        while (j-- != 0)
                        {
                            *--dst = 0;
                        }
                        break;
                    }
                    q[1] = q[0];
                    q[0] = 0;
                    dst = q + 1;
                    *(char**)((char*)buffer + ((lineIdx + 1) << 2)) = dst++;
                    break;
                } while (--k > 0);
            } while (dst <= q);
            boundary++;
            lineIdx++;
        }
        charPos++;
        src++;
    }
    *dst = 0;
    return buffer;
}

void* gameTextGetBox(int box)
{
    return &gTextBoxes[box * 0x20];
}

void* gameTextGetCurBox(void)
{
    return gCurTextBox;
}
