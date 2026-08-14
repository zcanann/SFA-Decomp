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
#include "main/textrender_internal.h"
#include "main/audio/sfx_trigger_ids.h"

/* In-string formatting control codes (Unicode PUA). */
#define TEXT_CTRL_SCALE 0xf8f4
#define TEXT_CTRL_FONT  0xf8f7

int isSpace(u32 c);

void gameTextMeasureStringBoundsAt(char* str, int boxIdx, int x, int y, int* outMinX, int* outMaxX, int* outMinY,
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

    gGameTextRenderingById = 1;
    if (gCurTextBox != NULL)
    {
        slot = gCurTextBox;
    }
    else if (def->boxId == 255)
    {
        slot = (TextSlot*)gTextBoxes + 2;
    }
    else
    {
        slot = (TextSlot*)gTextBoxes + def->boxId;
    }

    if (slot == (TextSlot*)gTextBoxes + 0x85)
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

    gGameTextRenderingById = 0;
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
        e->opcode = GAMETEXT_COMMAND_RENDER_BY_ID;
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
        e->opcode = GAMETEXT_COMMAND_RENDER_BY_ID;
        e->arg0 = a;
        e->arg1 = 0;
        e->arg2 = 0;
    }
}

static inline int gameTextCtrlCharLen(u32 c)
{
    CtrlCharEntry* p = gGameTextCtrlCodeArgCounts;
    int i = 46;
    while (i--)
    {
        if (p->key == c)
        {
            return p->len;
        }
        p++;
    }
    return 0;
}

static inline int gameTextCountChars(char* str) {
    int charCount;
    int byteOffset;
    u32 ch;
    int charLen;

    charCount = 0;
    byteOffset = 0;
    if (str == NULL) {
        return 0;
    }
    while ((ch = utf8GetNextChar((u8*)(str + byteOffset), &charLen)) != 0) {
        byteOffset += charLen;
        if (ch >= 0xe000 && ch <= 0xf8ff) {
            byteOffset += gameTextCtrlCharLen(ch) * 2;
        } else {
            charCount++;
        }
    }
    return charCount;
}

void gameTextTickReveal(int textId, TextDisplayState* state)
{
    GameTextDef* def;
    s32 charCount;
    char* lineStr;
    int special;
    u8* defAddress;

    if (gameTextFonts->status == 1)
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
    charCount = gameTextCountChars(lineStr);
    if (state->active == 0)
    {
        gGameTextDrawnCharIndex = 0;
        gGameTextRevealProgress = 2.0f;
        state->f10 = def->count;
        state->f8 = 0;
        state->active = 1;
    }
    if (gGameTextRevealProgress == 2.0f)
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
                gGameTextRevealProgress = 2.0f;
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

void gameTextQueueReveal(int a, TextDisplayState* b)
{
    int i = gGameTextCommandCount++;
    GameTextSlot* e = &gGameTextCommandSlots[i];
    e->opcode = GAMETEXT_COMMAND_TICK_REVEAL;
    e->arg0 = a;
    e->arg1 = (int)b;
}

static inline TextGlyph* gameTextFindGlyph(u32 ch, int langIdx)
{
    TextGlyph* g;
    int cnt;

    g = gameTextFonts->glyphs;
    cnt = gameTextFonts->glyphCount;
    while (cnt-- != 0)
    {
        if (g->key == ch && g->font == langIdx)
        {
            return g;
        }
        g++;
    }
    return NULL;
}

void gameTextFreePhrase(NpcDialoguePhraseState* p)
{
    p->display.active = 0;
    p->display.charIndex = 0;
    p->display.f8 = 0;
    p->display.fC = 0;
    if (p->phraseBuffer != NULL)
    {
        mm_free(p->phraseBuffer);
        p->phraseBuffer = NULL;
    }
}
static inline char* gameTextBreakLine(char* dst, char** buffer, int lineIdx)
{
    char* q;
    int k;
    int charLen2;
    u32 ch;

    q = dst;
    for (;;)
    {
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
            return dst;
        } while (--k > 0);
    }
}

char** gameTextWrapLines(char* str, f32 width, f32 height, int* outCount, f32* outLineH)
{
    int charPos;
    int cursor;
    int* boundary;
    int langIdx;
    FontMetrics* sizeEntry;
    int lineOff;
    int* bp;
    int lineCount;
    int breakPos;
    int haveSpace;
    int lineIdx;
    char* src;
    char** buffer;
    char* dst;
    int lineStarts[32];
    int params[8];
    f32 penX;
    int charLen;
    int i;
    u32 ch;
    lineCount = 0;
    lineOff = 0;
    cursor = 0;
    breakPos = 0;
    haveSpace = 0;
    penX = 0.0f;
    if (gameTextCharset == 2)
    {
        i = 6;
    }
    else
    {
        i = sLanguageNameTable[curLanguage].fontId;
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
    if (gGameTextCursorX != 0 || gGameTextCursorY != 0)
    {
        width = (f32)(u32)gGameTextCursorX;
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
            TextGlyph* found = gameTextFindGlyph(ch, langIdx);
            if (found != NULL)
            {
                int advance = (found->width + found->offsetX) + found->advanceX;
                penX += height * (f32)advance;
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
                    penX = 0.0f;
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
    charLen = cursor + lineCount + lineOff;
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
            dst = gameTextBreakLine(dst - 1, buffer, lineIdx);
            boundary++;
            lineIdx++;
        }
        src++;
        charPos++;
    }
    *dst = 0;
    return buffer;
}

void* gameTextGetBox(int box)
{
    return &gTextBoxes[box];
}

void* gameTextGetCurBox(void)
{
    return gCurTextBox;
}
