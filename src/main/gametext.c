#include "main/engine_shared.h"
#include "main/audio/sfx_trigger_ids.h"

/* In-string formatting control codes (Unicode PUA). */
#define TEXT_CTRL_SCALE 0xf8f4
#define TEXT_CTRL_LANGUAGE 0xf8f7

int isSpace(u32 c)
{
    int result = 0;

    if (c == 0x20 || c == 0x3000 || c == 0x303F)
    {
        result = 1;
    }
    return result;
}

void* gameTextGetBox(int box)
{
    return &gTextBoxes[box * 0x20];
}

void* gameTextGetCurBox(void)
{
    return gCurTextBox;
}

void gameTextFn_80016c18(int a, int b)
{
    int i = lbl_803DC9C8++;
    int* e = (int*)&lbl_8033A540[i * 0x14];
    e[0] = 1;
    e[1] = a;
    e[2] = b;
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

void gameTextFn_80016810(int a, int b, int c)
{
    int i;
    int* e;
    if (gameTextDrawFunc != NULL)
    {
        gameTextFn_8001658c(a, b, c);
    }
    else
    {
        i = lbl_803DC9C8++;
        e = (int*)&lbl_8033A540[i * 0x14];
        e[0] = 2;
        e[1] = a;
        e[2] = b;
        e[3] = c;
    }
}

int gameTextGetTaskText(int id, int* outA, int* outB)
{
    int i;
    TaskTextEntry* e = gTaskTextTable;
    for (i = 0; i < 0x7a; i++)
    {
        if (e->key == id)
        {
            if (outA != NULL)
            {
                *outA = e->a;
            }
            if (outB != NULL)
            {
                *outB = e->b;
            }
            return 1;
        }
        e++;
    }
    return 0;
}

void gameTextShowTimeStr(char* str)
{
    int i;
    int* e;
    char* buf;
    i = lbl_803DC9C8++;
    e = (int*)&lbl_8033A540[i * 0x14];
    e[0] = 5;
    buf = lbl_803DC9C4;
    lbl_803DC9C4 = gameStrcpy(buf, str) + 1;
    e[1] = (int)buf;
}

void gameTextShow(int a)
{
    int i;
    int* e;
    if (gameTextDrawFunc != NULL)
    {
        gameTextFn_8001658c(a, 0, 0);
    }
    else
    {
        i = lbl_803DC9C8++;
        e = (int*)&lbl_8033A540[i * 0x14];
        e[0] = 2;
        e[1] = a;
        e[2] = 0;
        e[3] = 0;
    }
}

void gameTextShowStr(char* text, int box, int arg2, int arg3)
{
    int i;
    int* e;
    char* buf;
    if (gameTextDrawFunc != NULL)
    {
        u8* slot = &gTextBoxes[box * 0x20];
        *(s16*)(slot + 0x18) = arg2;
        *(s16*)(slot + 0x1a) = arg3;
        gameTextRenderStrs(text, box);
    }
    else
    {
        i = lbl_803DC9C8++;
        e = (int*)&lbl_8033A540[i * 0x14];
        e[0] = 7;
        buf = lbl_803DC9C4;
        lbl_803DC9C4 = gameStrcpy(buf, text) + 1;
        e[1] = (int)buf;
        e[2] = box;
        e[3] = arg2;
        e[4] = arg3;
    }
}

void gameTextAppendStr(char* str, int arg2)
{
    int i;
    int* e;
    char* buf;
    if (gameTextDrawFunc != NULL)
    {
        gameTextRenderStrs(str, arg2);
    }
    else
    {
        i = lbl_803DC9C8++;
        e = (int*)&lbl_8033A540[i * 0x14];
        e[0] = 6;
        buf = lbl_803DC9C4;
        lbl_803DC9C4 = gameStrcpy(buf, str) + 1;
        e[1] = (int)buf;
        e[2] = arg2;
    }
}

void gameTextBoxFn_800164b0(char* str, int boxIdx, int* outMaxX, int* outMaxY, int* outMinX, int* outMinY)
{
    u8* box = &gTextBoxes[boxIdx * 0x20];
    s16 savedX = *(s16*)(box + 0x18);
    s16 savedY = *(s16*)(box + 0x1a);
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
    *(s16*)(box + 0x18) = savedX;
    *(s16*)(box + 0x1a) = savedY;
}

void gameTextMeasureFn_800163c4(char* str, int boxIdx, int x, int y, int* outMaxX, int* outMaxY, int* outMinX,
                                int* outMinY)
{
    u8* box = &gTextBoxes[boxIdx * 0x20];
    s16 savedX = *(s16*)(box + 0x18);
    s16 savedY = *(s16*)(box + 0x1a);
    lbl_803DC9BC = 1;
    lbl_803DC9B0 = 0x7FFFFFFF;
    lbl_803DC9AC = 0;
    lbl_803DC9B8 = 0x7FFFFFFF;
    lbl_803DC9B4 = 0;
    *(s16*)(box + 0x18) = x;
    *(s16*)(box + 0x1a) = y;
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
    *(s16*)(box + 0x18) = savedX;
    *(s16*)(box + 0x1a) = savedY;
}

#pragma dont_inline on
int utf8GetNextChar(u8* str, int* outLen)
{
    u8 first = *str;
    int cls = gUtf8CharClassTable[first];
    u32 acc = 0;
    switch (cls)
    {
    case 5:
        str++;
        acc = first << 6;
    case 4:
        acc += *str++;
        acc <<= 6;
    case 3:
        acc += *str++;
        acc <<= 6;
    case 2:
        acc += *str++;
        acc <<= 6;
    case 1:
        acc += *str++;
        acc <<= 6;
    case 0:
        acc += *str;
    default:
        break;
    }
    *outLen = cls + 1;
    return acc - gUtf8ClassOffsetTable[cls];
}
#pragma dont_inline reset

char* gameStrcpy(char* dst, char* src)
{
    u32 ch;
    int len;
    do
    {
        ch = utf8GetNextChar((u8*)src, &len);
        while (len-- != 0)
        {
            *dst++ = *src++;
        }
        if (ch >= 0xe000 && ch <= 0xf8ff)
        {
            len = getControlCharLen(ch) * 2;
            while (len-- != 0)
            {
                *dst++ = *src++;
            }
        }
    }
    while (ch != 0);
    return dst - 1;
}

void gameTextFn_8001628c(int id, int a, int b, int* outMaxX, int* outMaxY, int* outMinX, int* outMinY)
{
    GlyphEntry* e;
    GameTextFont* font = gameTextFonts;
    int found;
    if (font->mode != 2)
    {
        found = 0;
    }
    else
    {
        int count = font->count;
        int i;
        e = font->entries;
        for (i = 0; i != count; i++)
        {
            if (e->id == id)
            {
                found = 1;
                goto checked;
            }
            e++;
        }
        found = 0;
    }
checked:
    if (!found)
    {
        *outMaxX = 0;
        *outMaxY = 0;
        *outMinX = 0;
        *outMinY = 0;
        return;
    }
    lbl_803DC9BC = 1;
    lbl_803DC9B0 = 0x7FFFFFFF;
    lbl_803DC9AC = 0;
    lbl_803DC9B8 = 0x7FFFFFFF;
    lbl_803DC9B4 = 0;
    gameTextFn_8001658c(id, a, b);
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
}

#pragma dont_inline on
#pragma ppc_unroll_speculative on
char** textMeasureFn_80016c9c(char* str, f32 width, f32 height, int* outCount, f32* outLineH)
{
    int lineStarts[32];
    int params[8];
    int langIdx;
    FontSizeEntry* sizeEntry;
    f32 penX;
    int lineCount = 0;
    int lineOff = 0;
    int charLen;
    int i;
    int* bp;
    char** buffer;
    int lineIdx;
    int charLen2;
    u32 ch;
    int* boundary;
    int cursor = 0;
    int breakPos = 0;
    int haveSpace = 0;
    char* src;
    char* dst;
    int charPos;

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
    sizeEntry = &lbl_802C8680[i];

    *outCount = 0;
    if (outLineH != NULL)
    {
        *outLineH = (f32)(u32)
        sizeEntry->lineHeight * height;
    }
    if (str == NULL)
    {
        return 0;
    }
    if (lbl_803DC9AA != 0 || lbl_803DC9A8 != 0)
    {
        width = (f32)(u32)
        lbl_803DC9AA;
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
            SpecialGlyph* g = lbl_802C86F0;
            for (n = 45; n >= 0; n--)
            {
                if (g->key == ch)
                {
                    n = g->val;
                    goto haveCount;
                }
                g++;
            }
            n = 0;
        haveCount:
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
                height = (f32)(int)
                params[0] * lbl_803DE708;
                break;
            case TEXT_CTRL_LANGUAGE:
                langIdx = params[0];
                sizeEntry = &lbl_802C8680[langIdx];
                break;
            default:
                sel = 0;
            }
            if (sel != 0 && langIdx != 5)
            {
                f32 lh = (f32)(u32)
                sizeEntry->lineHeight * height;
                if (outLineH != NULL && lh > *outLineH)
                {
                    *outLineH = lh;
                }
            }
        }
        else
        {
            MeasGlyph* found = (MeasGlyph*)gameTextFonts->field0;
            int n = gameTextFonts->field8;
            while (n-- != 0)
            {
                if (found->key != ch || found->lang != langIdx)
                {
                    found++;
                    continue;
                }
                goto gotGlyph;
            }
            found = NULL;
        gotGlyph:
            if (found != NULL)
            {
                int advance = (found->f9 + found->f8) + found->fC;
                penX += height * (f32)(int)
                advance;
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
        buffer = mmAllocateFromFBMemoryStore(lbl_803DB378);
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

    buffer[0] = (char*)buffer + lineOff;
    dst = buffer[0];
    lineIdx = 0;
    charPos = 0;
    src = str;
    while (charPos < cursor)
    {
        *dst++ = *src;
        if (charPos == boundary[1])
        {
            char* q = --dst;
            for (;;)
            {
                int k = 6;
                do
                {
                    ch = utf8GetNextChar((u8*)(dst - k), &charLen2);
                    if (k == charLen2)
                    {
                        if (!isSpace(ch))
                        {
                            goto foundBreak;
                        }
                        {
                            int j = charLen2;
                            while (j-- != 0)
                            {
                                *--dst = 0;
                            }
                        }
                        break;
                    }
                    k--;
                } while (k > 0);
            }
        foundBreak:
            q[1] = q[0];
            q[0] = 0;
            dst = q + 1;
            *(char**)((char*)buffer + ((lineIdx + 1) << 2)) = dst++;
            boundary++;
            lineIdx++;
        }
        charPos++;
        src++;
    }
    *dst = 0;
    return buffer;
}
#pragma ppc_unroll_speculative off
#pragma dont_inline reset

void gameTextRenderStrs(char* str, int boxIdx)
{
    TextSlot* slot = (TextSlot*)gTextBoxes + boxIdx;
    char** lines;
    int count;
    f32 lineH;
    int i;
    int closeAtEnd = 0;

    if (lbl_803DC9C0 != 1)
    {
        slot->f12 = slot->f10;
        if (lbl_803DC9BC == 0)
        {
            gameTextDrawBox(NULL, (int)str, slot);
        }
    }
    lines = textMeasureFn_80016c9c(str, (f32)(u32)slot->f08,
                                   slot->f0c, &count, &lineH);
    if (lines == NULL)
    {
        slot->f1a = (s16)(lineH * count + slot->f1a);
        return;
    }
    if (gameTextDrawFunc != NULL)
    {
        gxSetScissorRect(0, 0, 0, 0, 0x280, 0x1e0);
    }
    else if (lbl_803DC9BC == 0)
    {
        gxSetScissorRect(0, 0, slot->f14, slot->f16,
                         slot->f14 + slot->f08, slot->f16 + slot->f0a);
    }
    lbl_803DC9A0 = slot->f0c;
    for (i = 0; i < count; i++)
    {
        if (i == count - 1 && slot->f12 == 3)
        {
            slot->f12 = 0;
            closeAtEnd = 1;
        }
        if (lbl_803DC984 == 1 && lbl_803DC9BC == 0)
        {
            u8 save7 = lbl_803DC9A7;
            u8 save6 = lbl_803DC9A6;
            u8 save5 = lbl_803DC9A5;
            f32 saveColor = lbl_803DC9A0;
            lbl_803DC9A7 = lbl_803DC992;
            lbl_803DC9A6 = lbl_803DC991;
            lbl_803DC9A5 = lbl_803DC990;
            textRenderStr(lines[i], slot, slot->f18, slot->f1a, lineH, 1);
            lbl_803DC9A7 = save7;
            lbl_803DC9A6 = save6;
            lbl_803DC9A5 = save5;
            lbl_803DC9A0 = saveColor;
        }
        textRenderStr(lines[i], slot, slot->f18, slot->f1a, lineH, 0);
        slot->f1a = (s16)((f32)slot->f1a + lineH);
        if (closeAtEnd)
        {
            slot->f12 = 3;
        }
    }
    if (lbl_803DC9BC == 0)
    {
        Camera_ApplyCurrentViewport(NULL);
    }
}

static inline int textCountChars(char* lineStr)
{
    int charCount;
    int byteOffset;
    u32 ch;
    int charLen;

    charCount = 0;
    byteOffset = 0;
    if (lineStr == NULL)
    {
        return 0;
    }
    while ((ch = utf8GetNextChar((u8*)(lineStr + byteOffset), &charLen)) != 0)
    {
        byteOffset += charLen;
        if (ch >= 0xe000 && ch <= 0xf8ff)
        {
            SpecialGlyph* g = lbl_802C86F0;
            int n;
            int val;
            for (n = 46; n-- != 0;)
            {
                if (g->key == ch)
                {
                    val = g->val;
                    goto haveVal;
                }
                g++;
            }
            val = 0;
        haveVal:
            byteOffset += val * 2;
        }
        else
        {
            charCount++;
        }
    }
    return charCount;
}

void textDisplayFn_800168dc(int textId, TextDisplayState* state)
{
    GameTextDef* def;
    int charCount;
    char* lineStr;
    int special;

    if (*(int*)((u8*)gameTextFonts + 0x1c) == 1)
    {
        return;
    }
    def = gameTextGet(textId);
    special = 0;
    if ((u8*)def >= lbl_803399C0 && (u8*)def < lbl_803399C0 + 0x60)
    {
        special = 1;
    }
    if (special)
    {
        state->f8 = 1;
        return;
    }
    lineStr = def->strings[state->charIndex];
    charCount = textCountChars(lineStr);
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
                if (state->charIndex < def->count &&
                    *(u8*)def->strings[state->charIndex] == 0)
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
            if (state->charIndex == def->count - 1)
            {
                if ((state->fC = 1) != 0 && lbl_803DC994 >= charCount)
                {
                    state->f8 = 1;
                }
                else
                {
                    goto setF8Zero;
                }
            }
            else
            {
            setF8Zero:
                state->f8 = 0;
            }
            state->fC = 0;
        }
    }
    gameTextRenderStrs(def->strings[state->charIndex], 0x7c);
}

void gameTextFn_8001658c(int a, int b, int c)
{
    GameTextDef* def = gameTextGet(a);
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

    if (def->f5 == 0)
    {
        slot->f12 = slot->f10;
    }
    slot->f18 = b;
    slot->f1a = c;

    if (lbl_803DC9BC == 0)
    {
        int mode;
        if (def->f6 == 0)
        {
            mode = slot->f11;
        }
        else
        {
            mode = def->f6;
        }
        if (mode == 2 || mode == 3)
        {
            int maxX, maxY, minX, minY;
            int v;
            gameTextFn_8001628c(a, b, c, &maxX, &maxY, &minX, &minY);
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

TaskTextEntry gTaskTextTable[208] = {
    { 0x0004, 0x0029, 0x00D1 },
    { 0x0006, 0x0029, 0x04F7 },
    { 0x0009, 0x0029, 0x017C },
    { 0x000B, 0x0029, 0x004B },
    { 0x000C, 0x0029, 0x0285 },
    { 0x000E, 0x0029, 0x04EA },
    { 0x0010, 0x0029, 0x0041 },
    { 0x0011, 0x0029, 0x047A },
    { 0x0013, 0x0029, 0x046C },
    { 0x0015, 0x0029, 0x01D7 },
    { 0x0016, 0x0029, 0x0477 },
    { 0x0031, 0x0029, 0x0205 },
    { 0x0037, 0x0029, 0x01B0 },
    { 0x0038, 0x0029, 0x0075 },
    { 0x003C, 0x0029, 0x02E5 },
    { 0x003D, 0x0029, 0x0078 },
    { 0x003F, 0x0029, 0x0499 },
    { 0x0042, 0x0029, 0x001E },
    { 0x0043, 0x0029, 0x000C },
    { 0x0048, 0x0029, 0x0027 },
    { 0x004B, 0x0029, 0x00A7 },
    { 0x0056, 0x0029, 0x00AD },
    { 0x005A, 0x0029, 0x020F },
    { 0x005F, 0x0029, 0x0023 },
    { 0x0092, 0x0029, 0x04C3 },
    { 0x00A6, 0x0029, 0x00E4 },
    { 0x00A7, 0x0029, 0x001C },
    { 0x00AA, 0x0029, 0x00FE },
    { 0x00AB, 0x0029, 0x0105 },
    { 0x00AD, 0x0029, 0x00FF },
    { 0x00AE, 0x0029, 0x0121 },
    { 0x00AF, 0x0029, 0x056A },
    { 0x00B1, 0x0029, 0x00FA },
    { 0x00B2, 0x0029, 0x00FB },
    { 0x00B3, 0x0029, 0x00FC },
    { 0x00B8, 0x0029, 0x01AA },
    { 0x00B9, 0x0029, 0x01AB },
    { 0x00CA, 0x0029, 0x016E },
    { 0x00CB, 0x0029, 0x01A4 },
    { 0x00E6, 0x0029, 0x007A },
    { 0x00F0, 0x0029, 0x0324 },
    { 0x01F8, 0x0029, 0x0338 },
    { 0x01FE, 0x0029, 0x035A },
    { 0x0203, 0x0029, 0x049C },
    { 0x0205, 0x0029, 0x053E },
    { 0x020A, 0x0029, 0x0510 },
    { 0x020B, 0x0029, 0x0544 },
    { 0x0265, 0x0029, 0x0462 },
    { 0x0288, 0x0029, 0x0532 },
    { 0x0289, 0x0029, 0x008E },
    { 0x028A, 0x0029, 0x0282 },
    { 0x028C, 0x0029, 0x01DB },
    { 0x028E, 0x0029, 0x0045 },
    { 0x02A0, 0x0029, 0x00E3 },
    { 0x02B4, 0x0029, 0x001F },
    { 0x02B9, 0x0029, 0x04E8 },
    { 0x02BA, 0x0029, 0x04E9 },
    { 0x02F1, 0x0029, 0x0127 },
    { 0x02F2, 0x0029, 0x0128 },
    { 0x02F3, 0x0029, 0x0487 },
    { 0x02F4, 0x0029, 0x03C4 },
    { 0x02F5, 0x0029, 0x03C8 },
    { 0x4E21, 0x0029, 0x0464 },
    { 0x4E22, 0x0029, 0x0481 },
    { 0x4E23, 0x0029, 0x0483 },
    { 0x4E24, 0x0029, 0x053D },
    { 0x4E25, 0x0029, 0x02D8 },
    { 0x4E26, 0x0029, 0x04FB },
    { 0x4E27, 0x0029, 0x04FE },
    { 0x4E28, 0x0029, 0x0505 },
    { 0x4E29, 0x0029, 0x0503 },
    { 0x4E2A, 0x0029, 0x0052 },
    { 0x4E2B, 0x0029, 0x004F },
    { 0x4E2C, 0x0029, 0x0050 },
    { 0x4E2D, 0x0029, 0x011B },
    { 0x4E2E, 0x0029, 0x0571 },
    { 0x4E2F, 0x0029, 0x0074 },
    { 0x4E30, 0x0029, 0x007B },
    { 0x4E31, 0x0029, 0x0383 },
    { 0x4E32, 0x0029, 0x0384 },
    { 0x4E34, 0x0029, 0x0515 },
    { 0x4E35, 0x0029, 0x0549 },
    { 0x4E36, 0x0029, 0x0148 },
    { 0x4E37, 0x0029, 0x014A },
    { 0x4E38, 0x0029, 0x033A },
    { 0x4E3D, 0x0029, 0x001D },
    { 0x4E40, 0x0029, 0x0020 },
    { 0x4E41, 0x0029, 0x0388 },
    { 0x4E42, 0x0029, 0x0395 },
    { 0x4E43, 0x0029, 0x015C },
    { 0x4E44, 0x0029, 0x058B },
    { 0x4E45, 0x0029, 0x0283 },
    { 0x4E46, 0x0029, 0x02AA },
    { 0x4E84, 0x0029, 0x0064 },
    { 0x4E89, 0x0029, 0x0069 },
    { 0x4E8B, 0x0029, 0x0083 },
    { 0x4E8C, 0x0029, 0x0490 },
    { 0x4EAB, 0x0029, 0x008B },
    { 0x4EAC, 0x0029, 0x0598 },
    { 0x4EB6, 0x0029, 0x059A },
    { 0x4EE9, 0x0029, 0x00C9 },
    { 0x4EEA, 0x0029, 0x00CA },
    { 0x4EEB, 0x0029, 0x00CB },
    { 0x4EF2, 0x0029, 0x00D2 },
    { 0x4EF5, 0x0029, 0x00D5 },
    { 0x4F0A, 0x0029, 0x00EA },
    { 0x4F35, 0x0029, 0x0115 },
    { 0x4F38, 0x0029, 0x0118 },
    { 0x4F3E, 0x0029, 0x011E },
    { 0x501A, 0x0029, 0x01FA },
    { 0x501C, 0x0029, 0x01FC },
    { 0x5078, 0x0029, 0x0080 },
    { 0x509B, 0x0029, 0x0271 },
    { 0x50B5, 0x0029, 0x0493 },
    { 0x50D7, 0x0029, 0x006D },
    { 0x50D8, 0x0029, 0x0180 },
    { 0x50DC, 0x0029, 0x059C },
    { 0x517F, 0x0029, 0x035F },
    { 0x529F, 0x0029, 0x047F },
    { 0x52B2, 0x0029, 0x0492 },
    { 0x52BD, 0x0029, 0x049D },
    { 0x5368, 0x0029, 0x0548 },
    { 0xFFFF, 0x0000, 0x0000 },
    { 0x0000, 0x0000, 0xFFFF },
    { 0xFFFF, 0x0000, 0x0000 },
    { 0x0006, 0x0006, 0x0006 },
    { 0x0006, 0x0006, 0x0006 },
    { 0xFFFF, 0xFFFF, 0x0002 },
    { 0x0002, 0x0005, 0x0005 },
    { 0x0005, 0x0005, 0x0006 },
    { 0xFFFF, 0xFFFF, 0x0006 },
    { 0x0006, 0x0006, 0x0006 },
    { 0x0006, 0x0006, 0xFFFF },
    { 0x0005, 0x0005, 0x0005 },
    { 0x0006, 0x0007, 0xFFFF },
    { 0x0007, 0x0007, 0x0007 },
    { 0x0007, 0x0007, 0x0007 },
    { 0x0007, 0x0007, 0x0007 },
    { 0x0007, 0xFFFF, 0xFFFF },
    { 0xFFFF, 0xFFFF, 0x0007 },
    { 0x0006, 0x0009, 0x0009 },
    { 0x000A, 0x000A, 0x000A },
    { 0x000A, 0x000A, 0xFFFF },
    { 0x0009, 0x0009, 0x0009 },
    { 0x0009, 0x0009, 0x0009 },
    { 0x0006, 0xFFFF, 0x0000 },
    { 0x0000, 0x000C, 0xFFFF },
    { 0x000C, 0xFFFF, 0xFFFF },
    { 0x000C, 0x0006, 0x000B },
    { 0xFFFF, 0x000B, 0x000B },
    { 0x000B, 0x000B, 0x000B },
    { 0x000B, 0xFFFF, 0xFFFF },
    { 0xFFFF, 0xFFFF, 0x000B },
    { 0xFFFF, 0x000C, 0x0008 },
    { 0x0008, 0x0008, 0x0008 },
    { 0xFFFF, 0xFFFF, 0xFFFF },
    { 0x0006, 0x0004, 0x0004 },
    { 0x0004, 0xFFFF, 0x0004 },
    { 0xFFFF, 0xFFFF, 0xFFFF },
    { 0x0004, 0xFFFF, 0x0000 },
    { 0x0006, 0x0006, 0x0003 },
    { 0xFFFF, 0x0003, 0x0003 },
    { 0x0003, 0x0003, 0xFFFF },
    { 0xFFFF, 0xFFFF, 0x0003 },
    { 0x000A, 0x000A, 0x000A },
    { 0x000A, 0xFFFF, 0x0006 },
    { 0xFFFF, 0x0006, 0x0005 },
    { 0x0005, 0x0005, 0xFFFF },
    { 0x0000, 0xFFFF, 0x0006 },
    { 0x0001, 0xFFFF, 0xFFFF },
    { 0x0001, 0x0001, 0x0001 },
    { 0x0001, 0xFFFF, 0x0001 },
    { 0x0001, 0xFFFF, 0xFFFF },
    { 0xFFFF, 0xFFFF, 0xFFFF },
    { 0xFFFF, 0x0001, 0x000C },
    { 0x0008, 0xFFFF, 0x0008 },
    { 0xFFFF, 0xFFFF, 0x0006 },
    { 0x0006, 0x0003, 0x0003 },
    { 0xFFFF, 0x0003, 0xFFFF },
    { 0xFFFF, 0xFFFF, 0x0003 },
    { 0x0003, 0x0000, 0x0000 },
    { 0x0000, 0x0000, 0x0000 },
    { 0xFFFF, 0xFFFF, 0xFFFF },
    { 0xFFFF, 0xFFFF, 0xFFFF },
    { 0x0000, 0x0000, 0xFFFF },
    { 0xFFFF, 0xFFFF, 0xFFFF },
    { 0xFFFF, 0xFFFF, 0xFFFF },
    { 0xFFFF, 0xFFFF, 0xFFFF },
    { 0xFFFF, 0xFFFF, 0xFFFF },
    { 0xFFFF, 0xFFFF, 0xFFFF },
    { 0xFFFF, 0xFFFF, 0xFFFF },
    { 0xFFFF, 0xFFFF, 0xFFFF },
    { 0xFFFF, 0xFFFF, 0xFFFF },
    { 0xFFFF, 0xFFFF, 0xFFFF },
    { 0xFFFF, 0xFFFF, 0xFFFF },
    { 0xFFFF, 0xFFFF, 0xFFFF },
    { 0xFFFF, 0xFFFF, 0xFFFF },
    { 0xFFFF, 0xFFFF, 0xFFFF },
    { 0xFFFF, 0xFFFF, 0xFFFF },
    { 0xFFFF, 0xFFFF, 0xFFFF },
    { 0xFFFF, 0xFFFF, 0xFFFF },
    { 0xFFFF, 0xFFFF, 0xFFFF },
    { 0xFFFF, 0xFFFF, 0xFFFF },
    { 0xFFFF, 0xFFFF, 0xFFFF },
    { 0xFFFF, 0xFFFF, 0xFFFF },
    { 0xFFFF, 0xFFFF, 0xFFFF },
    { 0xFFFF, 0xFFFF, 0xFFFF },
    { 0x0000, 0x0000, 0x0000 },
};

extern char sMapDirectoryNameArwing[];
extern char sMapDirectoryNameBoot[];
extern char sMapDirectoryNameCRFort[];
extern char sMapDirectoryNameDFPTop[];
extern char sMapDirectoryNameDesert[];
extern char sMapDirectoryNameLINKG[];
extern char sMapDirectoryNameLink[];
extern char sMapDirectoryNameLinkB[];
extern char sMapDirectoryNameLinkC[];
extern char sMapDirectoryNameLinkD[];
extern char sMapDirectoryNameLinkE[];
extern char sMapDirectoryNameLinkF[];
extern char sMapDirectoryNameLinkH[];
extern char sMapDirectoryNameLinkJ[];
extern char sMapDirectoryNameMMPass[];
extern char sMapDirectoryNameNWastes[];
extern char sMapDirectoryNameShop[];
extern char sMapDirectoryNameSwapHol[];
extern char sMapDirectoryNameVolcano[];
extern char sMapDirectoryNameWarlock[];

u8 gUtf8CharClassTable[256] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5,
};

int gUtf8ClassOffsetTable[6] = { 0, 12416, 925824, 63447168, -100130688, -2113396608 };

char sMapDirectoryNameAnimtest[] = "Animtest";

char sMapDirectoryNameBOSSAndross[] = "BOSSAndross";

char sMapDirectoryNameBossDrakor[] = "BossDrakor";

char sMapDirectoryNameBossGaldon[] = "BossGaldon";

char sMapDirectoryNameBossTrex[] = "BossTrex";

char sMapDirectoryNameCapeClaw[] = "CapeClaw";

char sMapDirectoryNameCloudDungeon[] = "CloudDungeon";

char sMapDirectoryNameCloudRace[] = "CloudRace";

char sMapDirectoryNameCommunicator[] = "Communicator";

char sMapDirectoryNameDBShrine[] = "DBShrine";

char sMapDirectoryNameDFShrine[] = "DFShrine";

char sMapDirectoryNameDarkIceMines[] = "DarkIceMines";

char sMapDirectoryNameDarkIceMines2[] = "DarkIceMines2";

char sMapDirectoryNameDragRock[] = "DragRock";

char sMapDirectoryNameDragRockBot[] = "DragRockBot";

char sMapDirectoryNameECShrine[] = "ECShrine";

char sMapDirectoryNameFrontEnd[] = "FrontEnd";

char sMapDirectoryNameGPShrine[] = "GPShrine";

char sMapDirectoryNameGameMaze[] = "GameMaze";

char sMapDirectoryNameIceMountain[] = "IceMountain";

char sMapDirectoryNameInsideGal[] = "InsideGal";

char sMapDirectoryNameLightFoot[] = "LightFoot";

char sMapDirectoryNameMMShrine[] = "MMShrine";

char sMapDirectoryNameMagicCave[] = "MagicCave";

char sMapDirectoryNameNWShrine[] = "NWShrine";

char sMapDirectoryNameSequences[] = "Sequences";

char sMapDirectoryNameShipBattle[] = "ShipBattle";

char sMapDirectoryNameTaskTexts000[] = "TaskTexts000";

char sMapDirectoryNameTaskTexts001[] = "TaskTexts001";

char sMapDirectoryNameTaskTexts002[] = "TaskTexts002";

char sMapDirectoryNameTaskTexts003[] = "TaskTexts003";

char sMapDirectoryNameTaskTexts004[] = "TaskTexts004";

char sMapDirectoryNameTaskTexts005[] = "TaskTexts005";

char sMapDirectoryNameTaskTexts006[] = "TaskTexts006";

char sMapDirectoryNameTaskTexts007[] = "TaskTexts007";

char sMapDirectoryNameTaskTexts008[] = "TaskTexts008";

char sMapDirectoryNameTaskTexts009[] = "TaskTexts009";

char sMapDirectoryNameTaskTexts010[] = "TaskTexts010";

char sMapDirectoryNameTaskTexts011[] = "TaskTexts011";

char sMapDirectoryNameTaskTexts012[] = "TaskTexts012";

char sMapDirectoryNameTaskTexts013[] = "TaskTexts013";

char sMapDirectoryNameTaskTexts014[] = "TaskTexts014";

char sMapDirectoryNameTaskTexts015[] = "TaskTexts015";

char sMapDirectoryNameTaskTexts016[] = "TaskTexts016";

char sMapDirectoryNameTaskTexts017[] = "TaskTexts017";

char sMapDirectoryNameTaskTexts018[] = "TaskTexts018";

char sMapDirectoryNameTaskTexts019[] = "TaskTexts019";

char sMapDirectoryNameTaskTexts021[] = "TaskTexts021";

char sMapDirectoryNameTaskTexts022[] = "TaskTexts022";

char sMapDirectoryNameTaskTexts023[] = "TaskTexts023";

char sMapDirectoryNameTaskTexts024[] = "TaskTexts024";

char sMapDirectoryNameWallCity[] = "WallCity";

char sMapDirectoryNameWorldMap[] = "WorldMap";

char sLanguageNameJapanese[] = "Japanese";

extern char sLanguageNameEnglish[];
extern char sLanguageNameFrench[];
extern char sLanguageNameGerman[];
extern char sLanguageNameItalian[];
extern char sLanguageNameSpanish[];

LanguageName sLanguageNameTable[6] = {
    { sLanguageNameEnglish, 4, { 0, 0, 0 } },
    { sLanguageNameFrench, 4, { 0, 0, 0 } },
    { sLanguageNameGerman, 4, { 0, 0, 0 } },
    { sLanguageNameItalian, 4, { 0, 0, 0 } },
    { sLanguageNameJapanese, 0, { 0, 0, 0 } },
    { sLanguageNameSpanish, 4, { 0, 0, 0 } },
};

u8 gTextBoxes[3144] = {
    2, 48, 2, 48, 1, 144, 1, 144, 2, 48, 1, 144, 63, 128, 0, 0,
    2, 0, 2, 5, 0, 40, 0, 40, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 0, 1, 0, 0, 96, 0, 96, 1, 0, 0, 96, 63, 128, 0, 0,
    3, 0, 3, 6, 0, 30, 0, 30, 0, 0, 0, 0, 0, 0, 0, 0,
    2, 68, 2, 68, 1, 144, 1, 144, 2, 68, 1, 144, 63, 128, 0, 0,
    2, 1, 2, 5, 0, 30, 0, 40, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 16, 1, 64, 0, 16, 0, 110, 1, 64, 0, 110, 63, 128, 0, 0,
    0, 1, 0, 7, 0, 40, 0, 40, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 74, 1, 74, 1, 0, 1, 0, 1, 74, 1, 0, 63, 128, 0, 0,
    0, 0, 0, 5, 0, 30, 0, 100, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 74, 1, 74, 1, 74, 1, 74, 1, 74, 1, 74, 63, 128, 0, 0,
    0, 0, 0, 5, 0, 30, 0, 240, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 230, 0, 230, 1, 0, 1, 0, 0, 230, 1, 0, 63, 128, 0, 0,
    2, 0, 2, 5, 1, 124, 0, 100, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 230, 0, 230, 1, 0, 1, 0, 0, 230, 1, 0, 63, 128, 0, 0,
    2, 0, 2, 5, 1, 124, 0, 240, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 16, 0, 200, 0, 100, 1, 0, 0, 200, 1, 0, 63, 128, 0, 0,
    1, 0, 1, 5, 1, 105, 0, 63, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 16, 0, 200, 0, 16, 1, 0, 0, 200, 1, 0, 63, 128, 0, 0,
    1, 0, 1, 5, 1, 90, 0, 88, 0, 0, 0, 0, 0, 0, 0, 0,
    2, 68, 2, 68, 0, 25, 0, 25, 2, 68, 0, 25, 63, 128, 0, 0,
    2, 0, 2, 5, 0, 30, 1, 159, 0, 0, 0, 0, 0, 0, 0, 0,
    2, 68, 2, 68, 1, 224, 1, 224, 2, 68, 1, 224, 63, 128, 0, 0,
    2, 0, 2, 5, 0, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 134, 1, 134, 0, 200, 0, 200, 1, 134, 0, 200, 63, 128, 0, 0,
    2, 0, 2, 7, 0, 40, 0, 50, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 150, 0, 150, 0, 16, 0, 40, 0, 150, 0, 40, 63, 153, 153, 154,
    0, 1, 0, 5, 0, 54, 1, 44, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 16, 1, 246, 0, 16, 0, 32, 1, 246, 0, 32, 63, 128, 0, 0,
    2, 0, 2, 3, 0, 69, 1, 7, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 16, 1, 246, 0, 16, 0, 32, 1, 246, 0, 32, 63, 128, 0, 0,
    2, 0, 2, 3, 0, 69, 1, 58, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 4, 1, 4, 0, 16, 0, 32, 1, 4, 0, 32, 63, 128, 0, 0,
    1, 0, 1, 5, 0, 56, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 4, 1, 4, 0, 16, 0, 32, 1, 4, 0, 32, 63, 128, 0, 0,
    1, 0, 1, 5, 0, 56, 255, 222, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 16, 1, 246, 0, 16, 0, 32, 1, 246, 0, 32, 63, 128, 0, 0,
    2, 0, 2, 3, 0, 69, 0, 161, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 16, 1, 246, 0, 16, 0, 32, 1, 246, 0, 32, 63, 128, 0, 0,
    2, 0, 2, 3, 0, 69, 0, 215, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 16, 1, 246, 0, 16, 0, 32, 1, 246, 0, 32, 63, 128, 0, 0,
    2, 0, 2, 3, 0, 69, 1, 13, 0, 0, 0, 0, 0, 0, 0, 0,
    2, 128, 2, 128, 0, 16, 0, 32, 2, 128, 0, 32, 63, 128, 0, 0,
    2, 0, 2, 5, 0, 0, 1, 160, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 4, 1, 4, 0, 16, 0, 32, 1, 4, 0, 32, 63, 128, 0, 0,
    0, 0, 0, 5, 0, 56, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 4, 1, 4, 0, 16, 0, 32, 1, 4, 0, 32, 63, 128, 0, 0,
    0, 0, 0, 5, 0, 56, 0, 26, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 4, 1, 4, 0, 16, 0, 32, 1, 4, 0, 32, 63, 128, 0, 0,
    0, 0, 0, 5, 0, 56, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 4, 1, 4, 0, 16, 0, 52, 1, 4, 0, 52, 63, 128, 0, 0,
    0, 0, 0, 5, 0, 56, 0, 78, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 4, 1, 4, 0, 16, 0, 32, 1, 4, 0, 32, 63, 128, 0, 0,
    0, 0, 0, 5, 0, 56, 0, 104, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 4, 1, 4, 0, 16, 0, 52, 1, 4, 0, 52, 63, 128, 0, 0,
    0, 0, 0, 5, 0, 56, 0, 130, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 4, 1, 4, 0, 16, 0, 32, 1, 4, 0, 32, 63, 128, 0, 0,
    0, 0, 0, 5, 0, 56, 0, 156, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 4, 1, 4, 0, 16, 0, 52, 1, 4, 0, 52, 63, 128, 0, 0,
    0, 0, 0, 5, 0, 56, 0, 182, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 4, 1, 4, 0, 16, 0, 52, 1, 4, 0, 52, 63, 128, 0, 0,
    0, 0, 0, 5, 0, 56, 0, 208, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 240, 0, 240, 0, 16, 0, 32, 0, 240, 0, 32, 63, 128, 0, 0,
    0, 0, 0, 5, 0, 76, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 240, 0, 240, 0, 16, 0, 32, 0, 240, 0, 32, 63, 128, 0, 0,
    0, 0, 0, 5, 0, 76, 0, 94, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 240, 0, 240, 0, 16, 0, 32, 0, 240, 0, 32, 63, 128, 0, 0,
    0, 0, 0, 5, 0, 76, 0, 136, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 4, 1, 4, 0, 128, 0, 128, 1, 4, 0, 128, 63, 128, 0, 0,
    1, 0, 1, 5, 0, 56, 0, 26, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 4, 1, 4, 0, 128, 0, 128, 1, 4, 0, 128, 63, 128, 0, 0,
    1, 0, 1, 5, 0, 56, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 4, 1, 4, 0, 128, 0, 128, 1, 4, 0, 128, 63, 128, 0, 0,
    1, 0, 1, 5, 0, 56, 0, 78, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 4, 1, 4, 0, 128, 0, 128, 1, 4, 0, 128, 63, 128, 0, 0,
    1, 0, 1, 5, 0, 56, 0, 104, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 4, 1, 4, 0, 128, 0, 128, 1, 4, 0, 128, 63, 128, 0, 0,
    1, 0, 1, 5, 0, 56, 0, 130, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 4, 1, 4, 0, 128, 0, 128, 1, 4, 0, 128, 63, 128, 0, 0,
    1, 0, 1, 5, 0, 56, 0, 156, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 4, 1, 4, 0, 128, 0, 128, 1, 4, 0, 128, 63, 128, 0, 0,
    1, 0, 1, 5, 0, 56, 0, 182, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 4, 1, 4, 0, 128, 0, 128, 1, 4, 0, 128, 63, 128, 0, 0,
    1, 0, 1, 5, 0, 56, 0, 208, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 32, 0, 32, 0, 16, 0, 32, 0, 32, 0, 32, 63, 128, 0, 0,
    2, 0, 2, 5, 0, 142, 0, 26, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 32, 0, 32, 0, 16, 0, 32, 0, 32, 0, 32, 63, 128, 0, 0,
    2, 0, 2, 5, 0, 169, 0, 26, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 32, 0, 32, 0, 16, 0, 32, 0, 32, 0, 32, 63, 128, 0, 0,
    2, 0, 2, 5, 0, 196, 0, 26, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 4, 1, 4, 0, 32, 0, 32, 1, 4, 0, 32, 63, 128, 0, 0,
    0, 0, 0, 5, 0, 56, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 4, 1, 4, 0, 32, 0, 32, 1, 4, 0, 32, 63, 128, 0, 0,
    0, 0, 0, 5, 0, 56, 0, 234, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 16, 1, 0, 0, 32, 0, 32, 1, 0, 0, 32, 63, 128, 0, 0,
    2, 0, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 16, 1, 0, 0, 32, 0, 32, 1, 0, 0, 32, 63, 128, 0, 0,
    2, 0, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 16, 1, 0, 0, 32, 0, 32, 1, 0, 0, 32, 63, 128, 0, 0,
    2, 0, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 16, 1, 0, 0, 32, 0, 32, 1, 0, 0, 32, 63, 128, 0, 0,
    2, 0, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 16, 1, 0, 0, 32, 0, 32, 1, 0, 0, 32, 63, 128, 0, 0,
    2, 0, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 16, 1, 0, 0, 32, 0, 32, 1, 0, 0, 32, 63, 128, 0, 0,
    2, 0, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 16, 1, 4, 0, 32, 0, 32, 1, 4, 0, 32, 63, 128, 0, 0,
    2, 0, 2, 3, 0, 56, 1, 141, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 144, 1, 144, 1, 44, 1, 44, 1, 144, 1, 44, 63, 128, 0, 0,
    2, 0, 2, 5, 0, 120, 0, 90, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 16, 0, 160, 0, 24, 0, 24, 0, 160, 0, 24, 63, 128, 0, 0,
    0, 2, 0, 5, 1, 194, 1, 7, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 16, 0, 187, 0, 24, 0, 24, 0, 187, 0, 24, 63, 128, 0, 0,
    0, 2, 0, 5, 1, 167, 1, 36, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 16, 1, 0, 0, 24, 0, 24, 1, 0, 0, 24, 63, 128, 0, 0,
    0, 2, 0, 5, 0, 64, 0, 97, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 16, 1, 0, 0, 24, 0, 24, 1, 0, 0, 24, 63, 128, 0, 0,
    0, 2, 0, 5, 1, 97, 0, 113, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 16, 0, 190, 0, 24, 0, 24, 0, 190, 0, 24, 63, 128, 0, 0,
    2, 2, 2, 5, 0, 111, 0, 125, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 16, 0, 244, 0, 24, 0, 24, 0, 244, 0, 24, 63, 128, 0, 0,
    0, 2, 0, 5, 1, 110, 0, 219, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 16, 0, 208, 0, 24, 0, 24, 0, 208, 0, 24, 63, 128, 0, 0,
    0, 2, 0, 5, 1, 146, 0, 180, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 16, 0, 189, 0, 24, 0, 24, 0, 189, 0, 24, 63, 128, 0, 0,
    0, 2, 0, 5, 1, 165, 0, 152, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 16, 1, 0, 0, 24, 0, 24, 1, 0, 0, 24, 63, 128, 0, 0,
    0, 2, 0, 5, 0, 67, 1, 103, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 16, 0, 225, 0, 24, 0, 24, 0, 225, 0, 24, 63, 128, 0, 0,
    0, 2, 0, 5, 1, 129, 1, 68, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 4, 1, 4, 0, 16, 0, 32, 1, 4, 0, 32, 63, 128, 0, 0,
    0, 0, 0, 5, 0, 56, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 4, 1, 4, 0, 128, 0, 128, 1, 4, 0, 128, 63, 128, 0, 0,
    1, 0, 1, 5, 0, 56, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 4, 1, 4, 0, 16, 0, 32, 1, 4, 0, 32, 63, 128, 0, 0,
    0, 0, 0, 5, 0, 56, 0, 26, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 200, 0, 200, 0, 128, 0, 128, 0, 200, 0, 128, 63, 128, 0, 0,
    1, 0, 1, 5, 0, 121, 0, 26, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 200, 0, 160, 0, 128, 0, 128, 0, 160, 0, 128, 63, 128, 0, 0,
    1, 0, 1, 5, 0, 121, 0, 26, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 200, 0, 200, 0, 24, 0, 24, 0, 200, 0, 24, 63, 128, 0, 0,
    2, 0, 2, 7, 1, 114, 1, 44, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 200, 0, 200, 0, 24, 0, 24, 0, 200, 0, 24, 63, 128, 0, 0,
    2, 0, 2, 7, 0, 70, 1, 44, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 200, 0, 200, 0, 24, 0, 24, 0, 200, 0, 24, 63, 128, 0, 0,
    2, 0, 2, 7, 0, 220, 1, 4, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 1, 244, 0, 46, 0, 46, 1, 244, 0, 46, 63, 128, 0, 0,
    2, 1, 2, 2, 0, 60, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 100, 0, 100, 0, 16, 0, 32, 0, 100, 0, 32, 63, 128, 0, 0,
    0, 0, 0, 5, 0, 130, 0, 178, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 100, 0, 100, 0, 16, 0, 32, 0, 100, 0, 32, 63, 128, 0, 0,
    0, 0, 0, 5, 0, 130, 0, 204, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 100, 0, 100, 0, 16, 0, 32, 0, 100, 0, 32, 63, 128, 0, 0,
    0, 0, 0, 5, 0, 130, 0, 230, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 100, 0, 100, 0, 16, 0, 32, 0, 100, 0, 32, 63, 128, 0, 0,
    0, 0, 0, 5, 0, 130, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 100, 0, 100, 0, 16, 0, 32, 0, 100, 0, 32, 63, 128, 0, 0,
    0, 0, 0, 5, 0, 130, 1, 26, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 100, 0, 100, 0, 16, 0, 32, 0, 100, 0, 32, 63, 128, 0, 0,
    0, 0, 0, 5, 1, 145, 0, 178, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 100, 0, 100, 0, 16, 0, 32, 0, 100, 0, 32, 63, 128, 0, 0,
    0, 0, 0, 5, 1, 145, 0, 204, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 100, 0, 100, 0, 16, 0, 32, 0, 100, 0, 32, 63, 128, 0, 0,
    0, 0, 0, 5, 1, 145, 0, 230, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 100, 0, 100, 0, 16, 0, 32, 0, 100, 0, 32, 63, 128, 0, 0,
    0, 0, 0, 5, 1, 145, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 100, 0, 100, 0, 16, 0, 32, 0, 100, 0, 32, 63, 128, 0, 0,
    0, 0, 0, 5, 1, 145, 1, 26, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 200, 0, 200, 0, 16, 0, 32, 0, 200, 0, 32, 63, 128, 0, 0,
    2, 0, 2, 5, 0, 70, 0, 110, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 200, 0, 200, 0, 16, 0, 32, 0, 200, 0, 32, 63, 128, 0, 0,
    2, 0, 2, 5, 1, 114, 0, 110, 0, 0, 0, 0, 0, 0, 0, 0,
    6, 64, 6, 64, 0, 24, 0, 24, 6, 64, 0, 24, 63, 128, 0, 0,
    0, 0, 0, 5, 0, 50, 0, 78, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 24, 0, 24, 0, 24, 0, 24, 0, 24, 0, 24, 63, 128, 0, 0,
    2, 0, 2, 7, 0, 152, 0, 200, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 24, 0, 24, 0, 24, 0, 24, 0, 24, 0, 24, 63, 128, 0, 0,
    2, 0, 2, 7, 0, 200, 0, 200, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 24, 0, 24, 0, 24, 0, 24, 0, 24, 0, 24, 63, 128, 0, 0,
    2, 0, 2, 7, 0, 248, 0, 200, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 24, 0, 24, 0, 24, 0, 24, 0, 24, 0, 24, 63, 128, 0, 0,
    2, 0, 2, 7, 1, 40, 0, 200, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 24, 0, 24, 0, 24, 0, 24, 0, 24, 0, 24, 63, 128, 0, 0,
    2, 0, 2, 7, 1, 88, 0, 200, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 24, 0, 24, 0, 24, 0, 24, 0, 24, 0, 24, 63, 128, 0, 0,
    2, 0, 2, 7, 1, 136, 0, 200, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 24, 0, 24, 0, 24, 0, 24, 0, 24, 0, 24, 63, 128, 0, 0,
    2, 0, 2, 7, 1, 184, 0, 200, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 24, 0, 24, 0, 24, 0, 24, 0, 24, 0, 24, 63, 128, 0, 0,
    2, 0, 2, 7, 1, 232, 0, 200, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 24, 0, 24, 0, 24, 0, 24, 0, 24, 0, 24, 63, 128, 0, 0,
    2, 0, 2, 7, 0, 128, 0, 248, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 24, 0, 24, 0, 24, 0, 24, 0, 24, 0, 24, 63, 128, 0, 0,
    2, 0, 2, 7, 0, 176, 0, 248, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 24, 0, 24, 0, 24, 0, 24, 0, 24, 0, 24, 63, 128, 0, 0,
    2, 0, 2, 7, 0, 224, 0, 248, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 24, 0, 24, 0, 24, 0, 24,
};

u8 lbl_802C8048[1592] = {
    0, 24, 0, 24, 63, 128, 0, 0, 2, 0, 2, 7, 1, 16, 0, 248,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 0, 24, 0, 24, 0, 24,
    0, 24, 0, 24, 63, 128, 0, 0, 2, 0, 2, 7, 1, 64, 0, 248,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 0, 24, 0, 24, 0, 24,
    0, 24, 0, 24, 63, 128, 0, 0, 2, 0, 2, 7, 1, 112, 0, 248,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 0, 24, 0, 24, 0, 24,
    0, 24, 0, 24, 63, 128, 0, 0, 2, 0, 2, 7, 1, 160, 0, 248,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 0, 24, 0, 24, 0, 24,
    0, 24, 0, 24, 63, 128, 0, 0, 2, 0, 2, 7, 1, 208, 0, 248,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 0, 24, 0, 24, 0, 24,
    0, 24, 0, 24, 63, 128, 0, 0, 2, 0, 2, 7, 0, 104, 1, 40,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 0, 24, 0, 24, 0, 24,
    0, 24, 0, 24, 63, 128, 0, 0, 2, 0, 2, 7, 0, 152, 1, 40,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 0, 24, 0, 24, 0, 24,
    0, 24, 0, 24, 63, 128, 0, 0, 2, 0, 2, 7, 0, 200, 1, 40,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 0, 24, 0, 24, 0, 24,
    0, 24, 0, 24, 63, 128, 0, 0, 2, 0, 2, 7, 0, 248, 1, 40,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 0, 24, 0, 24, 0, 24,
    0, 24, 0, 24, 63, 128, 0, 0, 2, 0, 2, 7, 1, 40, 1, 40,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 0, 24, 0, 24, 0, 24,
    0, 24, 0, 24, 63, 128, 0, 0, 2, 0, 2, 7, 1, 88, 1, 40,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 0, 24, 0, 24, 0, 24,
    0, 24, 0, 24, 63, 128, 0, 0, 2, 0, 2, 7, 1, 136, 1, 40,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 0, 24, 0, 24, 0, 24,
    0, 24, 0, 24, 63, 128, 0, 0, 2, 0, 2, 7, 1, 184, 1, 40,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 0, 24, 0, 24, 0, 24,
    0, 24, 0, 24, 63, 128, 0, 0, 2, 0, 2, 7, 1, 232, 1, 40,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 0, 24, 0, 24, 0, 24,
    0, 24, 0, 24, 63, 128, 0, 0, 2, 0, 2, 7, 0, 200, 1, 88,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 0, 24, 0, 24, 0, 24,
    0, 24, 0, 24, 63, 128, 0, 0, 2, 0, 2, 7, 0, 248, 1, 88,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 0, 24, 0, 24, 0, 24,
    0, 24, 0, 24, 63, 128, 0, 0, 2, 0, 2, 7, 1, 40, 1, 88,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 48, 0, 48, 0, 24, 0, 24,
    0, 48, 0, 24, 63, 128, 0, 0, 2, 0, 2, 7, 1, 88, 1, 88,
    0, 0, 0, 0, 0, 0, 0, 0, 1, 144, 1, 144, 0, 24, 0, 24,
    1, 144, 0, 24, 63, 128, 0, 0, 2, 0, 2, 5, 0, 120, 0, 228,
    0, 0, 0, 0, 0, 0, 0, 0, 1, 144, 1, 144, 0, 24, 0, 24,
    1, 144, 0, 24, 63, 128, 0, 0, 2, 0, 2, 5, 0, 120, 0, 254,
    0, 0, 0, 0, 0, 0, 0, 0, 1, 144, 1, 144, 0, 24, 0, 24,
    1, 144, 0, 24, 63, 128, 0, 0, 2, 0, 2, 5, 0, 120, 1, 24,
    0, 0, 0, 0, 0, 0, 0, 0, 1, 144, 1, 144, 0, 24, 0, 24,
    1, 144, 0, 24, 63, 128, 0, 0, 2, 0, 2, 5, 0, 120, 1, 50,
    0, 0, 0, 0, 0, 0, 0, 0, 1, 144, 1, 144, 0, 24, 0, 24,
    1, 144, 0, 24, 63, 128, 0, 0, 2, 0, 2, 5, 0, 120, 1, 76,
    0, 0, 0, 0, 0, 0, 0, 0, 1, 104, 1, 104, 0, 16, 1, 164,
    1, 104, 1, 164, 63, 128, 0, 0, 2, 1, 2, 5, 0, 140, 0, 60,
    0, 0, 0, 0, 0, 0, 0, 0, 2, 48, 2, 48, 0, 45, 0, 45,
    2, 48, 0, 45, 63, 128, 0, 0, 3, 0, 3, 5, 0, 40, 1, 139,
    0, 0, 0, 0, 0, 0, 0, 0, 2, 48, 2, 48, 1, 224, 1, 224,
    2, 48, 1, 224, 63, 128, 0, 0, 2, 0, 2, 5, 0, 40, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 2, 0, 0, 25, 0, 25,
    2, 0, 0, 25, 63, 128, 0, 0, 2, 0, 2, 5, 0, 84, 1, 159,
    0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 2, 0, 1, 224, 1, 224,
    2, 0, 1, 224, 63, 128, 0, 0, 3, 0, 3, 5, 0, 84, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 48, 0, 48, 0, 56, 0, 56,
    0, 48, 0, 56, 63, 128, 0, 0, 2, 1, 2, 5, 0, 32, 1, 159,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 160, 0, 160, 0, 16, 1, 0,
    0, 160, 1, 0, 63, 128, 0, 0, 1, 0, 1, 5, 0, 140, 0, 60,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 160, 0, 160, 0, 16, 1, 0,
    0, 160, 1, 0, 63, 128, 0, 0, 0, 0, 0, 5, 1, 84, 0, 60,
    0, 0, 0, 0, 0, 0, 0, 0, 1, 84, 1, 84, 1, 44, 1, 44,
    1, 84, 1, 44, 63, 128, 0, 0, 2, 0, 2, 7, 0, 150, 0, 60,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 240, 0, 240, 1, 0, 1, 0,
    0, 240, 1, 0, 63, 128, 0, 0, 2, 0, 2, 7, 1, 104, 0, 60,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 112, 0, 192, 0, 100, 0, 100,
    0, 192, 0, 100, 63, 128, 0, 0, 2, 1, 2, 5, 0, 54, 1, 84,
    0, 0, 0, 0, 0, 0, 0, 0, 2, 128, 2, 128, 0, 100, 0, 100,
    2, 128, 0, 100, 63, 217, 153, 154, 2, 0, 2, 5, 0, 0, 0, 230,
    0, 0, 0, 0, 0, 0, 0, 0, 2, 128, 2, 128, 1, 94, 1, 94,
    2, 128, 1, 94, 63, 217, 153, 154, 2, 0, 2, 5, 0, 0, 0, 100,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 180, 0, 180, 1, 44, 1, 44,
    0, 180, 1, 44, 63, 128, 0, 0, 1, 0, 1, 5, 0, 120, 0, 90,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 180, 0, 180, 1, 44, 1, 44,
    0, 180, 1, 44, 63, 128, 0, 0, 0, 0, 0, 5, 1, 84, 0, 90,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 0, 24, 0, 24, 0, 24,
    0, 24, 0, 24, 63, 128, 0, 0, 2, 0, 2, 7, 0, 128, 0, 248,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 0, 24, 0, 24, 0, 24,
    0, 24, 0, 24, 63, 128, 0, 0, 2, 0, 2, 7, 0, 176, 0, 248,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 0, 24, 0, 24, 0, 24,
    0, 24, 0, 24, 63, 128, 0, 0, 2, 0, 2, 7, 0, 224, 0, 248,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 0, 24, 0, 24, 0, 24,
    0, 24, 0, 24, 63, 128, 0, 0, 2, 0, 2, 7, 1, 16, 0, 248,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 0, 24, 0, 24, 0, 24,
    0, 24, 0, 24, 63, 128, 0, 0, 2, 0, 2, 7, 1, 64, 0, 248,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 0, 24, 0, 24, 0, 24,
    0, 24, 0, 24, 63, 128, 0, 0, 2, 0, 2, 7, 0, 0, 0, 248,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 0, 24, 0, 24, 0, 24,
    0, 24, 0, 24, 63, 128, 0, 0, 2, 0, 2, 7, 0, 0, 0, 248,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 0, 24, 0, 24, 0, 24,
    0, 24, 0, 24, 63, 128, 0, 0, 2, 0, 2, 7, 0, 0, 0, 248,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 0, 24, 0, 24, 0, 24,
    0, 24, 0, 24, 63, 128, 0, 0, 2, 0, 2, 7, 0, 0, 0, 248,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 24, 0, 24, 0, 24, 0, 24,
    0, 24, 0, 24, 63, 128, 0, 0, 2, 0, 2, 7, 0, 0, 0, 248,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 1, 64, 0, 16, 0, 110,
    1, 64, 0, 110, 63, 128, 0, 0, 0, 1, 0, 7, 0, 250, 0, 150,
    0, 0, 0, 0, 0, 0, 0, 0, 2, 128, 2, 128, 1, 224, 1, 224,
    2, 128, 1, 224, 63, 128, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
};

FontSizeEntry lbl_802C8680[7] = {
    { { 0, 0, 14, 170, 21, 10, 2, 0, 0, 21 }, 21, { 0, 0, 0, 0 } },
    { { 0, 0, 0, 1, 14, 7, 1, 0, 0, 14 }, 21, { 0, 0, 0, 0 } },
    { { 0, 0, 0, 11, 30, 15, 1, 0, 0, 30 }, 22, { 0, 0, 0, 0 } },
    { { 0, 0, 0, 6, 32, 16, 1, 0, 0, 32 }, 24, { 0, 0, 0, 0 } },
    { { 0, 0, 0, 136, 21, 10, 2, 0, 0, 21 }, 21, { 0, 0, 0, 0 } },
    { { 0, 0, 0, 8, 46, 23, 1, 0, 0, 46 }, 55, { 0, 0, 0, 0 } },
    { { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, 0, { 0, 0, 0, 0 } },
};

SpecialGlyph lbl_802C86F0[46] = {
    { 0x0000F8F2, 0x00000002 },
    { 0x0000F8F3, 0x00000000 },
    { 0x0000F8F4, 0x00000001 },
    { 0x0000F8F5, 0x00000001 },
    { 0x0000F8F6, 0x00000001 },
    { 0x0000F8F7, 0x00000001 },
    { 0x0000F8F8, 0x00000000 },
    { 0x0000F8F9, 0x00000000 },
    { 0x0000F8FA, 0x00000000 },
    { 0x0000F8FB, 0x00000000 },
    { 0x0000F8FC, 0x00000000 },
    { 0x0000F8FD, 0x00000000 },
    { 0x0000F8FE, 0x00000000 },
    { 0x0000F8FF, 0x00000004 },
    { 0x0000E000, 0x00000001 },
    { 0x0000E018, 0x00000003 },
    { 0x0000E020, 0x00000001 },
    { 0x0000F8FF, 0x00000004 },
    { 0x0000F8FF, 0x00000004 },
    { 0x0000F8FF, 0x00000004 },
    { 0x0000F8FF, 0x00000004 },
    { 0x0000F8FF, 0x00000004 },
    { 0x0000F8FF, 0x00000004 },
    { 0x0000F8FF, 0x00000004 },
    { 0x0000F8FF, 0x00000004 },
    { 0x0000F8FF, 0x00000004 },
    { 0x0000F8FF, 0x00000004 },
    { 0x0000F8FF, 0x00000004 },
    { 0x0000F8FF, 0x00000004 },
    { 0x0000F8FF, 0x00000004 },
    { 0x0000F8FF, 0x00000004 },
    { 0x0000F8FF, 0x00000004 },
    { 0x0000F8FF, 0x00000004 },
    { 0x0000F8FF, 0x00000004 },
    { 0x0000F8FF, 0x00000004 },
    { 0x0000F8FF, 0x00000004 },
    { 0x0000F8FF, 0x00000004 },
    { 0x0000F8FF, 0x00000004 },
    { 0x0000F8FF, 0x00000004 },
    { 0x0000F8FF, 0x00000004 },
    { 0x0000F8FF, 0x00000004 },
    { 0x0000F8FF, 0x00000004 },
    { 0x0000F8FF, 0x00000004 },
    { 0x0000F8FF, 0x00000004 },
    { 0x0000F8FF, 0x00000004 },
    { 0x0000F8FF, 0x00000004 },
};

char* sMapDirectoryNameTable[74] = {
    sMapDirectoryNameAnimtest, sMapDirectoryNameArwing, sMapDirectoryNameBOSSAndross, sMapDirectoryNameBoot,
    sMapDirectoryNameBossDrakor, sMapDirectoryNameBossGaldon, sMapDirectoryNameBossTrex, sMapDirectoryNameCRFort,
    sMapDirectoryNameCapeClaw, sMapDirectoryNameCloudDungeon, sMapDirectoryNameCloudRace, sMapDirectoryNameCommunicator,
    sMapDirectoryNameDBShrine, sMapDirectoryNameDFPTop, sMapDirectoryNameDFShrine, sMapDirectoryNameDarkIceMines,
    sMapDirectoryNameDarkIceMines2, sMapDirectoryNameDesert, sMapDirectoryNameDragRock, sMapDirectoryNameDragRockBot,
    sMapDirectoryNameECShrine, sMapDirectoryNameFrontEnd, sMapDirectoryNameGPShrine, sMapDirectoryNameGameMaze,
    sMapDirectoryNameIceMountain, sMapDirectoryNameInsideGal, sMapDirectoryNameLINKG, sMapDirectoryNameLightFoot,
    sMapDirectoryNameLink, sMapDirectoryNameLinkB, sMapDirectoryNameLinkC, sMapDirectoryNameLinkD,
    sMapDirectoryNameLinkE, sMapDirectoryNameLinkF, sMapDirectoryNameLinkH, sMapDirectoryNameLinkJ,
    sMapDirectoryNameMMPass, sMapDirectoryNameMMShrine, sMapDirectoryNameMagicCave, sMapDirectoryNameNWShrine,
    sMapDirectoryNameNWastes, sMapDirectoryNameSequences, sMapDirectoryNameShipBattle, sMapDirectoryNameShop,
    sMapDirectoryNameSwapHol, sMapDirectoryNameTaskTexts000, sMapDirectoryNameTaskTexts001, sMapDirectoryNameTaskTexts002,
    sMapDirectoryNameTaskTexts003, sMapDirectoryNameTaskTexts004, sMapDirectoryNameTaskTexts005, sMapDirectoryNameTaskTexts006,
    sMapDirectoryNameTaskTexts007, sMapDirectoryNameTaskTexts008, sMapDirectoryNameTaskTexts009, sMapDirectoryNameTaskTexts010,
    sMapDirectoryNameTaskTexts011, sMapDirectoryNameTaskTexts012, sMapDirectoryNameTaskTexts013, sMapDirectoryNameTaskTexts014,
    sMapDirectoryNameTaskTexts015, sMapDirectoryNameTaskTexts016, sMapDirectoryNameTaskTexts017, sMapDirectoryNameTaskTexts018,
    sMapDirectoryNameTaskTexts019, sMapDirectoryNameTaskTexts021, sMapDirectoryNameTaskTexts022, sMapDirectoryNameTaskTexts023,
    sMapDirectoryNameTaskTexts024, sMapDirectoryNameVolcano, sMapDirectoryNameWallCity, sMapDirectoryNameWarlock,
    sMapDirectoryNameWorldMap, NULL,
};
