#include "main/engine_shared.h"

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
    int lineOff = 0;
    int charLen;
    int i;
    int* bp;
    int lineCount = 0;
    char** buffer;
    f32 scale;
    f32 maxWidth;
    int breakPos = 0;
    int lineIdx;
    int charLen2;
    int total;
    u32 ch;
    int* boundary;
    int cursor = 0;
    int haveSpace = 0;
    char* src;
    char* dst;
    int charPos;

    maxWidth = width;
    scale = height;
    penX = lbl_803DE704;
    if (gameTextCharset == 2)
    {
        langIdx = 6;
    }
    else
    {
        langIdx = sLanguageNameTable[curLanguage].sizeIdx;
    }
    sizeEntry = &lbl_802C8680[langIdx];

    *outCount = 0;
    if (outLineH != NULL)
    {
        *outLineH = (f32)(u32)
        sizeEntry->lineHeight * scale;
    }
    if (str == NULL)
    {
        return 0;
    }
    if (lbl_803DC9AA != 0 || lbl_803DC9A8 != 0)
    {
        maxWidth = (f32)(u32)
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
            SpecialGlyph* g = lbl_802C86F0;
            int n;
            int sel;
            for (n = 46; n != 0; n--)
            {
                if (g->key == ch)
                {
                    n = g->val;
                    break;
                }
                g++;
            }
            for (i = 0; i < n; i++)
            {
                int b0 = ((u8*)str)[cursor++];
                int b1 = ((u8*)str)[cursor++];
                params[i] = (b0 << 8) | b1;
            }
            sel = 1;
            switch (ch)
            {
            case 0xf8f4:
                scale = (f32)(int)
                params[0] * lbl_803DE708;
                break;
            case 0xf8f7:
                langIdx = params[0];
                sizeEntry = &lbl_802C8680[langIdx];
                break;
            default:
                sel = 0;
            }
            if (sel != 0 && langIdx != 5)
            {
                f32 lh = (f32)(u32)
                sizeEntry->lineHeight * scale;
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
                if (found->key == ch && found->lang == langIdx)
                {
                    goto gotGlyph;
                }
                found++;
            }
            found = NULL;
        gotGlyph:
            if (found != NULL)
            {
                int advance = found->fC + (found->f9 + found->f8);
                penX += scale * (f32)(int)
                advance;
                if (penX >= maxWidth)
                {
                    if (haveSpace == 0)
                    {
                        breakPos = cursor - charLen;
                    }
                    bp++;
                    lineCount++;
                    lineOff += 4;
                    *(int*)((char*)lineStarts + lineOff) = breakPos;
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

    lineCount++;
    lineOff = lineCount << 2;
    *(int*)((char*)lineStarts + lineOff) = cursor;
    *outCount = lineCount;
    if (cursor == 0)
    {
        return 0;
    }
    total = cursor + (lineCount + lineOff);
    if (outLineH != NULL)
    {
        buffer = mmAllocateFromFBMemoryStore(lbl_803DB378);
    }
    else
    {
        buffer = mmAlloc(total, 0, 0);
    }
    if (buffer == NULL)
    {
        return 0;
    }
    dst = (char*)buffer;
    i = total;
    while (i-- != 0)
    {
        *dst++ = 0;
    }

    dst = (char*)buffer + lineOff;
    buffer[0] = dst;
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
                while (1)
                {
                    ch = utf8GetNextChar((u8*)(dst - k), &charLen2);
                    if (k == charLen2)
                    {
                        if (!isSpace(ch))
                        {
                            goto foundBreak;
                        }
                        if (charLen2 != 0)
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
                    if (k <= 0)
                    {
                        break;
                    }
                }
            }
        foundBreak:
            q[1] = q[0];
            q[0] = 0;
            dst = q + 1;
            *(char**)((char*)buffer + ((lineIdx + 1) << 2)) = dst;
            dst++;
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

void textDisplayFn_800168dc(int textId, TextDisplayState* state)
{
    GameTextDef* def;
    int charCount;
    int byteOffset;
    char* lineStr;
    int special;
    u32 ch;
    int charLen;

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
    charCount = 0;
    byteOffset = 0;
    if (lineStr != NULL)
    {
        while ((ch = utf8GetNextChar((u8*)(lineStr + byteOffset), &charLen)) != 0)
        {
            byteOffset += charLen;
            if (ch >= 0xe000 && ch <= 0xf8ff)
            {
                int n;
                SpecialGlyph* g = lbl_802C86F0;
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
        Sfx_PlayFromObject(0, 0x397);
    }
    lbl_803DC99C = 1;
    lbl_803DC998 = 0;
    lbl_803DC994 = timeDelta * lbl_803DB3D0 + lbl_803DC994;
    if (lbl_803DC994 >= (f32)(charCount - 2))
    {
        Sfx_StopFromObject(0, 0x397);
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
