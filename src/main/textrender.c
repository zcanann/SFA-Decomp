#include "ghidra_import.h"
#include "main/audio/sfx.h"

extern int saveFileStruct_isCheatActive();
extern void mm_free(void* ptr);

undefined2*
FUN_80017460(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9
             , int param_10, undefined4 param_11, undefined4 param_12, undefined4 param_13,
             undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
    return 0;
}

undefined2*
FUN_80017468(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9
             , undefined4 param_10, undefined4 param_11, undefined4 param_12, undefined4 param_13,
             undefined4 param_14, undefined4 param_15, undefined4 param_16)
{
    return 0;
}

extern int curLanguage;
extern u8* gameTextFonts;
extern void* gameTextDrawFunc;
extern char* sLanguageNameTable[][2];
extern u8 gTextBoxes[];
extern u8 lbl_802C8680[];
extern f32 lbl_803DE704;
extern f32 lbl_803DE708;
extern f32 lbl_803DE70C;
extern f32 lbl_803DE710;
extern f32 lbl_803DE714;
extern f32 lbl_803DE718;
extern f32 lbl_803DC9A0;
extern f32 lbl_803DC994;
extern u8 lbl_803DC9A4;
extern u8 lbl_803DC9A5;
extern u8 lbl_803DC9A6;
extern u8 lbl_803DC9A7;
extern int lbl_803DC9BC;
extern int lbl_803DC9B0;
extern int lbl_803DC9AC;
extern int lbl_803DC9B8;
extern int lbl_803DC9B4;
extern int lbl_803DC998;
extern int lbl_803DC98C;
extern int lbl_803DC988;
extern int lbl_803DC99C;
extern int gameTextCharset;
extern int lbl_803DB3CC;

typedef struct
{
    u32 key;
    int len;
} CtrlCharEntry;

extern CtrlCharEntry lbl_802C86F0[];

#pragma scheduling off
#pragma peephole off
int getControlCharLen(u32 c)
{
    CtrlCharEntry* p = lbl_802C86F0;
    int i;
    for (i = 45; i >= 0; i--)
    {
        if (p->key == c)
        {
            return p->len;
        }
        p++;
    }
    return 0;
}

extern int utf8GetNextChar(u8* p, int* outLen);
void gameTextMeasureString(u8* str, f32 scale, f32* outW, f32* outZero, f32* outMaxAdv, f32* outMaxH, int glyphLang);
extern void translateToDinoLanguage(u8 * str);
extern void setTextColor(int a, int r, int g, int b, int al);
extern void _textSetColor(int a, int r, int g, int b, int al);
extern void textureSetupFn_800799c0(void);
extern void textRenderSetup(void);
extern void textRenderSetupFn_80079804(void);
extern void textRenderSetupFn_800795e8(void);
extern void textBlendSetupFn_80078a7c(void);
extern void selectTexture(void* tex, int a);
extern void GXGetScissor(u32 * a, u32 * b, u32 * c, u32 * d);
extern void GXSetScissor(u32 a, u32 b, u32 c, u32 d);
extern void gxSetScissorRect(int a, int b, int c, int d, int e, int f);
extern void textRenderChar(int x0, int y0, int x1, int y1, f32 u0, f32 v0, f32 u1, f32 v1);

void textRenderStr(u8* str, u8* win, f32 x, f32 y, f32 lineH, int mode)
{
    int byteOff;
    int glyphLang;
    int curTexPage;
    int realign;
    u32 ch;
    int charLen;
    int n2;
    int i;
    int cnt;
    int skipGlyph;
    u8* p;
    u8* g;
    u8* winBase;
    void* tex;
    f32 spaceExtra;
    f32 measW;
    f32 measN;
    f32 fx0, fy0, fx1, fy1;
    f32 u0, v0;
    int params[8];
    u32 scisX, scisY, scisW, scisH;

    byteOff = 0;
    spaceExtra = lbl_803DE704;
    if (gameTextCharset == 2)
    {
        glyphLang = 6;
    }
    else
    {
        {
            u8* tbl = (u8*)sLanguageNameTable;
            glyphLang = tbl[curLanguage * 8 + 4];
        }
    }
    curTexPage = -1;
    realign = 1;
    if (str == NULL)
    {
        return;
    }
    if (*(int*)(gameTextFonts + 0x1c) != 2)
    {
        return;
    }

    if (curLanguage != 4 && mode == 1 && saveFileStruct_isCheatActive(3) &&
        win == gTextBoxes + 0x140)
    {
        translateToDinoLanguage(str);
    }

    gameTextMeasureString(str, lbl_803DC9A0, &measW, &measN, 0, 0, -1);
    if (lbl_803DC9BC == 0)
    {
        setTextColor(0, lbl_803DC9A7, lbl_803DC9A6, lbl_803DC9A5, lbl_803DC9A4);
        _textSetColor(0, lbl_803DC9A7, lbl_803DC9A6, lbl_803DC9A5, lbl_803DC9A4);
        textureSetupFn_800799c0();
        textRenderSetup();
        textRenderSetupFn_80079804();
        textBlendSetupFn_80078a7c();
    }

    x = x + (f32) * (s16*)(win + 0x14);
    y = y + (f32) * (s16*)(win + 0x16);
    winBase = gTextBoxes;

    while (p = str + byteOff, (ch = utf8GetNextChar(p, &charLen)) != 0)
    {
        byteOff += charLen;
        skipGlyph = 0;
        if (ch >= 0xe000 && ch <= 0xf8ff)
        {
            n2 = getControlCharLen(ch);
            for (i = 0; i < n2; i++)
            {
                int hi = str[byteOff++];
                int lo = str[byteOff++];
                params[i] = (hi << 8) | lo;
            }
            if ((u32)(ch - 0xf8f4) <= 0xb)
            {
                switch (ch)
                {
                case 0xf8f4:
                    lbl_803DC9A0 = (f32)params[0] * lbl_803DE708;
                    break;
                case 0xf8f7:
                    glyphLang = params[0];
                    break;
                case 0xf8f8:
                    win[0x12] = 0;
                    realign = 1;
                    break;
                case 0xf8f9:
                    win[0x12] = 1;
                    realign = 1;
                    break;
                case 0xf8fa:
                    win[0x12] = 2;
                    realign = 1;
                    break;
                case 0xf8fb:
                    win[0x12] = 3;
                    realign = 1;
                    break;
                case 0xf8ff:
                    if (mode == 0)
                    {
                        {
                            u8 c3 = params[3] * (lbl_803DC9A4 + 1) >> 8;
                            u8 c2 = params[2];
                            u8 c1 = params[1];
                            u8 c0 = params[0];
                            lbl_803DC9A7 = c0;
                            lbl_803DC9A6 = c1;
                            lbl_803DC9A5 = c2;
                            lbl_803DC9A4 = c3;
                        }
                        if (lbl_803DC9BC == 0)
                        {
                            setTextColor(0, lbl_803DC9A7, lbl_803DC9A6, lbl_803DC9A5, lbl_803DC9A4);
                            _textSetColor(0, lbl_803DC9A7, lbl_803DC9A6, lbl_803DC9A5, lbl_803DC9A4);
                            textureSetupFn_800799c0();
                            textRenderSetup();
                            textRenderSetupFn_80079804();
                            textBlendSetupFn_80078a7c();
                        }
                    }
                    skipGlyph = 1;
                    break;
                }
            }
            if (skipGlyph)
            {
                continue;
            }
        }
        else
        {
            if (mode == 0)
            {
                lbl_803DC998++;
            }
        }

        if (realign != 0)
        {
            switch (win[0x12])
            {
            case 0:
                spaceExtra = lbl_803DE704;
                break;
            case 1:
                spaceExtra = lbl_803DE704;
                gameTextMeasureString(p, lbl_803DC9A0, &measW, NULL, 0, 0, -1);
                x = (f32) * (s16*)(win + 0x14) +
                    ((f32)(u32) * (u16*)(win + 8) - measW);
                break;
            case 2:
                spaceExtra = lbl_803DE704;
                gameTextMeasureString(p, lbl_803DC9A0, &measW, NULL, 0, 0, -1);
                x = ((f32)(u32) * (u16*)(win + 8) - measW) * lbl_803DE70C +
                    (f32) * (s16*)(win + 0x14);
                break;
            case 3:
                {
                    int acc;
                    int spaceCount;
                    u32 innerCh;
                    int innerLen;
                    gameTextMeasureString(p, lbl_803DC9A0, &measW, NULL, 0, 0, -1);
                    acc = 0;
                    spaceCount = acc;
                    while ((innerCh = utf8GetNextChar(p + acc, &innerLen)) != 0)
                    {
                        acc += innerLen;
                        if (innerCh == 0x20)
                        {
                            spaceCount++;
                        }
                        if (innerCh >= 0xe000 && innerCh <= 0xf8ff)
                        {
                            acc += getControlCharLen(innerCh) * 2;
                        }
                    }
                    spaceExtra = ((f32)(u32) * (u16*)(win + 8) - measW) / (f32)spaceCount;
                    break;
                }
            }
            realign = 0;
        }

        g = *(u8**)gameTextFonts;
        cnt = *(int*)(gameTextFonts + 8);
        while (cnt-- != 0)
        {
            if (*(u32*)g == (u32)ch && g[0xe] == glyphLang)
            {
                goto matched;
            }
            g += 0x10;
        }
        g = NULL;
    matched:
        if (g == NULL)
        {
            continue;
        }

        if (ch == 0xa)
        {
            x = lbl_803DE704;
            y = y + lineH;
            continue;
        }
        if (ch == 0x20)
        {
            x = lbl_803DC9A0 * (f32)(g[0xc] + (*(s8*)(g + 9) + *(s8*)(g + 8))) + x;
            x = x + spaceExtra;
            continue;
        }

        u0 = (f32)(*(u16*)(g + 4) << 5);
        v0 = (f32)(*(u16*)(g + 6) << 5);
        fx0 = (f32) * (s8*)(g + 8) * lbl_803DC9A0;
        fx0 = x + fx0;
        fx0 = lbl_803DE710 * fx0;
        fy0 = (f32) * (s8*)(g + 0xa) * lbl_803DC9A0;
        fy0 = y + fy0;
        fy0 = lbl_803DE710 * fy0;
        fx1 = lbl_803DE710 * ((f32)(u32)
        g[0xc] * lbl_803DC9A0
        )
        +fx0;
        fy1 = lbl_803DE710 * ((f32)(u32)
        g[0xd] * lbl_803DC9A0
        )
        +fy0;
        if (fx0 < lbl_803DE704 && fx1 > lbl_803DE704)
        {
            u0 = lbl_803DE714 * -fx0 + u0;
            fx0 = lbl_803DE704;
        }
        if (fy0 < lbl_803DE704 && fy1 > lbl_803DE704)
        {
            v0 = lbl_803DE714 * -fy0 + v0;
            fy0 = lbl_803DE704;
        }

        if (lbl_803DC9BC != 0)
        {
            if (fx0 < (f32)lbl_803DC9B0)
            {
                lbl_803DC9B0 = (int)fx0;
            }
            if (fx1 > (f32)lbl_803DC9AC)
            {
                lbl_803DC9AC = (int)fx1;
            }
            if (fy0 < (f32)lbl_803DC9B8)
            {
                lbl_803DC9B8 = (int)fy0;
            }
            if (fy1 > (f32)lbl_803DC9B4)
            {
                lbl_803DC9B4 = (int)fy1;
            }
        }
        else
        {
            if (g[0xe] == 3)
            {
                int shift = lbl_803DB3CC << 2;
                fy0 = fy0 - (f32)shift;
                fy1 = fy1 - (f32)shift;
                GXGetScissor(&scisX, &scisY, &scisW, &scisH);
                GXSetScissor(scisX, (scisY >= lbl_803DB3CC) ? scisY - lbl_803DB3CC : 0, scisW, scisH);
            }
            if (g[0xe] == 5)
            {
                int iw = g[0xc] + (*(s8*)(g + 9) + *(s8*)(g + 8));
                int ih = g[0xd] + (*(s8*)(g + 0xb) + *(s8*)(g + 0xa));
                GXGetScissor(&scisX, &scisY, &scisW, &scisH);
                gxSetScissorRect(0, 0, *(s16*)(winBase + 0xfd4), *(s16*)(winBase + 0xfd6),
                                 *(s16*)(winBase + 0xfd4) + *(u16*)(winBase + 0xfc8),
                                 *(s16*)(winBase + 0xfd6) + *(u16*)(winBase + 0xfca));
                fx0 = (f32)(*(s16*)(winBase + 0xfd4) + ((*(u16*)(winBase + 0xfc8) - iw) >> 1));
                fx1 = fx0 + (f32)iw;
                fy0 = (f32)(*(s16*)(winBase + 0xfd6) + ((*(u16*)(winBase + 0xfca) - ih) >> 1));
                fy1 = fy0 + (f32)ih;
                fx0 = fx0 * lbl_803DE710;
                fx1 = fx1 * lbl_803DE710;
                fy0 = fy0 * lbl_803DE710;
                fy1 = fy1 * lbl_803DE710;
            }

            if (mode != 0)
            {
                int ox = lbl_803DC98C;
                int oy = lbl_803DC988;
                fx0 = fx0 + (f32)ox;
                fx1 = fx1 + (f32)ox;
                fy0 = fy0 + (f32)oy;
                fy1 = fy1 + (f32)oy;
            }

            if (lbl_803DC9BC == 0)
            {
                if (curTexPage != g[0xf])
                {
                    curTexPage = g[0xf];
                    tex = *(void**)(gameTextFonts + 0x10 + g[0xf] * 4);
                    selectTexture(tex, 0);
                    if (lbl_802C8680[g[0xe] * 16 + 6] == 1)
                    {
                        if (mode != 0)
                        {
                            setTextColor(0, 0, 0, 0, lbl_803DC9A4);
                        }
                        else
                        {
                            setTextColor(0, 0xff, 0xff, 0xff, lbl_803DC9A4);
                            textureSetupFn_800799c0();
                            textRenderSetupFn_800795e8();
                            textRenderSetupFn_80079804();
                        }
                    }
                    else
                    {
                        setTextColor(0, lbl_803DC9A7, lbl_803DC9A6, lbl_803DC9A5, lbl_803DC9A4);
                        _textSetColor(0, lbl_803DC9A7, lbl_803DC9A6, lbl_803DC9A5, lbl_803DC9A4);
                        textureSetupFn_800799c0();
                        textRenderSetup();
                        textRenderSetupFn_80079804();
                    }
                }
            }

            if (lbl_803DC99C != 0 && mode == 0 && g[0xe] != 5 &&
                (f32)lbl_803DC998 >= lbl_803DC994)
            {
                setTextColor(0, 0, 0, 0, 0);
            }

            if (gameTextDrawFunc != NULL)
            {
                f32 sW = lbl_803DE718 * (f32)(u32) * (u16*)((u8*)tex + 0xa);
                f32 sH = lbl_803DE718 * (f32)(u32) * (u16*)((u8*)tex + 0xc);
                ((void (*)(int, int, int, int, f32, f32, f32, f32))gameTextDrawFunc)(
                    (int)fx0, (int)fy0, (int)fx1, (int)fy1,
                    u0 / sW, v0 / sH,
                    (u0 + (f32)(g[0xc] << 5)) / sW,
                    (v0 + (f32)(g[0xd] << 5)) / sH);
            }
            else
            {
                f32 sW = lbl_803DE718 * (f32)(u32) * (u16*)((u8*)tex + 0xa);
                f32 sH = lbl_803DE718 * (f32)(u32) * (u16*)((u8*)tex + 0xc);
                textRenderChar((int)fx0, (int)fy0, (int)fx1, (int)fy1,
                               u0 / sW, v0 / sH,
                               (u0 + (f32)(g[0xc] << 5)) / sW,
                               (v0 + (f32)(g[0xd] << 5)) / sH);
            }

            if (g[0xe] == 3 || g[0xe] == 5)
            {
                GXSetScissor(scisX, scisY, scisW, scisH);
            }
        }

        if ((int)g[0xe] != 5)
        {
            x = lbl_803DC9A0 * (f32)(g[0xc] + (*(s8*)(g + 9) + *(s8*)(g + 8))) + x;
        }
    }
}

void gameTextMeasureString(u8* str, f32 scale, f32* outW, f32* outZero, f32* outMaxAdv, f32* outMaxH, int glyphLang)
{
    int byteOff;
    u32 ch;
    int charLen;
    int n2;
    int i;
    int cnt;
    u8* p;
    u8* g;
    u8* tbl;
    f32 width;
    f32 mAdv;
    f32 mH;
    int params[8];

    byteOff = 0;
    width = lbl_803DE704;
    if (str == NULL)
    {
        return;
    }
    if (glyphLang == -1)
    {
        if (gameTextCharset == 2)
        {
            glyphLang = 6;
        }
        else
        {
            glyphLang = ((u8*)sLanguageNameTable)[curLanguage * 8 + 4];
        }
    }
    tbl = &lbl_802C8680[glyphLang * 16];
    if (glyphLang != 5)
    {
        if (outMaxAdv != NULL)
        {
            *outMaxAdv = (f32)(u32) * (u16*)(tbl + 8) * scale;
        }
        if (outMaxH != NULL)
        {
            *outMaxH = (f32)(u32) * (u16*)(tbl + 0xa) * scale;
        }
    }

    while (p = str + byteOff, (ch = utf8GetNextChar(p, &charLen)) != 0)
    {
        byteOff += charLen;
        if (ch >= 0xe000 && ch <= 0xf8ff)
        {
            n2 = getControlCharLen(ch);
            for (i = 0; i < n2; i++)
            {
                int hi = str[byteOff++];
                int lo = str[byteOff++];
                params[i] = (hi << 8) | lo;
            }
            switch (ch)
            {
            case 0xf8f7:
                glyphLang = params[0];
                tbl = &lbl_802C8680[glyphLang * 16];
                if (glyphLang != 5)
                {
                    mAdv = (f32)(u32) * (u16*)(tbl + 8) * scale;
                    if (outMaxAdv != NULL && mAdv > *outMaxAdv)
                    {
                        *outMaxAdv = mAdv;
                    }
                    mH = (f32)(u32) * (u16*)(tbl + 0xa) * scale;
                    if (outMaxH != NULL && mH > *outMaxH)
                    {
                        *outMaxH = mH;
                    }
                }
                break;
            case 0xf8f4:
                scale = (f32)params[0] * lbl_803DE708;
                break;
            }
            continue;
        }

        g = *(u8**)gameTextFonts;
        cnt = *(int*)(gameTextFonts + 8);
        while (cnt-- != 0)
        {
            if (*(u32*)g == (u32)ch && g[0xe] == glyphLang)
            {
                goto matched;
            }
            g += 0x10;
        }
        g = NULL;
    matched:
        if (g == NULL)
        {
            continue;
        }
        if (glyphLang == 5)
        {
            continue;
        }
        width = scale * (f32)(g[0xc] + (*(s8*)(g + 9) + *(s8*)(g + 8))) + width;
    }

    if (outW != NULL)
    {
        *outW = width;
    }
    if (outZero != NULL)
    {
        *outZero = lbl_803DE704;
    }
}

extern u8 sGameTextGlyphOrder[];

void translateToDinoLanguage(u8* str)
{
    int byteOff = 0;
    u32 ch;
    int charLen;
    u8* p;

    if (str == NULL)
    {
        return;
    }
    while (p = str + byteOff, (ch = utf8GetNextChar(p, &charLen)) != 0)
    {
        if (ch >= 0xe000 && ch <= 0xf8ff)
        {
            byteOff += getControlCharLen(ch) * 2;
        }
        else
        {
            int base;
            if (ch >= 0x61 && ch <= 0x7a)
            {
                base = 0x61;
            }
            else if (ch >= 0x41 && ch <= 0x5a)
            {
                base = 0x41;
            }
            else
            {
                base = 0;
            }
            if (base != 0)
            {
                *p = sGameTextGlyphOrder[ch - base] + base - 0x61;
            }
        }
        byteOff += charLen;
    }
}

extern char lbl_802C8F40[];
extern u8 lbl_80339980[];
extern u8 lbl_803399A0[];
extern u8 lbl_803399C0[];
extern int lbl_803DC970;
extern u8* lbl_803DC974;
extern int gCurTextBuffer;
extern int lbl_803DC97C;
extern f32 timeDelta;
extern f32 lbl_803DE71C;
extern char lbl_803DB3D4[];
extern char* sMapDirectoryNameTable[];
extern void* curGameTextDir;
extern void* gameTextGet();
extern int sprintf(char* dst, const char* fmt, ...);

#pragma peephole on
void* gameTextGetPhrase(int textId, int phraseIndex)
{
    char* strings;
    u16* entry;

    strings = lbl_802C8F40;
    if (*(int*)(gameTextFonts + 0x1c) != 2)
    {
        lbl_803DC97C = lbl_803DC97C + 1;
        if (lbl_803DC97C >= 8)
        {
            lbl_803DC97C = 0;
        }
        entry = (u16*)(lbl_803399C0 + lbl_803DC97C * 0xc);
        lbl_803DC974 = (u8*)entry;
        gCurTextBuffer = *(int*)*(int**)((u8*)entry + 8);
        *entry = 0xffff;
        lbl_803DC970 = (int)(lbl_803399A0 + lbl_803DC97C * 4);
        switch (*(int*)(gameTextFonts + 0x1c))
        {
        case 0:
            sprintf((char*)gCurTextBuffer, strings + 0xec4);
            break;
        case 1:
            sprintf((char*)gCurTextBuffer, strings + 0xed4);
            break;
        case 3:
            sprintf((char*)gCurTextBuffer, strings + 0xee0);
            break;
        case 4:
            sprintf((char*)gCurTextBuffer, strings + 0xef0);
            break;
        }
        return lbl_803DC974;
    }

    entry = gameTextGet();
    if (*entry == 0xffff)
    {
        lbl_803DC97C = lbl_803DC97C + 1;
        if (lbl_803DC97C >= 8)
        {
            lbl_803DC97C = 0;
        }
        entry = (u16*)(lbl_803399C0 + lbl_803DC97C * 0xc);
        lbl_803DC974 = (u8*)entry;
        gCurTextBuffer = *(int*)*(int**)((u8*)entry + 8);
        *entry = 0xffff;
        lbl_803DC970 = (int)(lbl_803399A0 + lbl_803DC97C * 4);
        sprintf((char*)gCurTextBuffer, strings + 0xefc, textId,
                sMapDirectoryNameTable[(int)curGameTextDir]);
        return lbl_803DC974;
    }

    if (phraseIndex >= entry[1])
    {
        lbl_803DC97C = lbl_803DC97C + 1;
        if (lbl_803DC97C >= 8)
        {
            lbl_803DC97C = 0;
        }
        entry = (u16*)(lbl_803399C0 + lbl_803DC97C * 0xc);
        lbl_803DC974 = (u8*)entry;
        gCurTextBuffer = *(int*)*(int**)((u8*)entry + 8);
        *entry = 0xffff;
        lbl_803DC970 = (int)(lbl_803399A0 + lbl_803DC97C * 4);
        sprintf((char*)gCurTextBuffer, strings + 0xf10, textId, phraseIndex);
        return lbl_803DC974;
    }

    return *(void**)(*(int*)((u8*)entry + 8) + phraseIndex * 4);
}

void* gameTextGetStr(int textId)
{
    u8* entry;
    char* strings;
    void* t;

    strings = lbl_802C8F40;
    if (*(int*)(gameTextFonts + 0x1c) != 2)
    {
        lbl_803DC97C = lbl_803DC97C + 1;
        if (lbl_803DC97C >= 8)
        {
            lbl_803DC97C = 0;
        }
        entry = lbl_803399C0 + lbl_803DC97C * 0xc;
        lbl_803DC974 = entry;
        gCurTextBuffer = *(int*)*(int**)(entry + 8);
        *(u16*)entry = 0xffff;
        lbl_803DC970 = (int)(lbl_803399A0 + *(volatile int*)&lbl_803DC97C * 4);
        switch (*(int*)(gameTextFonts + 0x1c))
        {
        case 0:
            sprintf((char*)*(volatile int*)&gCurTextBuffer, strings + 0xec4);
            break;
        case 1:
            sprintf((char*)*(volatile int*)&gCurTextBuffer, strings + 0xed4);
            break;
        case 3:
            sprintf((char*)*(volatile int*)&gCurTextBuffer, strings + 0xee0);
            break;
        case 4:
            sprintf((char*)*(volatile int*)&gCurTextBuffer, strings + 0xef0);
            break;
        }
        return lbl_803DC974;
    }
    t = gameTextGet();
    return *(void**)*(u8**)((u8*)t + 8);
}

void* gameTextGet(int textId)
{
    u8* gameTextBase;
    char* strings;
    u8* fonts;
    u16* entry;
    int count;
    int slotIndex;
    u16* cachedEntry;
    u16* prevCachedEntry;
    f32 zero;
    f32 fadeLimit;
    f32* cachedAlpha;

    gameTextBase = lbl_80339980;
    strings = lbl_802C8F40;
    fonts = gameTextFonts;

    if (*(int*)(fonts + 0x1c) != 2)
    {
        lbl_803DC97C++;
        if (lbl_803DC97C >= 8)
        {
            lbl_803DC97C = 0;
        }
        entry = (u16*)(gameTextBase + 0x40 + *(volatile int*)&lbl_803DC97C * 0xc);
        lbl_803DC974 = (u8*)entry;
        gCurTextBuffer = *(int*)*(int**)((u8*)entry + 8);
        *entry = 0xffff;
        lbl_803DC970 = (int)(gameTextBase + 0x20 + *(volatile int*)&lbl_803DC97C * 4);

        switch (*(int*)(gameTextFonts + 0x1c))
        {
        case 0:
            sprintf((char*)*(volatile int*)&gCurTextBuffer, (char*)strings + 0xec4);
            break;
        case 1:
            sprintf((char*)*(volatile int*)&gCurTextBuffer, (char*)strings + 0xed4);
            break;
        case 3:
            sprintf((char*)*(volatile int*)&gCurTextBuffer, (char*)strings + 0xee0);
            break;
        case 4:
            sprintf((char*)*(volatile int*)&gCurTextBuffer, (char*)strings + 0xef0);
            break;
        }
        return lbl_803DC974;
    }

    entry = *(u16**)(fonts + 4);
    count = *(int*)(fonts + 0xc);
    while (count != 0)
    {
        if (*entry == textId)
        {
            return entry;
        }
        entry += 6;
        count--;
    }

    slotIndex = 8;
    cachedEntry = (u16*)(gameTextBase + 0xa0);
    while (1)
    {
        prevCachedEntry = cachedEntry;
        cachedEntry = prevCachedEntry - 6;
        if (slotIndex == 0)
        {
            break;
        }
        slotIndex--;
        if (*cachedEntry == textId)
        {
            zero = lbl_803DE704;
            *(f32*)(gameTextBase + slotIndex * 4) = zero;
            cachedAlpha = (f32*)(gameTextBase + 0x20 + slotIndex * 4);
            fadeLimit = lbl_803DE71C;
            if (zero < fadeLimit)
            {
                *cachedAlpha = zero + timeDelta;
                if (*cachedAlpha >= fadeLimit)
                {
                    sprintf((char*)*(int*)*(int**)((u8*)cachedEntry + 8), strings + 0xefc, textId,
                            sMapDirectoryNameTable[(int)curGameTextDir]);
                }
            }
            return cachedEntry;
        }
    }

    lbl_803DC97C++;
    if (lbl_803DC97C >= 8)
    {
        lbl_803DC97C = 0;
    }
    entry = (u16*)(gameTextBase + 0x40 + lbl_803DC97C * 0xc);
    lbl_803DC974 = (u8*)entry;
    gCurTextBuffer = *(int*)*(int**)((u8*)entry + 8);
    *entry = 0xffff;
    lbl_803DC970 = (int)(gameTextBase + 0x20 + lbl_803DC97C * 4);
    sprintf((char*)gCurTextBuffer, lbl_803DB3D4, textId,
            sMapDirectoryNameTable[(int)curGameTextDir]);
    *(u16*)lbl_803DC974 = (u16)textId;
    *(f32*)lbl_803DC970 = lbl_803DE704;
    return lbl_803DC974;
}

undefined4
#pragma scheduling on
FUN_80017500(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9)
{
    return 0;
}

undefined4
FUN_8001786c(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, undefined4 param_9,
             undefined4 param_10, undefined4 param_11, undefined4 param_12)
{
    return 0;
}

undefined*
FUN_80017998(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9
)
{
    return 0;
}

extern u8 framesThisStep;

int getGameState(void);

int getHudHiddenFrameCount(void);

int getCurLanguage(void)
{
    return curLanguage;
}

#pragma dont_inline on
void* getCurGameText(void)
{
    return curGameTextDir;
}

int gameTextGetCharset(void)
{
    return gameTextCharset;
}

#pragma dont_inline off
void gameTextSetDrawFunc(void* fn)
{
    gameTextDrawFunc = fn;
}

extern void* mmAlloc(int size, int type, int flag);
extern void textureFree(void* tex);

f32 gameTextFn_80019c00(void)
{
    return *(f32*)(gameTextFonts + 0x20);
}

typedef struct
{
    u8 _pad[0x1c];
    int state;
    u8 _pad2[8];
} GameTextStateElem;

extern GameTextStateElem lbl_8033AF40[];

#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
int gameTextGetState(int i)
{
    return lbl_8033AF40[i].state;
}

extern void subtitleBuildLineTable(void);
extern int lbl_803DC9F0;
extern int lbl_803DCA04;
extern void* lbl_803DC9F8;

#pragma dont_inline off
void mainLoopDoGameText(void)
{
    if (lbl_803DC9F0 != 0)
    {
        if (gameTextGetState(1) == 2 && lbl_803DCA04 == 1)
        {
            subtitleBuildLineTable();
        }
    }
    else
    {
        if (gameTextGetState(0) == 2 && (int)lbl_803DC9F8 == (int)getCurGameText() &&
            lbl_803DCA04 == 1)
        {
            subtitleBuildLineTable();
        }
    }
}

int mmSetFreeDelay(int v);

int testAndSet_onlyUseHeap3(int v);

extern void* textureLoadAsset(int assetId);

extern void gameTextInitFn_8001c794(void);
extern void gameTextLoadDir(int dirId);
extern u8 lbl_803DC980;

void gameTextInit(void)
{
    gameTextInitFn_8001c794();
    lbl_803DC980 = 1;
    gameTextLoadDir(0x1c);
}

void mm_free(void* p);

extern void subtitleFn_8001b700(void);
extern int lbl_803DCA00;
extern s16 lbl_803DC9AA;
extern s16 lbl_803DC9A8;
extern int lbl_803DC9C8;

typedef struct
{
    int v;
    int f4;
    int f8;
    int fc;
    int f10;
} GameTextSlot;

extern GameTextSlot lbl_8033A540[];

int setSubtitlesEnabled(int enabled)
{
    int old = lbl_803DCA00;
    lbl_803DCA00 = enabled;
    if (enabled == 0)
    {
        subtitleFn_8001b700();
    }
    return old;
}

extern int lbl_803DB3C8;
extern void hudDrawRect(int x0, int y0, int x1, int y1, void* color);
extern int lbl_803DC9D8;
extern int subtitleIsActive(void);
extern int gameTextFn_8001b44c(int x);
extern void gameTextLoadForCurMap(int sourceId);

#pragma dont_inline on
void gameTextSetCharset(int charset, int flags)
{
    if (gameTextDrawFunc != NULL || (flags & 1))
    {
        gameTextFonts = (u8*)&lbl_8033AF40[charset];
        gameTextCharset = charset;
        if (charset == 2)
        {
            int color = lbl_803DB3C8;
            hudDrawRect(0, 0, 0xa00, 0x780, &color);
            lbl_803DC99C = 0;
        }
    }
    if (gameTextDrawFunc == NULL || (flags & 2))
    {
        int i = lbl_803DC9C8;
        GameTextSlot* s;
        lbl_803DC9C8 = i + 1;
        s = &lbl_8033A540[i];
        s->v = 0xf;
        s->f4 = charset;
    }
}

#pragma dont_inline off
void gameTextLoadDir(int dirId)
{
    GameTextSlot* cmd;
    int color;
    int slotIndex;

    lbl_803DC9A7 = 0xff;
    lbl_803DC9A6 = 0xff;
    lbl_803DC9A5 = 0xff;
    lbl_803DC9A4 = 0xff;

    if (dirId == 3)
    {
        gameTextFonts = (u8*)&lbl_8033AF40[2];
        gameTextCharset = 2;
        color = lbl_803DB3C8;
        hudDrawRect(0, 0, 0xa00, 0x780, &color);
        lbl_803DC99C = 0;
        if (gameTextDrawFunc == NULL)
        {
            slotIndex = lbl_803DC9C8;
            lbl_803DC9C8 = slotIndex + 1;
            cmd = &lbl_8033A540[slotIndex];
            cmd->v = 0xf;
            cmd->f4 = 2;
        }
    }
    else if (dirId == 0x1c)
    {
        curGameTextDir = (void*)dirId;
        gameTextFonts = (u8*)&lbl_8033AF40[3];
        gameTextCharset = 3;
        if (gameTextDrawFunc == NULL)
        {
            slotIndex = lbl_803DC9C8;
            lbl_803DC9C8 = slotIndex + 1;
            cmd = &lbl_8033A540[slotIndex];
            cmd->v = 0xf;
            cmd->f4 = 3;
        }
        gameTextLoadForCurMap(3);
    }
    else
    {
        gameTextFonts = (u8*)&lbl_8033AF40[0];
        gameTextCharset = 0;
        if (gameTextDrawFunc == NULL)
        {
            slotIndex = lbl_803DC9C8;
            lbl_803DC9C8 = slotIndex + 1;
            cmd = &lbl_8033A540[slotIndex];
            cmd->v = 0xf;
            cmd->f4 = 0;
        }
        curGameTextDir = (void*)dirId;
        if ((subtitleIsActive() == 0 || gameTextFn_8001b44c(dirId) == 0) &&
            (int)curGameTextDir != lbl_803DC9D8)
        {
            gameTextLoadForCurMap(0);
        }
    }
}

void gameTextResetCursor(int flags)
{
    if (flags & 1)
    {
        lbl_803DC9AA = 0;
        lbl_803DC9A8 = 0;
    }
    if (flags & 2)
    {
        int i = lbl_803DC9C8;
        lbl_803DC9C8 = i + 1;
        lbl_8033A540[i].v = 0xb;
    }
}

extern void* gCurTextBox;

void gameTextSetWindow(u8* textBox)
{
    int i;
    GameTextSlot* s;
    int idx;

    if (textBox == NULL)
    {
        i = lbl_803DC9C8;
        lbl_803DC9C8 = i + 1;
        s = &lbl_8033A540[i];
        gCurTextBox = NULL;
        s->v = 8;
        s->f4 = 0xff;
    }
    else
    {
        i = lbl_803DC9C8;
        lbl_803DC9C8 = i + 1;
        s = &lbl_8033A540[i];
        idx = (textBox - gTextBoxes) / 0x20;
        if (idx == 0xff)
        {
            gCurTextBox = NULL;
        }
        else
        {
            gCurTextBox = gTextBoxes + idx * 0x20;
        }
        s->v = 8;
        s->f4 = idx;
    }
}

void gameTextSetCursor(s16 x, s16 y, int flags)
{
    if (flags & 1)
    {
        lbl_803DC9AA = x;
        lbl_803DC9A8 = y;
    }
    if (flags & 2)
    {
        int i = lbl_803DC9C8;
        GameTextSlot* s;
        lbl_803DC9C8 = i + 1;
        s = &lbl_8033A540[i];
        s->v = 0xa;
        s->f4 = (u16)x;
        s->f8 = (u16)y;
    }
}

typedef f32 Mtx[3][4];
extern int lbl_803DB3E0;
extern s16 lbl_802C9EE8[];
extern int lbl_803DC9FC;
extern u8 lbl_803DC9F7;
extern u8 lbl_803DC9F6;
extern u8 lbl_803DC9F5;
extern u8 lbl_803DC9F4;
extern int gameTextGetTaskText(int taskId, int* textId, int* dirId);
extern void loadGameTextSequence();

int gameTextFn_8001b44c(int x)
{
    if (lbl_803DC9F0 == 0)
    {
        lbl_803DB3E0 = x;
        return 1;
    }
    return 0;
}

#pragma peephole on
void gameTextLoadTaskText(int taskId)
{
    int textId;
    int dirId;
    s16* taskList;
    int count;
    int allowed;

    if (gameTextGetTaskText(taskId, &textId, &dirId) != 0)
    {
        if (lbl_803DCA00 == 0)
        {
            taskList = lbl_802C9EE8;
            count = 0xb;
            do
            {
                if (taskId == *taskList)
                {
                    allowed = 1;
                    goto checkAllowed;
                }
                taskList++;
            } while (--count != 0);
            allowed = 0;
        checkAllowed:
            if (allowed == 0)
            {
                return;
            }
        }

        lbl_803DC9FC = textId;
        lbl_803DC9F8 = (void*)dirId;
        if (dirId == 0x29)
        {
            loadGameTextSequence();
            lbl_803DC9F0 = 1;
        }
        else
        {
            lbl_803DB3E0 = (int)getCurGameText();
            gameTextLoadDir((int)lbl_803DC9F8);
            lbl_803DC9F0 = 0;
        }
        lbl_803DCA04 = 1;
        lbl_803DC9F7 = 0xff;
        lbl_803DC9F6 = 0xff;
        lbl_803DC9F5 = 0xff;
        lbl_803DC9F4 = 0xff;
    }
}
#pragma peephole reset

int subtitleIsActive(void)
{
    int ret;

    ret = 0;
    if (lbl_803DCA00 != 0)
    {
        if (lbl_803DCA04 != 0)
        {
            ret = 1;
        }
    }
    return ret;
}

int mmCreateMemoryStore(int size);

extern void DCFlushRange(void* addr, u32 nBytes);

extern void* memcpy(void* dst, const void* src, int n);

#pragma dont_inline on
void gameTextSetColor(u8 r, u8 g, u8 b, u8 a)
{
    if (gameTextDrawFunc != NULL)
    {
        lbl_803DC9A7 = r;
        lbl_803DC9A6 = g;
        lbl_803DC9A5 = b;
        lbl_803DC9A4 = a;
    }
    else
    {
        int i = lbl_803DC9C8;
        GameTextSlot* s;
        lbl_803DC9C8 = i + 1;
        s = &lbl_8033A540[i];
        s->v = 3;
        s->f4 = r;
        s->f8 = g;
        s->fc = b;
        s->f10 = a;
    }
}

#pragma dont_inline off
void gameTextSetWindowStrPos(int idx, int x, int y)
{
    if (gameTextDrawFunc != NULL)
    {
        s16 sx = x;
        u8* box = gTextBoxes;
        *(s16*)(box + idx * 0x20 + 0x18) = sx;
        *(s16*)(box + idx * 0x20 + 0x1a) = y;
    }
    else
    {
        int i = lbl_803DC9C8;
        GameTextSlot* s;
        lbl_803DC9C8 = i + 1;
        s = &lbl_8033A540[i];
        s->v = 4;
        s->f4 = idx;
        s->f8 = x;
        s->fc = y;
    }
}

extern void* lbl_8033BE54[];
extern void* lbl_8033B240[];
extern int lbl_803DCA14;

#pragma peephole on
void gameTextInitFn_8001bd14(void)
{
    int i;
    int zero;
    int* scratch;

    zero = 0;
    lbl_803DCA04 = zero;
    lbl_803DCA00 = 1;
    lbl_803DB3E0 = -1;

    scratch = (int*)lbl_8033B240;
    for (i = 0; i < 8; i++)
    {
        scratch[0] = zero;
        scratch[1] = zero;
        scratch[2] = zero;
        scratch[3] = zero;
        scratch[4] = zero;
        scratch[5] = zero;
        scratch[6] = zero;
        scratch[7] = zero;
        scratch += 8;
        scratch[0] = zero;
        scratch[1] = zero;
        scratch[2] = zero;
        scratch[3] = zero;
        scratch[4] = zero;
        scratch[5] = zero;
        scratch[6] = zero;
        scratch[7] = zero;
        scratch += 8;
        scratch[0] = zero;
        scratch[1] = zero;
        scratch[2] = zero;
        scratch[3] = zero;
        scratch[4] = zero;
        scratch[5] = zero;
        scratch[6] = zero;
        scratch[7] = zero;
        scratch += 8;
        scratch[0] = zero;
        scratch[1] = zero;
        scratch[2] = zero;
        scratch[3] = zero;
        scratch[4] = zero;
        scratch[5] = zero;
        scratch[6] = zero;
        scratch[7] = zero;
        scratch += 8;
    }
}
#pragma peephole reset

#pragma dont_inline on
void subtitleFn_8001b700(void)
{
    void** slot;
    int i;
    int oldDelay;

    if (lbl_803DCA04 != 0)
    {
        lbl_803DCA04 = 0;
        i = 0;
        slot = lbl_8033B240;
        while (i < lbl_803DCA14)
        {
            if (*slot != NULL)
            {
                oldDelay = mmSetFreeDelay(0);
                mm_free(*slot);
                mmSetFreeDelay(oldDelay);
                *slot = NULL;
            }
            slot++;
            i++;
        }

        if (lbl_803DB3E0 != -1)
        {
            gameTextLoadDir(lbl_803DB3E0);
            lbl_803DB3E0 = -1;
        }
    }
}

#pragma dont_inline off
void fn_8001BDD4(int mode)
{
    switch (mode)
    {
    case 3:
        textureFree(lbl_8033BE54[0]);
        textureFree(lbl_8033BE54[1]);
        textureFree(lbl_8033BE54[2]);
        break;
    }
}

void fn_8001BE2C(int mode)
{
    switch (mode)
    {
    case 3:
        lbl_8033BE54[0] = textureLoadAsset(0x43b);
        lbl_8033BE54[1] = textureLoadAsset(0x43e);
        lbl_8033BE54[2] = textureLoadAsset(0x43d);
        break;
    }
}

void subtitleStart(int x)
{
    if (lbl_803DCA00 != 0)
    {
        lbl_803DC9FC = x;
        lbl_803DC9F8 = getCurGameText();
        lbl_803DC9F0 = 0;
        lbl_803DB3E0 = -1;
        lbl_803DCA04 = 1;
        lbl_803DC9F7 = 0xff;
        lbl_803DC9F6 = 0xff;
        lbl_803DC9F5 = 0xff;
        lbl_803DC9F4 = 0xff;
    }
}

extern u8 curGameTexts[];

void dvdCancelCallback_8001b39c(int a, u8* match)
{
    int i;
    u8* p = curGameTexts;
    for (i = 8; i != 0; i--)
    {
        if (match == p)
        {
            *(int*)(p + 0x44) = 5;
            return;
        }
        p += 0x4c;
    }
}

void gameTextOpenCallback_8001b3d0(int status, u8* match)
{
    int i;
    u8* p = curGameTexts;
    if (status != -1 && status != -3)
    {
        for (i = 8; i != 0; i--)
        {
            if (match == p)
            {
                *(int*)(p + 0x44) = 2;
                return;
            }
            p += 0x4c;
        }
    }
    else
    {
        p = curGameTexts;
        for (i = 8; i != 0; i--)
        {
            if (match == p)
            {
                *(int*)(p + 0x44) = 5;
                return;
            }
            p += 0x4c;
        }
    }
}

extern void DCStoreRange(void* p, int size);

typedef struct
{
    int state;
    u8 pad04[4];
    u8 dirId;
    u8 languageId;
    u8 pad0a[0x1e];
} GameTextLoadRequest;

typedef struct
{
    u8 pad00[0x3c];
    void* loadHandle;
    void* dvdFileInfo;
    int state;
    u8 dirId;
    u8 languageId;
    u8 active;
    u8 sourceId;
} GameTextLoadSlot;

#define GAMETEXT_PATH_BUFFER_OFFSET 0x380
#define GAMETEXT_COMMAND_STRING_BUFFER_OFFSET 0x3c0
#define GAMETEXT_LOAD_REQUESTS_OFFSET 0x15dc
#define GAMETEXT_SEQUENCE_LOAD_STATE_OFFSET 0x1604
#define GAMETEXT_FONT_SLOT_OFFSET 0x1610
#define GAMETEXT_LOAD_SLOTS_OFFSET 0x1660
#define GAMETEXT_PENDING_REQUEST_SCAN_OFFSET (GAMETEXT_LOAD_REQUESTS_OFFSET - 0x1c)
#define GAMETEXT_LOAD_SLOT_COUNT 8
#define GAMETEXT_PENDING_SOURCE_COUNT 4
#define GAMETEXT_INVALID_DIR 0xff
#define GAMETEXT_INVALID_LANGUAGE 6
#define GAMETEXT_MAP_DIR_COUNT 0x49
#define GAMETEXT_LANGUAGE_COUNT 6
#define GAMETEXT_SEQUENCE_SOURCE_ID 1

extern int lbl_803DC9D0;
extern int lbl_803DC9D4;
extern int lbl_803DC9E0;
extern char sGameTextMapPathFormat[];
extern char sGameTextSequencePathFormat[];
extern void setFileInfo(void* fileInfo);
extern void* loadFileByPathAsync(char* path, void* fileInfo, int flags, void* callback);
extern void DVDCancelAsync(void* fileInfo, void* callback);
extern void setLanguageFn_8001ad64(void* slot);
extern void textDisplayFn_800168dc(int a, int b);
extern void gameTextFn_8001658c(int a, int b, int c);
extern void gameTextRenderStrs(int a, int b);
extern int lbl_803DC984;
extern u8 lbl_803DC990;
extern u8 lbl_803DC991;
extern u8 lbl_803DC992;
extern u8* lbl_803DC9C4;
extern int lbl_803DB378;
extern void gameTextLoadGraphicsFn_8001a918(void);

void gameTextInitFn_8001a234(void)
{
    u8* gameTextBase;
    u8* p;
    u8* textWindow;
    u8* glyphPage;
    u8** glyphPagePtr;
    u8* fontState;
    u8* request;
    u8* clearPtr;
    f32 zero;
    int i;
    int j;

    gameTextBase = lbl_80339980;

    i = 0x94;
    textWindow = gTextBoxes + 0x1280;
    p = textWindow;
    while (p -= 0x20, i-- != 0)
    {
        *(u16*)(p + 8) = *(u16*)(p + 2);
        *(u16*)(p + 0xa) = *(u16*)(p + 6);
    }

    i = 8;
    glyphPage = gameTextBase + 0x2c0;
    glyphPagePtr = (u8**)(gameTextBase + 0xc0);
    fontState = gameTextBase + 0xa0;
    while (glyphPage -= 0x40, glyphPagePtr--, fontState -= 0xc, i-- != 0)
    {
        *glyphPagePtr = glyphPage;
        *(u16*)fontState = 0xffff;
        *(u16*)(fontState + 2) = 1;
        fontState[4] = 0xff;
        fontState[5] = 0;
        fontState[6] = 0;
        fontState[7] = 0;
        *(u8***)(fontState + 8) = glyphPagePtr;
    }

    i = 0x94;
    while (textWindow -= 0x20, i-- != 0)
    {
        textWindow[0x1e] = 0xff;
    }

    i = 4;
    request = gameTextBase + 0x1660;
    zero = lbl_803DE704;
    while (request -= 0x28, i-- != 0)
    {
        *(int*)(request + 8) = 0;
        *(int*)(request + 0xc) = 0;
        *(int*)(request + 0) = 0;
        *(int*)(request + 4) = 0;
        *(int*)(request + 0x1c) = 0;
        *(f32*)(request + 0x20) = zero;
        request[0x24] = 0xff;
        request[0x25] = 6;

        j = 3;
        clearPtr = request + 0xc;
        while (clearPtr -= 4, j-- != 0)
        {
            *(int*)(clearPtr + 0x10) = 0;
        }
    }

    gameTextFonts = gameTextBase + GAMETEXT_FONT_SLOT_OFFSET;
    gameTextCharset = 2;
    curLanguage = -1;
    curGameTextDir = (void*)-1;
    gCurTextBox = NULL;
    lbl_803DC9E0 = -1;
    lbl_803DC9D8 = -1;
    lbl_803DC9BC = 0;
    lbl_803DC9A7 = 0xff;
    lbl_803DC9A6 = 0xff;
    lbl_803DC9A5 = 0xff;
    lbl_803DC9A4 = 0xff;
    lbl_803DC9C8 = 0;
    lbl_803DC9C4 = gameTextBase + GAMETEXT_COMMAND_STRING_BUFFER_OFFSET;
    lbl_803DC97C = 0;
    textWindow = gameTextBase + 0x40;
    lbl_803DC974 = textWindow;
    gCurTextBuffer = *(int*)*(void**)(textWindow + 8);
    lbl_803DC992 = 0;
    lbl_803DC991 = 0;
    lbl_803DC990 = 0;
    lbl_803DC98C = 5;
    lbl_803DC988 = 5;
    lbl_803DC984 = 1;
    lbl_803DC980 = 0;
    gameTextLoadGraphicsFn_8001a918();
    curGameTextDir = (void*)3;
    lbl_803DB378 = mmCreateMemoryStore(0x800);
}

void gameTextRun(void)
{
    u8* gameTextBase;
    GameTextLoadSlot* slot;
    GameTextLoadSlot* freeSlot;
    u8* pending;
    int sourceId;
    int dirId;
    int languageId;
    int i;
    GameTextSlot* cmd;
    u8* textWindow;
    int color;
    double zero;
    double fadeLimit;

    gameTextBase = lbl_80339980;

    slot = (GameTextLoadSlot*)(gameTextBase + GAMETEXT_LOAD_SLOTS_OFFSET);
    i = GAMETEXT_LOAD_SLOT_COUNT - 1;
    do
    {
        if (slot->state == 2)
        {
            setLanguageFn_8001ad64(slot);
        }
        slot++;
    }
    while (i-- != 0);

    sourceId = 0;
    pending = gameTextBase + GAMETEXT_PENDING_REQUEST_SCAN_OFFSET;
    do
    {
        dirId = pending[0x24];
        if ((u8)dirId != GAMETEXT_INVALID_DIR)
        {
            slot = (GameTextLoadSlot*)(gameTextBase + GAMETEXT_LOAD_SLOTS_OFFSET);
            freeSlot = (slot->active == 0)
                           ? slot
                           : ((++slot)->active == 0)
                           ? slot
                           : ((++slot)->active == 0)
                           ? slot
                           : ((++slot)->active == 0)
                           ? slot
                           : ((++slot)->active == 0)
                           ? slot
                           : ((++slot)->active == 0)
                           ? slot
                           : ((++slot)->active == 0)
                           ? slot
                           : ((++slot)->active == 0)
                           ? slot
                           : NULL;

            if (freeSlot != NULL)
            {
                languageId = pending[0x25];
                freeSlot->state = 1;
                freeSlot->dirId = (u8)dirId;
                freeSlot->languageId = (u8)languageId;
                freeSlot->active = 1;
                freeSlot->sourceId = (u8)sourceId;
                sprintf((char*)(gameTextBase + GAMETEXT_PATH_BUFFER_OFFSET), sGameTextMapPathFormat,
                        sMapDirectoryNameTable[dirId], sLanguageNameTable[languageId][0]);
                setFileInfo(freeSlot);
                freeSlot->loadHandle =
                    loadFileByPathAsync((char*)(gameTextBase + GAMETEXT_PATH_BUFFER_OFFSET),
                                        &freeSlot->dvdFileInfo, 1, gameTextOpenCallback_8001b3d0);
                setFileInfo(NULL);
                pending[0x24] = GAMETEXT_INVALID_DIR;
                pending[0x25] = GAMETEXT_INVALID_LANGUAGE;
            }
        }
        pending += 0x28;
        sourceId++;
    }
    while (sourceId < GAMETEXT_PENDING_SOURCE_COUNT);

    slot = (GameTextLoadSlot*)(gameTextBase + GAMETEXT_LOAD_SLOTS_OFFSET);
    i = GAMETEXT_LOAD_SLOT_COUNT - 1;
    do
    {
        if ((slot->state == 5 || slot->state == 6) && slot->loadHandle != NULL)
        {
            mm_free(slot->loadHandle);
            slot->loadHandle = NULL;
            slot->dvdFileInfo = NULL;
            slot->active = 0;
        }
        slot++;
    }
    while (i-- != 0);

    zero = lbl_803DE704;
    fadeLimit = lbl_803DE71C;
    for (i = 7; i >= 0; i--)
    {
        f32* alpha = (f32*)(gameTextBase + 0x20 + i * 4);
        f32* timer = (f32*)(gameTextBase + 0x40 + i * 4);
        u8* entry = gameTextBase + 0xa0 + i * 0xc;

        if ((double)*timer > zero)
        {
            *alpha += timeDelta;
            if ((double)*alpha > fadeLimit)
            {
                *timer = (f32)zero;
                *alpha = (f32)zero;
                sprintf(**(char***)(entry + 8), lbl_803DB3D4);
            }
        }
    }

    if (*(int*)(gameTextFonts + 0x1c) == 1)
    {
        *(f32*)(gameTextFonts + 0x20) += timeDelta;
    }
    else
    {
        *(f32*)(gameTextFonts + 0x20) = lbl_803DE704;
    }

    textWindow = gTextBoxes;
    for (i = 148; i != 0; i--)
    {
        *(u16*)(textWindow + 0x1c) &= 0xfffe;
        textWindow += 0x20;
    }

    lbl_803DC99C = 0;
    lbl_803DC9AA = 0;
    lbl_803DC9A8 = 0;

    cmd = lbl_8033A540;
    i = lbl_803DC9C8;
    while (i-- != 0)
    {
        switch (cmd->v)
        {
        case 3:
            {
                u8 c3 = cmd->f10;
                u8 c2 = cmd->fc;
                u8 c1 = cmd->f8;
                u8 c0 = cmd->f4;
                lbl_803DC9A7 = c0;
                lbl_803DC9A6 = c1;
                lbl_803DC9A5 = c2;
                lbl_803DC9A4 = c3;
                break;
            }
        case 4:
            {
                int t1 = cmd->fc;
                int t2 = (s16)cmd->f8;
                textWindow = gTextBoxes + cmd->f4 * 0x20;
                *(s16*)(textWindow + 0x18) = t2;
                *(s16*)(textWindow + 0x1a) = (s16)t1;
                break;
            }
        case 1:
            textDisplayFn_800168dc(cmd->f4, cmd->f8);
            break;
        case 2:
            gameTextFn_8001658c(cmd->f4, cmd->f8, cmd->fc);
            break;
        case 5:
            if (gCurTextBox != NULL)
            {
                gameTextRenderStrs(cmd->f4, ((u8*)gCurTextBox - gTextBoxes) / 0x20);
            }
            break;
        case 6:
            gameTextRenderStrs(cmd->f4, cmd->f8);
            break;
        case 7:
            {
                int t3 = cmd->f10;
                int t2 = cmd->f8;
                int t1 = cmd->f4;
                textWindow = gTextBoxes + t2 * 0x20;
                *(s16*)(textWindow + 0x18) = (s16)cmd->fc;
                *(s16*)(textWindow + 0x1a) = (s16)t3;
                gameTextRenderStrs(t1, t2);
                break;
            }
        case 8:
            if (cmd->f4 == 0xff)
            {
                gCurTextBox = NULL;
            }
            else
            {
                gCurTextBox = gTextBoxes + cmd->f4 * 0x20;
            }
            break;
        case 9:
            ((void (*)(void))cmd->f4)();
            break;
        case 10:
            lbl_803DC9AA = (u16)cmd->f4;
            lbl_803DC9A8 = (u16)cmd->f8;
            break;
        case 11:
            lbl_803DC9AA = 0;
            lbl_803DC9A8 = 0;
            break;
        case 12:
            lbl_803DC984 = cmd->f4;
            break;
        case 14:
            lbl_803DC992 = (u8)cmd->f4;
            lbl_803DC991 = (u8)cmd->f8;
            lbl_803DC990 = (u8)cmd->fc;
            break;
        case 13:
            lbl_803DC98C = cmd->f4;
            lbl_803DC988 = cmd->f8;
            break;
        case 15:
            gameTextFonts = gameTextBase + GAMETEXT_PENDING_REQUEST_SCAN_OFFSET + cmd->f4 * 0x28;
            gameTextCharset = cmd->f4;
            if (cmd->f4 == 2)
            {
                color = lbl_803DB3C8;
                hudDrawRect(0, 0, 0xa00, 0x780, &color);
                lbl_803DC99C = 0;
            }
            break;
        }
        cmd++;
    }

    if (lbl_803DC99C == 0)
    {
        Sfx_StopFromObject(0, 0x397);
    }
    lbl_803DC9C8 = 0;
    lbl_803DC9C4 = gameTextBase + GAMETEXT_COMMAND_STRING_BUFFER_OFFSET;

    textWindow = gTextBoxes + 0x1280;
    for (i = 0x94; i > 0; i--)
    {
        textWindow -= 0x20;
        *(s16*)(textWindow + 0x18) = 0;
        *(s16*)(textWindow + 0x1a) = 0;
    }
    gCurTextBox = NULL;
}

void loadGameTextSequence(int sequenceSlotDir, int sequenceId)
{
    int oldHeap;
    int languageId;
    int languageTableOffset;
    GameTextLoadSlot* slot;
    GameTextLoadSlot* freeSlot;
    u8* gameTextBase;
    u8* languageTable;
    int i;

    gameTextBase = lbl_80339980;
    languageId = curLanguage;
    languageTableOffset = languageId << 3;
    languageTable = (u8*)sLanguageNameTable;
    oldHeap = testAndSet_onlyUseHeap3(0);
    if (getGameState() != 0 && getGameState() != 1)
    {
        testAndSet_onlyUseHeap3(oldHeap);
        return;
    }

    lbl_803DC9D0 = lbl_803DC9D4;
    if (curLanguage < 0 || curLanguage >= 6)
    {
        testAndSet_onlyUseHeap3(oldHeap);
        return;
    }

    slot = (GameTextLoadSlot*)(gameTextBase + GAMETEXT_LOAD_SLOTS_OFFSET);
    i = GAMETEXT_LOAD_SLOT_COUNT - 1;
    do
    {
        if (slot->sourceId == GAMETEXT_SEQUENCE_SOURCE_ID)
        {
            if (slot->state == 1)
            {
                slot->state = 4;
                DVDCancelAsync(slot, dvdCancelCallback_8001b39c);
            }
            if (slot->state == 3 && slot->active != 0)
            {
                mmSetFreeDelay(0);
                mm_free(slot->loadHandle);
                mmSetFreeDelay(2);
                slot->loadHandle = NULL;
                slot->dvdFileInfo = NULL;
                slot->active = 0;
            }
        }
        slot++;
    }
    while (i-- != 0);

    *(int*)(gameTextBase + GAMETEXT_SEQUENCE_LOAD_STATE_OFFSET) = 1;
    slot = (GameTextLoadSlot*)(gameTextBase + GAMETEXT_LOAD_SLOTS_OFFSET);
    freeSlot = (slot->active == 0)
                   ? slot
                   : ((++slot)->active == 0)
                   ? slot
                   : ((++slot)->active == 0)
                   ? slot
                   : ((++slot)->active == 0)
                   ? slot
                   : ((++slot)->active == 0)
                   ? slot
                   : ((++slot)->active == 0)
                   ? slot
                   : ((++slot)->active == 0)
                   ? slot
                   : ((++slot)->active == 0)
                   ? slot
                   : NULL;

    freeSlot->state = 1;
    freeSlot->dirId = (u8)sequenceSlotDir;
    freeSlot->languageId = (u8)curLanguage;
    freeSlot->active = 1;
    freeSlot->sourceId = GAMETEXT_SEQUENCE_SOURCE_ID;
    sprintf((char*)(gameTextBase + GAMETEXT_PATH_BUFFER_OFFSET), sGameTextSequencePathFormat,
            sequenceId, *(char**)(languageTable + languageTableOffset));
    setFileInfo(freeSlot);
    freeSlot->loadHandle = loadFileByPathAsync((char*)(gameTextBase + GAMETEXT_PATH_BUFFER_OFFSET),
                                               &freeSlot->dvdFileInfo, 1, gameTextOpenCallback_8001b3d0);
    setFileInfo(NULL);
    testAndSet_onlyUseHeap3(oldHeap);
}

void gameTextLoadForCurMap(int sourceId)
{
    int oldHeap;
    int dirId;
    int languageId;
    GameTextLoadSlot* slot;
    GameTextLoadSlot* freeSlot;
    GameTextLoadRequest* request;
    u8* gameTextBase;
    int i;

    gameTextBase = lbl_80339980;
    oldHeap = testAndSet_onlyUseHeap3(0);
    if (getGameState() != 0 && getGameState() != 1)
    {
        testAndSet_onlyUseHeap3(oldHeap);
        return;
    }

    dirId = (int)curGameTextDir;
    languageId = curLanguage;
    lbl_803DC9D8 = dirId;
    lbl_803DC9E0 = languageId;
    if (dirId < 0 || dirId >= GAMETEXT_MAP_DIR_COUNT ||
        languageId < 0 || languageId >= GAMETEXT_LANGUAGE_COUNT)
    {
        testAndSet_onlyUseHeap3(oldHeap);
        return;
    }

    slot = (GameTextLoadSlot*)(gameTextBase + GAMETEXT_LOAD_SLOTS_OFFSET);
    i = GAMETEXT_LOAD_SLOT_COUNT - 1;
    do
    {
        if (slot->sourceId == sourceId)
        {
            if (slot->state == 1)
            {
                slot->state = 4;
                DVDCancelAsync(slot, dvdCancelCallback_8001b39c);
            }
            if (slot->state == 3 && slot->active != 0)
            {
                mmSetFreeDelay(0);
                if (slot->loadHandle != NULL)
                {
                    mm_free(slot->loadHandle);
                }
                mmSetFreeDelay(2);
                slot->loadHandle = NULL;
                slot->dvdFileInfo = NULL;
                slot->active = 0;
            }
        }
        slot++;
    }
    while (i-- != 0);

    request = (GameTextLoadRequest*)(gameTextBase + GAMETEXT_LOAD_REQUESTS_OFFSET +
        sourceId * sizeof(GameTextLoadRequest));
    request->state = 1;
    request->dirId = (u8)curGameTextDir;
    request->languageId = (u8)curLanguage;

    slot = (GameTextLoadSlot*)(gameTextBase + GAMETEXT_LOAD_SLOTS_OFFSET);
    freeSlot = (slot->active == 0)
                   ? slot
                   : ((++slot)->active == 0)
                   ? slot
                   : ((++slot)->active == 0)
                   ? slot
                   : ((++slot)->active == 0)
                   ? slot
                   : ((++slot)->active == 0)
                   ? slot
                   : ((++slot)->active == 0)
                   ? slot
                   : ((++slot)->active == 0)
                   ? slot
                   : ((++slot)->active == 0)
                   ? slot
                   : NULL;

    if (freeSlot != NULL)
    {
        dirId = request->dirId;
        languageId = request->languageId;
        freeSlot->state = 1;
        freeSlot->dirId = (u8)dirId;
        freeSlot->languageId = (u8)languageId;
        freeSlot->active = 1;
        freeSlot->sourceId = (u8)sourceId;
        sprintf((char*)(gameTextBase + GAMETEXT_PATH_BUFFER_OFFSET), sGameTextMapPathFormat,
                sMapDirectoryNameTable[dirId], sLanguageNameTable[languageId][0]);
        setFileInfo(freeSlot);
        freeSlot->loadHandle =
            loadFileByPathAsync((char*)(gameTextBase + GAMETEXT_PATH_BUFFER_OFFSET),
                                &freeSlot->dvdFileInfo, 1, gameTextOpenCallback_8001b3d0);
        setFileInfo(NULL);
        request->dirId = GAMETEXT_INVALID_DIR;
        request->languageId = GAMETEXT_INVALID_LANGUAGE;
    }

    testAndSet_onlyUseHeap3(oldHeap);
}

extern void* lbl_8033BE40[];
extern int lbl_803DB3EC;
extern void* lbl_803DCA24;
extern void* lbl_803DCA28;
extern u32 lbl_803DE740;
extern u8* gameTextGetCurBox(void);
extern void gameTextFn_8001628c(int id, int a, int b, int* x0, int* x1, int* y0, int* y1);
extern void gameTextBoxFn_800164b0(int id, int idx, int* x0, int* x1, int* y0, int* y1);
extern void drawTexture(f32 x, f32 y, void* tex, int alpha, int scale);
extern void drawScaledTexture(f32 x, f32 y, void* tex, int alpha, int scale, int w, int h, int flag);
extern void drawPartialTexture(f32 x, f32 y, void* tex, int alpha, int scale, int w, int h, int part, int flag);
extern void drawHudBox(int x, int y, int w, int h, int alpha, int flag);

typedef struct GameTextBox
{
    u8 unk00[8];
    u16 width;
    u16 height;
    u8 unk0C[7];
    u8 style;
    s16 x;
    s16 y;
    s16 unk18;
    s16 unk1A;
    u16 flags;
    u8 alpha;
    u8 unk1F;
} GameTextBox;

STATIC_ASSERT(offsetof(GameTextBox, style) == 0x13);
STATIC_ASSERT(offsetof(GameTextBox, alpha) == 0x1E);

extern void boxDrawFn_8001c5ac(u16* strPtr, int boxId, u8* box);

#pragma dont_inline on
void gameTextDrawBox(u16* strPtr, int boxId, u8* box)
{
    u32 colorB;
    u32 colorA;
    int c6y1;
    int c6y0;
    int c6x1;
    int c6x0;
    int c3y1;
    int c3y0;
    int c3x1;
    int c3x0;
    s16 savedX;
    s16 savedY;
    u16 f;
    u8* cur;
    int hw;
    int hh;
    int cx;
    int cy;
    u16 h7;
    u16 w7;
    s16 y7;
    s16 x7;
    s16 x2;
    int w2;
    int xw;
    s16 y2;
    int half;
    int rem;

    savedX = ((GameTextBox*)box)->unk18;
    savedY = ((GameTextBox*)box)->unk1A;
    f = ((GameTextBox*)box)->flags;
    if (f & 1)
    {
        return;
    }
    ((GameTextBox*)box)->flags = f | 1;
    switch (((GameTextBox*)box)->style)
    {
    case 5:
        return;
    case 7:
        if ((int)getCurGameText() == 3)
        {
            colorB = lbl_803DE740;
            hudDrawRect(((GameTextBox*)box)->x, ((GameTextBox*)box)->y,
                        ((GameTextBox*)box)->x + ((GameTextBox*)box)->width,
                        ((GameTextBox*)box)->y + ((GameTextBox*)box)->height, &colorB);
        }
        else
        {
            h7 = ((GameTextBox*)box)->height;
            w7 = ((GameTextBox*)box)->width;
            y7 = ((GameTextBox*)box)->y;
            x7 = ((GameTextBox*)box)->x;
            GXSetScissor(0, 0, 0x280, 0x1e0);
            drawHudBox(x7, y7, (s16)w7, (s16)h7, 0xff, 1);
        }
        break;
    case 1:
        colorA = lbl_803DE740;
        hudDrawRect(((GameTextBox*)box)->x, ((GameTextBox*)box)->y,
                    ((GameTextBox*)box)->x + ((GameTextBox*)box)->width,
                    ((GameTextBox*)box)->y + ((GameTextBox*)box)->height, &colorA);
        break;
    case 6:
        if (strPtr == NULL)
        {
            return;
        }
        cur = gameTextGetCurBox();
        if (strPtr != NULL)
        {
            gameTextFn_8001628c(*strPtr, 0, 0, &c6x0, &c6x1, &c6y0, &c6y1);
        }
        else if (boxId != 0)
        {
            gameTextBoxFn_800164b0(boxId, (int)(box - gTextBoxes) / 0x20, &c6x0, &c6x1, &c6y0, &c6y1);
        }
        gameTextSetWindow(cur);
        hw = (c6x1 - c6x0) >> 1;
        hh = (c6y1 - c6y0) >> 1;
        cx = c6x0 + hw;
        cy = c6y0 + hh;
        drawScaledTexture((f32)(c6x0 - lbl_803DB3EC), (f32)(c6y0 - lbl_803DB3EC), lbl_803DCA24, 0xff, 0x100,
                          hw + lbl_803DB3EC, hh + lbl_803DB3EC, 0);
        drawScaledTexture((f32)cx, (f32)(c6y0 - lbl_803DB3EC), lbl_803DCA24, 0xff, 0x100,
                          hw + lbl_803DB3EC, hh + lbl_803DB3EC, 1);
        drawScaledTexture((f32)(c6x0 - lbl_803DB3EC), (f32)cy, lbl_803DCA24, 0xff, 0x100,
                          hw + lbl_803DB3EC, hh + lbl_803DB3EC, 2);
        drawScaledTexture((f32)cx, (f32)cy, lbl_803DCA24, 0xff, 0x100,
                          hw + lbl_803DB3EC, hh + lbl_803DB3EC, 3);
        break;
    case 0:
        drawScaledTexture((f32)((GameTextBox*)box)->x, (f32)((GameTextBox*)box)->y, lbl_803DCA28, 0xff, 0x100,
                          ((GameTextBox*)box)->width, ((GameTextBox*)box)->height, 0);
        break;
    case 3:
        cur = gameTextGetCurBox();
        if (strPtr != NULL)
        {
            gameTextFn_8001628c(*strPtr, 0, 0, &c3x0, &c3x1, &c3y0, &c3y1);
        }
        else if (boxId != 0)
        {
            gameTextBoxFn_800164b0(boxId, (int)(box - gTextBoxes) / 0x20, &c3x0, &c3x1, &c3y0, &c3y1);
        }
        gameTextSetWindow(cur);
        drawTexture((f32)(c3x0 - 0x16), (f32)(c3y0 - 9), lbl_8033BE40[5], ((GameTextBox*)box)->alpha, 0x100);
        drawScaledTexture((f32)c3x0, (f32)(c3y0 - 9), lbl_8033BE40[6], ((GameTextBox*)box)->alpha, 0x100,
                          c3x1 - c3x0, 0x24, 0);
        drawTexture((f32)c3x1, (f32)(c3y0 - 9), lbl_8033BE40[7], ((GameTextBox*)box)->alpha, 0x100);
        break;
    case 2:
        x2 = ((GameTextBox*)box)->x;
        w2 = ((GameTextBox*)box)->width;
        xw = x2 + w2;
        y2 = ((GameTextBox*)box)->y;
        half = w2 >> 1;
        if (half > 0xc)
        {
            half = 0xc;
        }
        rem = w2 - half * 2;
        if (rem < 0)
        {
            rem = 0;
        }
        GXSetScissor(0, 0, 0x280, 0x1e0);
        drawTexture((f32)(x2 - 0x34), (f32)(y2 - 0x23), lbl_8033BE40[0], ((GameTextBox*)box)->alpha, 0x100);
        drawTexture((f32)xw, (f32)(y2 - 0x23), lbl_8033BE40[4], ((GameTextBox*)box)->alpha, 0x100);
        if (half != 0)
        {
            drawScaledTexture((f32)x2, (f32)(y2 - 0x13), lbl_8033BE40[1], ((GameTextBox*)box)->alpha, 0x100,
                              half, 0x3a, 0);
            drawPartialTexture((f32)(xw - half), (f32)(y2 - 0x13), lbl_8033BE40[3], ((GameTextBox*)box)->alpha, 0x100,
                               half, 0x3a, 0xc - half, 0);
        }
        if (rem != 0)
        {
            drawScaledTexture((f32)(x2 + half), (f32)(y2 - 0x13), lbl_8033BE40[2], ((GameTextBox*)box)->alpha, 0x100,
                              rem, 0x3a, 0);
        }
        break;
    case 4:
        boxDrawFn_8001c5ac(strPtr, boxId, box);
        break;
    }
    ((GameTextBox*)box)->unk18 = savedX;
    ((GameTextBox*)box)->unk1A = savedY;
}

extern int mmSetFreeDelay(int delay);

extern u8* textureAlloc(u32 w, u32 h, int kind, int a, int b, int c, int d, int e, int f);

typedef struct GameTextCharset
{
    u8* strings;
    u8* entries;
    int headerCount;
    int count;
    u8 pad10[0xc];
    int status;
} GameTextCharset;

#pragma dont_inline off
#pragma peephole on
void setLanguageFn_8001ad64(void* reqp)
{
    u8* req = (u8*)reqp;
    GameTextCharset* cs;
    int* data;
    u8* hdr;
    int ofs;
    int* table;
    int numStrings;
    int* strs;
    int i;
    u8* txt;
    int* texHdr;
    u16* p;
    u16* texStart;
    int** slot;
    int kind;
    u32 bpp;
    u32 w;
    u32 h;
    int n;
    u32 size;
    u16* newBuf;
    u16* old;
    int delta;
    int* strs2;

    DCStoreRange(*(void**)(req + 0x3c), *(u32*)(req + 0x40));
    if (req[0x4b] == 1)
    {
        cs = (GameTextCharset*)&lbl_8033AF40[1];
    }
    else if (req[0x4b] == 3)
    {
        cs = (GameTextCharset*)&lbl_8033AF40[3];
    }
    else
    {
        cs = (GameTextCharset*)&lbl_8033AF40[0];
        curGameTextDir = (void*)req[0x48];
        curLanguage = req[0x49];
    }
    data = *(int**)(req + 0x3c);
    cs->headerCount = data[0];
    if (cs->headerCount == 0)
    {
        cs->status = 3;
        *(int*)(req + 0x44) = 6;
        return;
    }
    cs->strings = (u8*)(data + 1);
    hdr = (u8*)data + cs->headerCount * 16;
    cs->count = *(u16*)(hdr + 4);
    ofs = *(u16*)(hdr + 6);
    cs->entries = hdr + 8;
    table = (int*)(cs->entries + cs->count * 12);
    numStrings = table[0];
    strs = table + 1;
    for (i = 0; i < cs->count; i++)
    {
        *(int**)(cs->entries + i * 12 + 8) = strs + *(int*)(cs->entries + i * 12 + 8);
    }
    txt = (u8*)(table + numStrings + 1);
    for (i = 0; i < numStrings; i++)
    {
        strs[i] = strs[i] + (int)txt;
    }
    texHdr = (int*)(txt + ofs);
    p = (u16*)((u8*)texHdr + texHdr[0] + 4);
    texStart = p;
    slot = (int**)cs;
    while (1)
    {
        kind = p[0];
        bpp = p[1];
        w = p[2];
        h = p[3];
        p += 4;
        if (w == 0 && h == 0)
        {
            break;
        }
        switch (kind)
        {
        case 1:
            kind = 5;
            break;
        case 2:
            kind = 0;
            break;
        }
        if (slot[4] != NULL)
        {
            mmSetFreeDelay(0);
            mm_free(slot[4]);
            mmSetFreeDelay(2);
        }
        slot[4] = (int*)textureAlloc(w, h, kind, 0, 0, 0, 0, 1, 1);
        if (slot[4] != NULL)
        {
            if (bpp == 4)
            {
                u8* dst8 = (u8*)slot[4] + 0x60;
                u8* src8 = (u8*)p;
                n = (int)(w * h) >> 1;
                for (i = 0; i < n; i++)
                {
                    *dst8 = *src8;
                    dst8++;
                    src8++;
                }
                DCFlushRange((u8*)slot[4] + 0x60, *(u32*)((u8*)slot[4] + 0x44));
            }
            else
            {
                u16* dst16 = (u16*)((u8*)slot[4] + 0x60);
                u16* src16 = p;
                n = w * h;
                for (i = 0; i < n; i++)
                {
                    *dst16 = *src16;
                    dst16++;
                    src16++;
                }
                DCFlushRange((u8*)slot[4] + 0x60, *(u32*)((u8*)slot[4] + 0x44));
            }
        }
        p += (int)(w * h * bpp) >> 4;
        slot = slot + 1;
    }
    size = (u32)((u8*)texStart - *(u8**)(req + 0x3c));
    newBuf = (u16*)mmAlloc(size, 0x1a, 0);
    old = *(u16**)(req + 0x3c);
    delta = (int)newBuf - (int)old;
    n = size >> 1;
    {
        u16* d = newBuf;
        u16* s = old;
        for (i = 0; i < n; i++)
        {
            *d = *s;
            d++;
            s++;
        }
    }
    cs->strings = cs->strings + delta;
    cs->entries = cs->entries + delta;
    for (i = 0; i < cs->count; i++)
    {
        *(int*)(cs->entries + i * 12 + 8) = *(int*)(cs->entries + i * 12 + 8) + delta;
    }
    strs2 = (int*)((u8*)strs + delta);
    for (i = 0; i < numStrings; i++)
    {
        strs2[i] = strs2[i] + delta;
    }
    mmSetFreeDelay(0);
    mm_free(*(void**)(req + 0x3c));
    *(int*)(req + 0x3c) = 0;
    mmSetFreeDelay(2);
    *(u16**)(req + 0x3c) = newBuf;
    cs->status = 2;
    *(int*)(req + 0x44) = 3;
}

extern u16 OSGetFontEncode(void);
extern void OSLoadFont(void* buf, void* tmp);
extern void OSGetFontWidth(u8* s, int* width);
extern void OSGetFontTexel(u8* s, void* img, int pos, int stride, int* width);
extern u8 lbl_803DC968;
extern u16 lbl_802C8D40[];
extern int lbl_803DB3C4;

#pragma peephole off
void gameTextLoadGraphicsFn_8001a918(void)
{
    u8* fontData;
    u8* base30;
    u8* base31;
    u8* buf;
    int sizeA;
    int sizeB;
    u8* bufA;
    u8* bufB;
    int savedHeap;
    int count;
    u8* glyph;
    int x;
    int y;
    int wbytes;
    u8 s[3];
    int width;

    fontData = (u8*)lbl_802C8F40;
    base30 = (u8*)lbl_802C8680;
    base31 = (u8*)lbl_8033AF40;
    savedHeap = testAndSet_onlyUseHeap3(0);
    buf = mmAlloc(0x120, 0x1a, 0);
    switch (OSGetFontEncode())
    {
    case 0:
        sizeA = 0x3000;
        sizeB = 0x10120;
        curLanguage = 0;
        lbl_803DC968 = 0;
        break;
    case 1:
        sizeA = 0x4d000;
        sizeB = 0x90ee4;
        curLanguage = 4;
        lbl_803DC968 = 1;
        break;
    }
    bufA = mmAlloc(sizeA, 0x1a, 0);
    bufB = mmAlloc(sizeB, 0x1a, 0);
    OSLoadFont(bufB, bufA);
    if (*(int*)(base31 + 0x58) == 0)
    {
        if (lbl_803DC968)
        {
            *(u8**)(base31 + 0x50) = fontData;
            *(int*)(base31 + 0x58) = 0x55;
            *(u8**)(base31 + 0x54) = fontData + 0x8ec;
            *(int*)(base31 + 0x5c) = 7;
        }
        else
        {
            *(u8**)(base31 + 0x50) = fontData + 0x940;
            *(int*)(base31 + 0x58) = 0x2b;
            *(u8**)(base31 + 0x54) = fontData + 0xe24;
            *(int*)(base31 + 0x5c) = 7;
        }
    }
    *(u8**)(base31 + 0x60) = textureAlloc(0x200, 0x60, 0, 0, 0, 0, 0, 1, 1);
    *(u16*)(base30 + 0x60) = *(int*)(base31 + 0x58);
    *(u8*)(base30 + 0x64) = 0x30;
    *(u8*)(base30 + 0x65) = 0x20;
    *(u16*)(base30 + 0x68) = 0;
    *(u16*)(base30 + 0x6a) = 0x18;
    count = *(int*)(base31 + 0x58);
    glyph = *(u8**)(base31 + 0x50);
    x = 0;
    y = 0;
    while (count--)
    {
        if (lbl_803DC968)
        {
            int c = *(int*)glyph;
            u16* p = lbl_802C8D40;
            int i;
            u32 val;
            int hi;
            u8 lo;
            for (i = 0xfd; i > 0; i -= 2)
            {
                if (p[0] == c)
                {
                    val = p[1];
                    goto found;
                }
                p++;
                if (p[0] == c)
                {
                    val = p[1];
                    goto found;
                }
                p++;
            }
            val = 0;
        found:
            hi = (val >> 8) & 0xff;
            lo = val;
            if (hi == 0)
            {
                s[0] = lo;
                s[1] = 0;
            }
            else
            {
                s[0] = hi;
                s[1] = lo;
                s[2] = 0;
            }
        }
        else
        {
            s[0] = *(int*)glyph;
            s[1] = 0;
        }
        OSGetFontWidth(s, &width);
        if (width > *(u16*)(base30 + 0x68))
        {
            *(u16*)(base30 + 0x68) = width;
        }
        wbytes = width >> 3;
        if ((width & 7) != 0)
        {
            wbytes++;
        }
        {
            u32* q = (u32*)buf;
            int j = 0x47;
            do
            {
                q[0] = 0;
                q[1] = 0;
                q[2] = 0;
                q[3] = 0;
                q[4] = 0;
                q[5] = 0;
                q[6] = 0;
                q[7] = 0;
                q[8] = 0;
                q += 9;
                j -= 9;
            }
            while (j > 0);
        }
        OSGetFontTexel(s, buf, 0, 6, &width);
        if (x + 0x18 > 0x200)
        {
            x = 0;
            y += 0x18;
        }
        *(u16*)(glyph + 4) = x;
        *(u16*)(glyph + 6) = y;
        *(u8*)(glyph + 8) = 0;
        *(u8*)(glyph + 9) = 0;
        *(u8*)(glyph + 0xa) = 0;
        *(u8*)(glyph + 0xb) = 0;
        *(u8*)(glyph + 0xc) = width;
        *(u8*)(glyph + 0xd) = 0x18;
        *(u8*)(glyph + 0xe) = 6;
        *(u8*)(glyph + 0xf) = 0;
        {
            u32* src = (u32*)buf;
            int tx = *(u16*)(glyph + 4) >> 3;
            int ty = *(u16*)(glyph + 6) >> 3;
            int txEnd = tx + 3;
            int tyEnd = ty + 3;
            int cnt = txEnd - tx;
            int row;
            for (row = ty; row < tyEnd; row++)
            {
                int off = tx << 5;
                int j2 = tx;
                int n;
                if (j2 < txEnd)
                {
                    n = cnt;
                    do
                    {
                        u8* dst = *(u8**)(base31 + 0x60) + off;
                        u32 tmp;
                        dst += row * lbl_803DB3C4;
                        *(u32*)(dst + 0x60) = src[0];
                        *(u32*)(dst + 0x64) = src[1];
                        *(u32*)(dst + 0x68) = src[2];
                        *(u32*)(dst + 0x6c) = src[3];
                        *(u32*)(dst + 0x70) = src[4];
                        *(u32*)(dst + 0x74) = src[5];
                        *(u32*)(dst + 0x78) = src[6];
                        tmp = src[7];
                        src += 8;
                        *(u32*)(dst + 0x7c) = tmp;
                        off += 0x20;
                        j2++;
                    }
                    while (--n != 0);
                }
            }
        }
        x += wbytes << 3;
        glyph += 0x10;
    }
    DCFlushRange(*(u8**)(base31 + 0x60) + 0x60, 0x20000);
    mm_free(bufA);
    mm_free(bufB);
    mm_free(buf);
    testAndSet_onlyUseHeap3(savedHeap);
    *(int*)(base31 + 0x6c) = 2;
}

void* mmAlloc(int size, int type, int flag);

extern void subtitleUpdateAndDraw(int a);

extern int lbl_803DCA08;
extern f32 lbl_803DCA0C;
extern int lbl_803DCA10;
extern int lbl_803DCA18;
extern int lbl_8033B640[];
extern f32 lbl_8033BA40[];
extern f32 lbl_803DE720;

typedef struct
{
    u32 code;
    u16 r, g, b, a;
} SubtitleCmd;

extern SubtitleCmd* subtitleParseControlCmds(int str, int* count);
extern void gameTextShowStr(int str, int a, int b, int c);

void subtitleUpdateAndDraw(int a)
{
    int charset;
    SubtitleCmd* cmds;
    int delay;
    int n;

    if (lbl_803DCA04 == 2)
    {
        if (lbl_803DC9F0 != 0)
        {
            charset = gameTextGetCharset();
            gameTextSetCharset(1, 2);
        }
        if (getHudHiddenFrameCount() == 0)
        {
            lbl_803DCA10 += framesThisStep;
        }
        lbl_803DCA0C = (f32)lbl_803DCA10 / lbl_803DE720;
        if (lbl_803DCA08 + 1 < lbl_803DCA18 && lbl_803DCA0C >= lbl_8033BA40[lbl_803DCA08 + 1])
        {
            cmds = subtitleParseControlCmds(lbl_8033B640[lbl_803DCA08], &n);
            if (cmds != NULL)
            {
                SubtitleCmd* p = &cmds[n];
                while (p--, n-- != 0)
                {
                    if (p->code == 0xf8ff)
                    {
                        SubtitleCmd* e = &cmds[n];
                        lbl_803DC9F7 = e->r;
                        lbl_803DC9F6 = e->g;
                        lbl_803DC9F5 = e->b;
                        lbl_803DC9F4 = e->a;
                        break;
                    }
                }
                delay = mmSetFreeDelay(0);
                mm_free(cmds);
                mmSetFreeDelay(delay);
            }
            lbl_803DCA08++;
            if (lbl_803DCA08 + 1 >= lbl_803DCA18)
            {
                subtitleFn_8001b700();
                if (lbl_803DC9F0 != 0)
                {
                    gameTextSetCharset(charset, 2);
                }
                return;
            }
        }
        gameTextSetColor(lbl_803DC9F7, lbl_803DC9F6, lbl_803DC9F5, lbl_803DC9F4);
        gameTextShowStr(lbl_8033B640[lbl_803DCA08], 10, 0, 0);
        if (lbl_803DC9F0 != 0)
        {
            gameTextSetCharset(charset, 2);
        }
    }
}

extern int lbl_803DB3F0;
extern int lbl_803DB3F4;
extern int lbl_803DB3F8;
extern int lbl_803DB3FC;
extern int lbl_803DB400;
extern void* lbl_803DCA20;

#pragma peephole on
void boxDrawFn_8001c5ac(u16* strPtr, int boxId, u8* p)
{
    int x;
    int y;
    int alpha;
    int halfW;
    int halfH;
    int midX;
    int midY;

    alpha = *(u8*)(p + 0x1e);
    x = *(s16*)(p + 0x14);
    y = *(s16*)(p + 0x16);
    halfW = ((x + *(u16*)(p + 0x8)) - *(s16*)(p + 0x14)) >> 1;
    halfH = ((y + *(u16*)(p + 0xa)) - *(s16*)(p + 0x16)) >> 1;
    midX = x + halfW;
    midY = y + halfH;
    setTextColor(0, lbl_803DB3F4 & 0xff, lbl_803DB3F8 & 0xff, lbl_803DB3FC & 0xff, lbl_803DB400 & 0xff);
    textureSetupFn_800799c0();
    textRenderSetupFn_800795e8();
    textRenderSetupFn_80079804();
    ((void (*)(void*, f32, f32, int, int, int, int, int))drawScaledTexture)(
        lbl_803DCA20, (f32)(x - lbl_803DB3F0), (f32)(y - lbl_803DB3F0), alpha, 0x100, halfW + lbl_803DB3F0,
        halfH + lbl_803DB3F0, 0);
    ((void (*)(void*, f32, f32, int, int, int, int, int))drawScaledTexture)(
        lbl_803DCA20, (f32)midX, (f32)(y - lbl_803DB3F0), alpha, 0x100, halfW + lbl_803DB3F0, halfH + lbl_803DB3F0, 1);
    ((void (*)(void*, f32, f32, int, int, int, int, int))drawScaledTexture)(
        lbl_803DCA20, (f32)(x - lbl_803DB3F0), (f32)midY, alpha, 0x100, halfW + lbl_803DB3F0, halfH + lbl_803DB3F0, 2);
    ((void (*)(void*, f32, f32, int, int, int, int, int))drawScaledTexture)(
        lbl_803DCA20, (f32)midX, (f32)midY, alpha, 0x100, halfW + lbl_803DB3F0, halfH + lbl_803DB3F0, 3);
}

extern s16 lbl_803DB3E8;
extern u16 lbl_802C9F00[];
extern u16 lbl_802CA100[];

#pragma opt_strength_reduction off
#pragma scheduling off
#pragma peephole off
void gameTextInitFn_8001c794(void)
{
    s16* p;
    void** q;
    int i;
    int j;
    int x;
    int xb;
    int y;
    int x1;
    int x2;
    int x3;
    int off;
    u16* dst;
    u16* src;

    i = 1;
    p = &lbl_803DB3E8 + 1;
    q = (void**)&lbl_803DCA28 + 1;
    while (p--, q--, i-- != 0)
    {
        *q = textureLoadAsset(*p);
    }

    lbl_803DCA24 = textureAlloc(0x10, 0x10, 5, 0, 0, 0, 0, 1, 1);
    dst = (u16*)((u8*)lbl_803DCA24 + 0x60);
    y = 0;
    src = lbl_802C9F00;
    for (i = 0; i < 4; i++)
    {
        x = 0;
        xb = 0;
        for (j = 0; j < 2; j++)
        {
            x1 = (x + 1) * 2;
            x2 = (x + 2) * 2;
            x3 = (x + 3) * 2;
            off = y * 32;
            dst[0] = *(u16*)((u8*)src + off + xb);
            dst[1] = *(u16*)((u8*)src + off + x1);
            dst[2] = *(u16*)((u8*)src + off + x2);
            dst[3] = *(u16*)((u8*)src + off + x3);
            off += 32;
            dst[4] = *(u16*)((u8*)src + off + xb);
            dst[5] = *(u16*)((u8*)src + off + x1);
            dst[6] = *(u16*)((u8*)src + off + x2);
            dst[7] = *(u16*)((u8*)src + off + x3);
            off += 32;
            dst[8] = *(u16*)((u8*)src + off + xb);
            dst[9] = *(u16*)((u8*)src + off + x1);
            dst[10] = *(u16*)((u8*)src + off + x2);
            dst[11] = *(u16*)((u8*)src + off + x3);
            off += 32;
            dst[12] = *(u16*)((u8*)src + off + xb);
            dst[13] = *(u16*)((u8*)src + off + x1);
            dst[14] = *(u16*)((u8*)src + off + x2);
            dst[15] = *(u16*)((u8*)src + off + x3);
            xb += 8;
            x1 = (x + 5) * 2;
            x2 = (x + 6) * 2;
            x3 = (x + 7) * 2;
            off = y * 32;
            dst[16] = *(u16*)((u8*)src + off + xb);
            dst[17] = *(u16*)((u8*)src + off + x1);
            dst[18] = *(u16*)((u8*)src + off + x2);
            dst[19] = *(u16*)((u8*)src + off + x3);
            off += 32;
            dst[20] = *(u16*)((u8*)src + off + xb);
            dst[21] = *(u16*)((u8*)src + off + x1);
            dst[22] = *(u16*)((u8*)src + off + x2);
            dst[23] = *(u16*)((u8*)src + off + x3);
            off += 32;
            dst[24] = *(u16*)((u8*)src + off + xb);
            dst[25] = *(u16*)((u8*)src + off + x1);
            dst[26] = *(u16*)((u8*)src + off + x2);
            dst[27] = *(u16*)((u8*)src + off + x3);
            off += 32;
            dst[28] = *(u16*)((u8*)src + off + xb);
            dst[29] = *(u16*)((u8*)src + off + x1);
            dst[30] = *(u16*)((u8*)src + off + x2);
            dst[31] = *(u16*)((u8*)src + off + x3);
            dst += 32;
            x += 8;
            xb += 8;
        }
        y += 4;
    }
    DCFlushRange((u8*)lbl_803DCA24 + 0x60, 0x200);

    lbl_803DCA20 = textureAlloc(0x14, 0x14, 5, 0, 0, 0, 0, 1, 1);
    dst = (u16*)((u8*)lbl_803DCA20 + 0x60);
    y = 0;
    src = lbl_802CA100;
    for (i = 0; i < 5; i++)
    {
        x = 0;
        xb = 0;
        for (j = 0; j < 5; j++)
        {
            x1 = (x + 1) * 2;
            x2 = (x + 2) * 2;
            x3 = (x + 3) * 2;
            off = y * 40;
            dst[0] = *(u16*)((u8*)src + off + xb);
            dst[1] = *(u16*)((u8*)src + off + x1);
            dst[2] = *(u16*)((u8*)src + off + x2);
            dst[3] = *(u16*)((u8*)src + off + x3);
            off += 40;
            dst[4] = *(u16*)((u8*)src + off + xb);
            dst[5] = *(u16*)((u8*)src + off + x1);
            dst[6] = *(u16*)((u8*)src + off + x2);
            dst[7] = *(u16*)((u8*)src + off + x3);
            off += 40;
            dst[8] = *(u16*)((u8*)src + off + xb);
            dst[9] = *(u16*)((u8*)src + off + x1);
            dst[10] = *(u16*)((u8*)src + off + x2);
            dst[11] = *(u16*)((u8*)src + off + x3);
            off += 40;
            dst[12] = *(u16*)((u8*)src + off + xb);
            dst[13] = *(u16*)((u8*)src + off + x1);
            dst[14] = *(u16*)((u8*)src + off + x2);
            dst[15] = *(u16*)((u8*)src + off + x3);
            dst += 16;
            x += 4;
            xb += 8;
        }
        y += 4;
    }
    DCFlushRange((u8*)lbl_803DCA20 + 0x60, 800);
}
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803DE730;
extern f32 lbl_803DE734;
int GameText_CountPrintableChars(u8 * str);
int GameText_FindControlCodeArgs(u8* str, u32 target, int* out);
extern char** textMeasureFn_80016c9c(char* str, f32 width, f32 height, int* outCount, f32* outLineH);

typedef struct SubtitleLineTable
{
    void* blocks[256];
    char* lines[256];
    f32 times[256];
} SubtitleLineTable;

typedef struct SubtitleTextEntry
{
    u8 pad0[2];
    u16 count;
    u8 pad4[4];
    char** strs;
} SubtitleTextEntry;

#pragma opt_strength_reduction on
#pragma optimization_level 1
#pragma peephole off
void subtitleBuildLineTable(void)
{
    int total;
    SubtitleLineTable* s = (SubtitleLineTable*)lbl_8033B240;
    f32 delta;
    f32 curTime;
    int savedCharset;
    SubtitleTextEntry* t;
    u8* win;
    int i;
    char* str;
    int k;
    int m;
    int oldDelay;
    char** strLines;
    int found;
    int q;
    int n;
    int count;
    int args[3];
    f32 ftotal;

    total = 0;
    curTime = lbl_803DE730;
    if (lbl_803DC9F0 != 0)
    {
        savedCharset = gameTextGetCharset();
        gameTextSetCharset(1, 1);
    }
    t = (SubtitleTextEntry*)gameTextGet(lbl_803DC9FC);
    win = gTextBoxes + 0x140;
    lbl_803DCA18 = 0;
    lbl_803DCA14 = 0;
    for (i = 0; i < 256; i++)
    {
        s->times[i] = lbl_803DE734;
    }
    for (i = 0; i < t->count; i++)
    {
        str = t->strs[i];
        n = GameText_FindControlCodeArgs((u8*)str, 0xE018, args);
        if (n != 0)
        {
            q = args[2] / 60;
            s->times[lbl_803DCA18] = (f32)(args[1] + (args[0] * 60 + q));
        }
        strLines = textMeasureFn_80016c9c(str, (f32)(u32) * (u16*)(win + 2), *(f32*)(win + 0xc), &count, NULL);
        if (strLines != NULL)
        {
            for (k = 0; k < count; k++)
            {
                s->lines[lbl_803DCA18++] = strLines[k];
            }
            if (s->blocks[lbl_803DCA14] != NULL)
            {
                oldDelay = mmSetFreeDelay(0);
                mm_free(s->blocks[lbl_803DCA14]);
                mmSetFreeDelay(oldDelay);
            }
            s->blocks[lbl_803DCA14++] = strLines;
        }
    }
    for (k = 0; k < lbl_803DCA18; k++)
    {
        if (lbl_803DE734 != s->times[k])
        {
            curTime = s->times[k];
            total = GameText_CountPrintableChars((u8*)s->lines[k]);
        }
        else
        {
            found = 0;
            m = k;
            for (i = 0; i < 256; i++)
            {
                ftotal = (f32)total;
                if (m < 255)
                {
                    if (lbl_803DE734 != s->times[m + 1])
                    {
                        delta = s->times[m + 1] - curTime;
                        found = 1;
                    }
                    n = GameText_CountPrintableChars((u8*)s->lines[m]);
                    s->times[m] = (f32)n;
                    total += n;
                    if (found != 0)
                    {
                        for (q = m; q >= k; q--)
                        {
                            s->times[q] = s->times[q + 1] - delta * (s->times[q] / (f32)total);
                        }
                        break;
                    }
                    m++;
                }
            }
        }
    }
    lbl_803DCA08 = 0;
    lbl_803DCA10 = 0;
    lbl_803DCA04 = 2;
    if (lbl_803DC9F0 != 0)
    {
        gameTextSetCharset(savedCharset, 1);
    }
}

#pragma optimization_level reset
int GameText_CountPrintableChars(u8* str)
{
    int count;
    int off;
    int len;
    u32 ch;

    count = 0;
    off = 0;
    if (str == NULL)
    {
        return 0;
    }
    while ((ch = utf8GetNextChar(str + off, &len)) != 0)
    {
        off += len;
        if (ch >= 0xE000 && ch <= 0xF8FF)
        {
            off += getControlCharLen(ch) * 2;
        }
        else
        {
            count++;
        }
    }
    return count;
}

int GameText_FindControlCodeArgs(u8* str, u32 target, int* out)
{
    int off;
    int len;
    u32 ch;
    int n;
    int i;

    off = 0;
    if (str == NULL)
    {
        return 0;
    }
    while ((ch = utf8GetNextChar(str + off, &len)) != 0)
    {
        off += len;
        if (ch >= 0xE000 && ch <= 0xF8FF)
        {
            n = getControlCharLen(ch);
            if (ch == target)
            {
                for (i = 0; i < n; i++)
                {
                    u32 hi = str[off++];
                    u32 lo = str[off++];
                    out[i] = (hi << 8) | lo;
                }
                return 1;
            }
            off += n * 2;
        }
    }
    return 0;
}

extern u32 lbl_80339C40[];

SubtitleCmd* subtitleParseControlCmds(int str, int* count)
{
    int off;
    int n;
    u8* tbl;
    int len;
    u32 ch;

    off = 0;
    n = 0;
    tbl = (u8*)lbl_80339C40;
    if ((u8*)str == NULL)
    {
        return NULL;
    }
    while ((ch = utf8GetNextChar((u8*)(str + off), &len)) != 0)
    {
        off += len;
        if (ch >= 0xE000 && ch <= 0xF8FF)
        {
            int i;
            int n2;
            u8* q;

            n++;
            if (n > 0x10)
            {
                break;
            }
            *(u32*)tbl = ch;
            q = tbl + 4;
            n2 = getControlCharLen(ch);
            if (n2 > 4)
            {
                n2 = 4;
            }
            for (i = 0; i < n2; i++)
            {
                u32 hi = ((u8*)str)[off++];
                u32 lo = ((u8*)str)[off++];
                *(u16*)q = (hi << 8) | lo;
                q += 2;
            }
        }
    }
    if (n == 0)
    {
        return NULL;
    }
    {
        int size = n * 0xc;
        u8* buf = mmAlloc(size, 0x1a, 0);
        memcpy(buf, lbl_80339C40, size);
        *count = n;
        return (SubtitleCmd*)buf;
    }
}
