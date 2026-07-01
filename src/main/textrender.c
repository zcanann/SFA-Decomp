#include "ghidra_import.h"
#include "main/audio/sfx.h"
#include "main/gameplay_runtime.h"
#include "dolphin/gx/GXCull.h"
#include "main/mm.h"
#include "main/texture.h"
#include "dolphin/os/OSCache.h"
#include "main/sfa_extern_decls.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/printf.h"
extern int saveFileStruct_isCheatActive(u8 idx);

u16*
FUN_80017460(u64 param_1, u64 param_2, u64 param_3, u64 param_4,
             u64 param_5, u64 param_6, u64 param_7, u64 param_8, u32 param_9
             , int param_10, u32 param_11, u32 param_12, u32 param_13,
             u32 param_14, u32 param_15, u32 param_16)
{
    return 0;
}

u16*
FUN_80017468(u64 param_1, u64 param_2, u64 param_3, u64 param_4,
             u64 param_5, u64 param_6, u64 param_7, u64 param_8, u32 param_9
             , u32 param_10, u32 param_11, u32 param_12, u32 param_13,
             u32 param_14, u32 param_15, u32 param_16)
{
    return 0;
}

typedef struct
{
    u32 key;     /* 0x00 */
    u16 u;       /* 0x04 */
    u16 v;       /* 0x06 */
    s8 offsetX;  /* 0x08 */
    s8 advance;  /* 0x09 */
    s8 offsetY;  /* 0x0a */
    s8 f0b;      /* 0x0b */
    u8 width;    /* 0x0c */
    u8 height;   /* 0x0d */
    u8 lang;     /* 0x0e */
    u8 page;     /* 0x0f */
} TextGlyph;

typedef struct
{
    TextGlyph* glyphs; /* 0x00 */
    u16* entries;      /* 0x04 */
    int glyphCount;    /* 0x08 */
    int entryCount;    /* 0x0c */
    void* textures[3]; /* 0x10 */
    int mode;          /* 0x1c */
    f32 timer;         /* 0x20 */
} TextFont;

extern int curLanguage;
extern TextFont* gameTextFonts;
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
extern int gGameTextShadowOffsetX;
extern int gGameTextShadowOffsetY;
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

extern int utf8GetNextChar(u8* p, int* outLen);
void gameTextMeasureString(u8* str, f32 scale, f32* outW, f32* outZero, f32* outMaxAdv, f32* outMaxH, int glyphLang);
extern void translateToDinoLanguage(u8 * str);
extern void setTextColor(int unused, int a, int b, int c, int d);
extern void _textSetColor(int unused, int a, int b, int c, int d);
extern void textureSetupFn_800799c0(void);
extern void textRenderSetup(void);
extern void textRenderSetupFn_80079804(void);
extern void textRenderSetupFn_800795e8(void);
extern void textBlendSetupFn_80078a7c(void);
extern void selectTexture(u8* tex, int mapId);
extern void GXGetScissor(u32* left, u32* top, u32* wd, u32* ht);
extern void gxSetScissorRect(int a, int b, int c, int d, int e, int f);
extern void textRenderChar(int x0, int y0, int x1, int y1, f32 u0, f32 v0, f32 u1, f32 v1);

void textRenderStr(u8* str, u8* win, f32 x, f32 y, f32 lineH, int mode)
{
    int realign;
    void* tex;
    f32 fx0, fy0, fx1, fy1;
    int byteOff;
    f32 u0, v0;
    int charLen;
    int n2;
    int i;
    int cnt;
    int skipGlyph;
    u8* p;
    TextGlyph* g;
    u8* winBase;
    int glyphLang;
    f32 spaceExtra;
    f32 measW;
    f32 measN;
    int curTexPage;
    u32 ch;
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
    if (gameTextFonts->mode != 2)
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
                    lbl_803DC9A0 = params[0] * lbl_803DE708;
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
                    spaceExtra = ((f32)(u32) * (u16*)(win + 8) - measW) / spaceCount;
                    break;
                }
            }
            realign = 0;
        }

        g = gameTextFonts->glyphs;
        cnt = gameTextFonts->glyphCount;
        while (cnt-- != 0)
        {
            if (g->key == ch && g->lang == glyphLang)
            {
                goto matched;
            }
            g++;
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
            x = lbl_803DC9A0 * (f32)(g->width + (g->advance + g->offsetX)) + x;
            x = x + spaceExtra;
            continue;
        }

        u0 = (f32)(g->u << 5);
        v0 = (f32)(g->v << 5);
        fx0 = (f32)g->offsetX * lbl_803DC9A0;
        fx0 = x + fx0;
        fx0 = lbl_803DE710 * fx0;
        fy0 = (f32)g->offsetY * lbl_803DC9A0;
        fy0 = y + fy0;
        fy0 = lbl_803DE710 * fy0;
        fx1 = lbl_803DE710 * ((f32)(u32)
        g->width * lbl_803DC9A0
        )
        +fx0;
        fy1 = lbl_803DE710 * ((f32)(u32)
        g->height * lbl_803DC9A0
        )
        +fy0;
        if (fx0 < lbl_803DE704 && fx1 > lbl_803DE704)
        {
            u0 = lbl_803DE714 * -fx0 + u0;
            fx0 = lbl_803DE704;
        }
        if (fy0 < *(volatile f32*)&lbl_803DE704 && fy1 > lbl_803DE704)
        {
            v0 = lbl_803DE714 * -fy0 + v0;
            fy0 = lbl_803DE704;
        }

        if (lbl_803DC9BC != 0)
        {
            if (fx0 < lbl_803DC9B0)
            {
                lbl_803DC9B0 = fx0;
            }
            if (fx1 > lbl_803DC9AC)
            {
                lbl_803DC9AC = fx1;
            }
            if (fy0 < lbl_803DC9B8)
            {
                lbl_803DC9B8 = fy0;
            }
            if (fy1 > lbl_803DC9B4)
            {
                lbl_803DC9B4 = fy1;
            }
        }
        else
        {
            if (g->lang == 3)
            {
                int shift = lbl_803DB3CC << 2;
                fy0 = fy0 - shift;
                fy1 = fy1 - shift;
                GXGetScissor(&scisX, &scisY, &scisW, &scisH);
                GXSetScissor(scisX, (scisY >= lbl_803DB3CC) ? scisY - lbl_803DB3CC : 0, scisW, scisH);
            }
            if (g->lang == 5)
            {
                int iw = g->width + (g->advance + g->offsetX);
                int ih = g->height + (g->f0b + g->offsetY);
                GXGetScissor(&scisX, &scisY, &scisW, &scisH);
                gxSetScissorRect(0, 0, *(s16*)(winBase + 0xfd4), *(s16*)(winBase + 0xfd6),
                                 *(s16*)(winBase + 0xfd4) + *(u16*)(winBase + 0xfc8),
                                 *(s16*)(winBase + 0xfd6) + *(u16*)(winBase + 0xfca));
                fx0 = (f32)(*(s16*)(winBase + 0xfd4) + ((*(u16*)(winBase + 0xfc8) - iw) >> 1));
                fx1 = fx0 + iw;
                fy0 = (f32)(*(s16*)(winBase + 0xfd6) + ((*(u16*)(winBase + 0xfca) - ih) >> 1));
                fy1 = fy0 + ih;
                fx0 = fx0 * lbl_803DE710;
                fx1 = fx1 * lbl_803DE710;
                fy0 = fy0 * lbl_803DE710;
                fy1 = fy1 * lbl_803DE710;
            }

            if (mode != 0)
            {
                int ox = gGameTextShadowOffsetX;
                int oy = gGameTextShadowOffsetY;
                fx0 = fx0 + ox;
                fx1 = fx1 + ox;
                fy0 = fy0 + oy;
                fy1 = fy1 + oy;
            }

            if (lbl_803DC9BC == 0)
            {
                if (curTexPage != g->page)
                {
                    curTexPage = g->page;
                    tex = gameTextFonts->textures[g->page];
                    selectTexture(tex, 0);
                    if (lbl_802C8680[g->lang * 16 + 6] == 1)
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

            if (lbl_803DC99C != 0 && mode == 0 && g->lang != 5 &&
                lbl_803DC998 >= lbl_803DC994)
            {
                setTextColor(0, 0, 0, 0, 0);
            }

            if (gameTextDrawFunc != NULL)
            {
                f32 sW = lbl_803DE718 * (f32)(u32) * (u16*)((u8*)tex + 0xa);
                f32 sH = lbl_803DE718 * (f32)(u32) * (u16*)((u8*)tex + 0xc);
                ((void (*)(int, int, int, int, f32, f32, f32, f32))gameTextDrawFunc)(
                    fx0, fy0, fx1, fy1,
                    u0 / sW, v0 / sH,
                    (u0 + (f32)(g->width << 5)) / sW,
                    (v0 + (f32)(g->height << 5)) / sH);
            }
            else
            {
                f32 sW = lbl_803DE718 * (f32)(u32) * (u16*)((u8*)tex + 0xa);
                f32 sH = lbl_803DE718 * (f32)(u32) * (u16*)((u8*)tex + 0xc);
                textRenderChar((int)fx0, fy0, fx1, fy1,
                               u0 / sW, v0 / sH,
                               (u0 + (f32)(g->width << 5)) / sW,
                               (v0 + (f32)(g->height << 5)) / sH);
            }

            if (g->lang == 3 || g->lang == 5)
            {
                GXSetScissor(scisX, scisY, scisW, scisH);
            }
        }

        if ((int)g->lang != 5)
        {
            x = lbl_803DC9A0 * (f32)(g->width + (g->advance + g->offsetX)) + x;
        }
    }
}

static inline TextGlyph* findGlyph(u32 ch, int glyphLang)
{
    TextGlyph* g;
    int cnt;

    g = gameTextFonts->glyphs;
    cnt = gameTextFonts->glyphCount;
    while (cnt-- != 0)
    {
        if (g->key == ch && g->lang == glyphLang)
        {
            return g;
        }
        g++;
    }
    return NULL;
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
    TextGlyph* g;
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
            tbl = (u8*)sLanguageNameTable;
            glyphLang = tbl[curLanguage * 8 + 4];
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
            case 0xf8f4:
                scale = params[0] * lbl_803DE708;
                break;
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
            }
            continue;
        }

        g = findGlyph(ch, glyphLang);
        if (g == NULL)
        {
            continue;
        }
        if (glyphLang == 5)
        {
            continue;
        }
        width = scale * (f32)(g->advance + (g->width + g->offsetX)) + width;
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
                *p = sGameTextGlyphOrder[ch - base] - 0x61 + base;
            }
        }
        byteOff += charLen;
    }
}

extern char gGameTextFontData[];
extern u8 gGameTextBase[];
extern u8 lbl_803399A0[];
extern u8 lbl_803399C0[];
extern int gGameTextFallbackBuf;
extern u8* gGameTextLastEntry;
extern int gCurTextBuffer;
extern int gGameTextBufferIndex;
extern f32 timeDelta;
extern f32 gGameTextFadeLimit;
extern char lbl_803DB3D4;
extern char* sMapDirectoryNameTable[];
extern void* curGameTextDir;
extern void* gameTextGet(int textId);


#pragma peephole on
void* gameTextGetPhrase(int textId, int phraseIndex)
{
    char* strings;
    u16* entry;

    strings = gGameTextFontData;
    if (gameTextFonts->mode != 2)
    {
        gGameTextBufferIndex = gGameTextBufferIndex + 1;
        if (gGameTextBufferIndex >= 8)
        {
            gGameTextBufferIndex = 0;
        }
        entry = (u16*)(lbl_803399C0 + *(volatile int*)&gGameTextBufferIndex * 0xc);
        gGameTextLastEntry = (u8*)entry;
        gCurTextBuffer = *(int*)*(int**)((u8*)entry + 8);
        *entry = 0xffff;
        gGameTextFallbackBuf = (int)(lbl_803399A0 + *(volatile int*)&gGameTextBufferIndex * 4);
        switch (gameTextFonts->mode)
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
        return gGameTextLastEntry;
    }

    entry = gameTextGet(textId);
    if (*entry == 0xffff)
    {
        gGameTextBufferIndex = gGameTextBufferIndex + 1;
        if (gGameTextBufferIndex >= 8)
        {
            gGameTextBufferIndex = 0;
        }
        entry = (u16*)(lbl_803399C0 + *(volatile int*)&gGameTextBufferIndex * 0xc);
        gGameTextLastEntry = (u8*)entry;
        gCurTextBuffer = *(int*)*(int**)((u8*)entry + 8);
        *entry = 0xffff;
        gGameTextFallbackBuf = (int)(lbl_803399A0 + *(volatile int*)&gGameTextBufferIndex * 4);
        sprintf((char*)*(volatile int*)&gCurTextBuffer, strings + 0xefc, textId,
                sMapDirectoryNameTable[(int)curGameTextDir]);
        return gGameTextLastEntry;
    }

    if (phraseIndex >= entry[1])
    {
        gGameTextBufferIndex = gGameTextBufferIndex + 1;
        if (gGameTextBufferIndex >= 8)
        {
            gGameTextBufferIndex = 0;
        }
        entry = (u16*)(lbl_803399C0 + *(volatile int*)&gGameTextBufferIndex * 0xc);
        gGameTextLastEntry = (u8*)entry;
        gCurTextBuffer = *(int*)*(int**)((u8*)entry + 8);
        *entry = 0xffff;
        gGameTextFallbackBuf = (int)(lbl_803399A0 + *(volatile int*)&gGameTextBufferIndex * 4);
        sprintf((char*)*(volatile int*)&gCurTextBuffer, strings + 0xf10, textId, phraseIndex);
        return gGameTextLastEntry;
    }

    return *(void**)(*(int*)((u8*)entry + 8) + phraseIndex * 4);
}

void* gameTextGetStr(int textId)
{
    u8* entry;
    char* strings;
    void* t;

    strings = gGameTextFontData;
    if (gameTextFonts->mode != 2)
    {
        gGameTextBufferIndex = gGameTextBufferIndex + 1;
        if (gGameTextBufferIndex >= 8)
        {
            gGameTextBufferIndex = 0;
        }
        entry = lbl_803399C0 + gGameTextBufferIndex * 0xc;
        gGameTextLastEntry = entry;
        gCurTextBuffer = *(int*)*(int**)(entry + 8);
        *(u16*)entry = 0xffff;
        gGameTextFallbackBuf = (int)(lbl_803399A0 + *(volatile int*)&gGameTextBufferIndex * 4);
        switch (gameTextFonts->mode)
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
        return gGameTextLastEntry;
    }
    t = gameTextGet(textId);
    return *(void**)*(u8**)((u8*)t + 8);
}

#pragma peephole off
void* gameTextGet(int textId)
{
    u8* gameTextBase;
    char* strings;
    TextFont* fonts;
    u16* entry;
    int count;
    int slotIndex;
    u16* cachedEntry;
    f32 zero;
    f32* cachedAlpha;

    gameTextBase = gGameTextBase;
    strings = gGameTextFontData;
    fonts = gameTextFonts;

    if (fonts->mode != 2)
    {
        gGameTextBufferIndex++;
        if (gGameTextBufferIndex >= 8)
        {
            gGameTextBufferIndex = 0;
        }
        {
            u8* slotBase = gameTextBase + *(volatile int*)&gGameTextBufferIndex * 0xc;
            entry = (u16*)(slotBase + 0x40);
        }
        gGameTextLastEntry = (u8*)entry;
        gCurTextBuffer = *(int*)*(int**)((u8*)entry + 8);
        *entry = 0xffff;
        { u8* fb = gameTextBase + *(volatile int*)&gGameTextBufferIndex * 4; gGameTextFallbackBuf = (int)(fb + 0x20); }

        switch (gameTextFonts->mode)
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
        return gGameTextLastEntry;
    }

    entry = fonts->entries;
    count = fonts->entryCount;
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
    while (cachedEntry -= 6, slotIndex-- != 0)
    {
        if (*cachedEntry == textId)
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
                    sprintf((char*)*(int*)*(int**)((u8*)cachedEntry + 8), strings + 0xefc, textId,
                            sMapDirectoryNameTable[(int)curGameTextDir]);
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
    {
        u8* slotBase = gameTextBase + *(volatile int*)&gGameTextBufferIndex * 0xc;
        entry = (u16*)(slotBase + 0x40);
    }
    gGameTextLastEntry = (u8*)entry;
    gCurTextBuffer = *(int*)*(int**)((u8*)entry + 8);
    *entry = 0xffff;
    { u8* fb = gameTextBase + *(volatile int*)&gGameTextBufferIndex * 4; gGameTextFallbackBuf = (int)(fb + 0x20); }
    sprintf((char*)*(volatile int*)&gCurTextBuffer, &lbl_803DB3D4, textId,
            sMapDirectoryNameTable[(int)curGameTextDir]);
    *(u16*)gGameTextLastEntry = textId;
    *(f32*)gGameTextFallbackBuf = lbl_803DE704;
    return gGameTextLastEntry;
}
#pragma peephole reset

u32
#pragma scheduling on
FUN_80017500(u64 param_1, u64 param_2, u64 param_3, u64 param_4,
             u64 param_5, u64 param_6, u64 param_7, u64 param_8, int param_9)
{
    return 0;
}

u32
FUN_8001786c(u64 param_1, double param_2, double param_3, u64 param_4, u64 param_5,
             u64 param_6, u64 param_7, u64 param_8, u32 param_9,
             u32 param_10, u32 param_11, u32 param_12)
{
    return 0;
}

u8*
FUN_80017998(u64 param_1, u64 param_2, u64 param_3, u64 param_4,
             u64 param_5, u64 param_6, u64 param_7, u64 param_8, u32 param_9
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

f32 gameTextFn_80019c00(void)
{
    return gameTextFonts->timer;
}

typedef struct
{
    u8 _pad[0x1c];
    int state;
    u8 _pad2[8];
} GameTextStateElem;

extern GameTextStateElem gGameTextCharsets[];

#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
int gameTextGetState(int i)
{
    return gGameTextCharsets[i].state;
}


extern int gGameTextSequenceMode;
extern int gSubtitleActive;
extern void* gGameTextPendingDir;

#pragma dont_inline off
void mainLoopDoGameText(void)
{
    if (gGameTextSequenceMode != 0)
    {
        if (gameTextGetState(1) == 2 && gSubtitleActive == 1)
        {
            subtitleBuildLineTable();
        }
    }
    else
    {
        if (gameTextGetState(0) == 2 && (int)gGameTextPendingDir == (int)getCurGameText() &&
            gSubtitleActive == 1)
        {
            subtitleBuildLineTable();
        }
    }
}

int mmSetFreeDelay(int v);

int testAndSet_onlyUseHeap3(int v);


extern void gameTextLoadDir(int dirId);
extern u8 lbl_803DC980;

void gameTextInit(void)
{
    gameTextInitFn_8001c794();
    lbl_803DC980 = 1;
    gameTextLoadDir(0x1c);
}


extern void subtitleFn_8001b700(void);
extern int gSubtitlesEnabled;
extern u16 lbl_803DC9AA;
extern u16 lbl_803DC9A8;
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
    int old = gSubtitlesEnabled;
    gSubtitlesEnabled = enabled;
    if (enabled == 0)
    {
        subtitleFn_8001b700();
    }
    return old;
}

extern int gGameTextClearColor;
extern void hudDrawRect(int x0, int y0, int x1, int y1, void* color);
extern int gGameTextLastDir;

extern int gameTextFn_8001b44c(int x);
extern void gameTextLoadForCurMap(int sourceId);

#pragma dont_inline on
void gameTextSetCharset(int charset, int flags)
{
    if (gameTextDrawFunc != NULL || (flags & 1))
    {
        gameTextFonts = (TextFont*)&gGameTextCharsets[charset];
        gameTextCharset = charset;
        if (charset == 2)
        {
            int color = gGameTextClearColor;
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
        gameTextFonts = (TextFont*)&gGameTextCharsets[2];
        gameTextCharset = 2;
        color = gGameTextClearColor;
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
        gameTextFonts = (TextFont*)&gGameTextCharsets[3];
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
        gameTextFonts = (TextFont*)&gGameTextCharsets[0];
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
            (int)curGameTextDir != gGameTextLastDir)
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
        int* p = &lbl_8033A540[lbl_803DC9C8++].v;
        *p = 0xb;
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

void gameTextSetCursor(u16 x, u16 y, int flags)
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
extern int gGameTextSavedDir;
extern s16 gGameTextTaskTextAllowList[];
extern int gGameTextPendingTextId;
extern u8 gSubtitleColorR;
extern u8 gSubtitleColorG;
extern u8 gSubtitleColorB;
extern u8 gSubtitleColorA;
extern int gameTextGetTaskText(int taskId, int* textId, int* dirId);
extern void loadGameTextSequence();

int gameTextFn_8001b44c(int x)
{
    if (gGameTextSequenceMode == 0)
    {
        gGameTextSavedDir = x;
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
        if (gSubtitlesEnabled == 0)
        {
            taskList = gGameTextTaskTextAllowList;
            for (count = 0; count < 0xb; count++)
            {
                if (taskId == taskList[count])
                {
                    allowed = 1;
                    goto checkAllowed;
                }
            }
            allowed = 0;
        checkAllowed:
            if (allowed == 0)
            {
                return;
            }
        }

        gGameTextPendingTextId = textId;
        gGameTextPendingDir = (void*)dirId;
        if (dirId == 0x29)
        {
            loadGameTextSequence();
            gGameTextSequenceMode = 1;
        }
        else
        {
            gGameTextSavedDir = (int)getCurGameText();
            gameTextLoadDir((int)gGameTextPendingDir);
            gGameTextSequenceMode = 0;
        }
        gSubtitleActive = 1;
        gSubtitleColorR = 0xff;
        gSubtitleColorG = 0xff;
        gSubtitleColorB = 0xff;
        gSubtitleColorA = 0xff;
    }
}
#pragma peephole reset

int subtitleIsActive(void)
{
    int ret;

    ret = 0;
    if (gSubtitlesEnabled != 0)
    {
        if (gSubtitleActive != 0)
        {
            ret = 1;
        }
    }
    return ret;
}

int mmCreateMemoryStore(int size);

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
#pragma optimization_level 2
void gameTextSetWindowStrPos(int idx, int x, int y)
{
    if (gameTextDrawFunc != NULL)
    {
        s16 sx = x;
        s16* base = (s16*)gTextBoxes;
        s16* box = base + idx * 0x10;
        box[0xc] = sx;
        box[0xd] = y;
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
#pragma optimization_level reset

extern void* gSubtitleBoxTextures[];
extern void* gSubtitleLineTable[];
extern int gSubtitleBlockCount;

#pragma peephole off
#pragma opt_unroll_loops off
void gameTextInitFn_8001bd14(void)
{
    int i;
    int zero;
    int (*scratch)[8];

    zero = 0;
    gSubtitleActive = zero;
    gSubtitlesEnabled = 1;
    gGameTextSavedDir = -1;

    scratch = (int(*)[8])gSubtitleLineTable;
    for (i = 0; i < 32; i++)
    {
        scratch[i][0] = zero;
        scratch[i][1] = zero;
        scratch[i][2] = zero;
        scratch[i][3] = zero;
        scratch[i][4] = zero;
        scratch[i][5] = zero;
        scratch[i][6] = zero;
        scratch[i][7] = zero;
    }
}
#pragma opt_unroll_loops on
#pragma peephole reset

#pragma dont_inline on
void subtitleFn_8001b700(void)
{
    void** slot;
    int i;
    int oldDelay;

    if (gSubtitleActive != 0)
    {
        gSubtitleActive = 0;
        i = 0;
        slot = gSubtitleLineTable;
        while (i < gSubtitleBlockCount)
        {
            if (slot[i] != NULL)
            {
                oldDelay = mmSetFreeDelay(0);
                mm_free(slot[i]);
                mmSetFreeDelay(oldDelay);
                slot[i] = NULL;
            }
            i++;
        }

        if (gGameTextSavedDir != -1)
        {
            gameTextLoadDir(gGameTextSavedDir);
            gGameTextSavedDir = -1;
        }
    }
}

#pragma dont_inline off
void fn_8001BDD4(int mode)
{
    switch (mode)
    {
    case 3:
        textureFree(gSubtitleBoxTextures[0]);
        textureFree(gSubtitleBoxTextures[1]);
        textureFree(gSubtitleBoxTextures[2]);
        break;
    }
}

void fn_8001BE2C(int mode)
{
    switch (mode)
    {
    case 3:
        gSubtitleBoxTextures[0] = textureLoadAsset(0x43b);
        gSubtitleBoxTextures[1] = textureLoadAsset(0x43e);
        gSubtitleBoxTextures[2] = textureLoadAsset(0x43d);
        break;
    }
}

void subtitleStart(int x)
{
    if (gSubtitlesEnabled != 0)
    {
        gGameTextPendingTextId = x;
        gGameTextPendingDir = getCurGameText();
        gGameTextSequenceMode = 0;
        gGameTextSavedDir = -1;
        gSubtitleActive = 1;
        gSubtitleColorR = 0xff;
        gSubtitleColorG = 0xff;
        gSubtitleColorB = 0xff;
        gSubtitleColorA = 0xff;
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
extern int gGameTextLastLanguage;
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


void gameTextInitFn_8001a234(void)
{
    u8* clearPtr;
    u8** glyphPagePtr;
    u8* fontState;
    u8* textWindow;
    u8* gameTextBase;
    u8* glyphPage;
    u8* request;
    u8* p;
    f32 zero;
    int i;
    int j;

    gameTextBase = gGameTextBase;

    i = 0x94;
    p = textWindow = gTextBoxes + 0x1280;
    while (p -= 0x20, i-- != 0)
    {
        *(u16*)(p + 8) = *(u16*)(p + 2);
        *(u16*)(p + 0xa) = *(u16*)(p + 6);
    }

    i = GAMETEXT_LOAD_SLOT_COUNT;
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
    request = gameTextBase + GAMETEXT_LOAD_SLOTS_OFFSET;
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

    gameTextFonts = (TextFont*)(gameTextBase + GAMETEXT_FONT_SLOT_OFFSET);
    gameTextCharset = 2;
    curLanguage = -1;
    curGameTextDir = (void*)-1;
    gCurTextBox = NULL;
    gGameTextLastLanguage = -1;
    gGameTextLastDir = -1;
    lbl_803DC9BC = 0;
    lbl_803DC9A7 = 0xff;
    lbl_803DC9A6 = 0xff;
    lbl_803DC9A5 = 0xff;
    lbl_803DC9A4 = 0xff;
    lbl_803DC9C8 = 0;
    lbl_803DC9C4 = gameTextBase + GAMETEXT_COMMAND_STRING_BUFFER_OFFSET;
    gGameTextBufferIndex = 0;
    textWindow = gameTextBase + 0x40;
    gGameTextLastEntry = textWindow;
    gCurTextBuffer = *(int*)*(void**)(textWindow + 8);
    lbl_803DC992 = 0;
    lbl_803DC991 = 0;
    lbl_803DC990 = 0;
    gGameTextShadowOffsetX = 5;
    gGameTextShadowOffsetY = 5;
    lbl_803DC984 = 1;
    lbl_803DC980 = 0;
    gameTextLoadGraphicsFn_8001a918();
    curGameTextDir = (void*)3;
    lbl_803DB378 = mmCreateMemoryStore(0x800);
}

void gameTextRun(void)
{
    GameTextSlot* cmd;
    u8* gameTextBase;
    int sourceId;
    GameTextLoadSlot* freeSlot;
    u8* pending;
    int i;
    int dirId;
    int languageId;
    GameTextLoadSlot* slot;
    u8* textWindow;
    int color;
    double fadeLimit;
    double zero;

    gameTextBase = gGameTextBase;
    cmd = (GameTextSlot*)(gameTextBase + 0xbc0);

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
                freeSlot->dirId = dirId;
                freeSlot->languageId = languageId;
                freeSlot->active = 1;
                freeSlot->sourceId = sourceId;
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
    fadeLimit = gGameTextFadeLimit;
    i = GAMETEXT_LOAD_SLOT_COUNT;
    {
        f32* timer = (f32*)(gameTextBase + 0x40);
        u8* entry = gameTextBase + 0xa0;
        f32* alpha = (f32*)(gameTextBase + 0x20);
        do
        {
            if ((double)*timer > zero)
            {
                *alpha += timeDelta;
                if ((double)*alpha > fadeLimit)
                {
                    *timer = zero;
                    *alpha = zero;
                    sprintf(**(char***)(entry + 8), &lbl_803DB3D4);
                }
            }
            timer--;
            alpha--;
            entry -= 0xc;
        }
        while (i-- != 0);
    }

    if (gameTextFonts->mode == 1)
    {
        gameTextFonts->timer += timeDelta;
    }
    else
    {
        gameTextFonts->timer = lbl_803DE704;
    }

    textWindow = gTextBoxes;
    for (i = 148; i != 0; i--)
    {
        *(u16*)(textWindow + 0x1c) &= ~1;
        textWindow += 0x20;
    }

    lbl_803DC99C = 0;
    lbl_803DC9AA = 0;
    lbl_803DC9A8 = 0;

    i = lbl_803DC9C8;
    while (i-- != 0)
    {
        switch (cmd->v)
        {
        case 3:
            {
                u8 c0 = cmd->f4;
                u8 c1 = cmd->f8;
                u8 c2 = cmd->fc;
                u8 c3 = cmd->f10;
                lbl_803DC9A7 = c0;
                lbl_803DC9A6 = c1;
                lbl_803DC9A5 = c2;
                lbl_803DC9A4 = c3;
                break;
            }
        case 4:
            {
                int t1 = cmd->fc;
                s16 t2 = cmd->f8;
                textWindow = gTextBoxes + cmd->f4 * 0x20;
                *(s16*)(textWindow + 0x18) = t2;
                *(s16*)(textWindow + 0x1a) = t1;
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
                *(s16*)(textWindow + 0x18) = cmd->fc;
                *(s16*)(textWindow + 0x1a) = t3;
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
            {
                u16 b1 = cmd->f8;
                lbl_803DC9AA = (u16)cmd->f4;
                lbl_803DC9A8 = b1;
                break;
            }
        case 11:
            lbl_803DC9AA = 0;
            lbl_803DC9A8 = 0;
            break;
        case 12:
            lbl_803DC984 = cmd->f4;
            break;
        case 14:
            {
                u8 e0 = cmd->f4;
                u8 e1 = cmd->f8;
                u8 e2 = cmd->fc;
                lbl_803DC992 = e0;
                lbl_803DC991 = e1;
                lbl_803DC990 = e2;
                break;
            }
        case 13:
            {
                int sy = cmd->f8;
                gGameTextShadowOffsetX = cmd->f4;
                gGameTextShadowOffsetY = sy;
                break;
            }
        case 15:
            gameTextFonts = (TextFont*)(gameTextBase + GAMETEXT_PENDING_REQUEST_SCAN_OFFSET + cmd->f4 * 0x28);
            gameTextCharset = cmd->f4;
            if (cmd->f4 == 2)
            {
                color = gGameTextClearColor;
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

    i = 0x94;
    textWindow = gTextBoxes + 0x1280;
    do
    {
        textWindow -= 0x20;
        *(s16*)(textWindow + 0x18) = 0;
        *(s16*)(textWindow + 0x1a) = 0;
    }
    while (i-- != 0);
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

    gameTextBase = gGameTextBase;
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
    freeSlot->dirId = sequenceSlotDir;
    freeSlot->languageId = curLanguage;
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
    u8* dirPtr;
    u8* langPtr;
    int oldHeap;
    int dirId;
    int languageId;
    GameTextLoadSlot* slot;
    GameTextLoadSlot* freeSlot;
    GameTextLoadRequest* request;
    u8* gameTextBase;
    int i;

    gameTextBase = gGameTextBase;
    oldHeap = testAndSet_onlyUseHeap3(0);
    if (getGameState() != 0 && getGameState() != 1)
    {
        testAndSet_onlyUseHeap3(oldHeap);
        return;
    }

    gGameTextLastDir = dirId = (int)curGameTextDir;
    gGameTextLastLanguage = languageId = curLanguage;
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

    request = (GameTextLoadRequest*)(gameTextBase +
        sourceId * sizeof(GameTextLoadRequest));
    *(int*)((u8*)request + GAMETEXT_LOAD_REQUESTS_OFFSET) = 1;
    *(dirPtr = (u8*)request + GAMETEXT_LOAD_REQUESTS_OFFSET + 8) = (u8)curGameTextDir;
    *(langPtr = (u8*)request + GAMETEXT_LOAD_REQUESTS_OFFSET + 9) = curLanguage;

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
        int slotDir = *dirPtr;
        int slotLang = *langPtr;
        freeSlot->state = 1;
        freeSlot->dirId = slotDir;
        freeSlot->languageId = slotLang;
        freeSlot->active = 1;
        freeSlot->sourceId = sourceId;
        sprintf((char*)(gameTextBase + GAMETEXT_PATH_BUFFER_OFFSET), sGameTextMapPathFormat,
                sMapDirectoryNameTable[slotDir], sLanguageNameTable[slotLang][0]);
        setFileInfo(freeSlot);
        freeSlot->loadHandle =
            loadFileByPathAsync((char*)(gameTextBase + GAMETEXT_PATH_BUFFER_OFFSET),
                                &freeSlot->dvdFileInfo, 1, gameTextOpenCallback_8001b3d0);
        setFileInfo(NULL);
        *dirPtr = GAMETEXT_INVALID_DIR;
        *langPtr = GAMETEXT_INVALID_LANGUAGE;
    }

    testAndSet_onlyUseHeap3(oldHeap);
}

extern void* lbl_8033BE40[];
extern int gGameTextBoxCornerInset;
extern void* gGameTextBoxCornerTexture;
extern void* gGameTextBoxBgTexture;
extern u32 gGameTextBoxFillColor;
extern u8* gameTextGetCurBox(void);
extern void gameTextFn_8001628c(int id, int a, int b, int* outMaxX, int* outMaxY, int* outMinX, int* outMinY);
extern void gameTextBoxFn_800164b0(int id, int idx, int* x0, int* x1, int* y0, int* y1);
extern void drawTexture(void* tex, f32 x, f32 y, int alpha, int scale);
extern void drawScaledTexture(void* tex, f32 x, f32 y, int alpha, int scale, int w, int h, int flag);
extern void drawPartialTexture(void* tex, f32 x, f32 y, int alpha, int scale, int w, int h, int part, int flag);
extern void drawHudBox(s16 x, s16 y, s16 w, s16 h, int alpha, u8 flag);

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
    s16 savedY;
    s16 savedX;
    u16 f;
    u8* cur;
    int cy;
    int cx;
    int hh;
    int hw;
    s16 x7;
    s16 y7;
    u16 w7;
    u16 h7;
    int c3x0;
    int y2;
    int w2;
    int xw;
    s16 x2;
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
            u16 bh = ((GameTextBox*)box)->height;
            u16 bw = ((GameTextBox*)box)->width;
            s16 by = ((GameTextBox*)box)->y;
            s16 bx = ((GameTextBox*)box)->x;
            colorB = gGameTextBoxFillColor;
            hudDrawRect(bx, by, bx + bw, by + bh, &colorB);
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
        {
            u16 bh = ((GameTextBox*)box)->height;
            u16 bw = ((GameTextBox*)box)->width;
            s16 by = ((GameTextBox*)box)->y;
            s16 bx = ((GameTextBox*)box)->x;
            colorA = gGameTextBoxFillColor;
            hudDrawRect(bx, by, bx + bw, by + bh, &colorA);
        }
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
        else if ((u32)boxId != 0)
        {
            gameTextBoxFn_800164b0(boxId, (int)(box - gTextBoxes) / 0x20, &c6x0, &c6x1, &c6y0, &c6y1);
        }
        gameTextSetWindow(cur);
        hw = (c6x1 - c6x0) >> 1;
        hh = (c6y1 - c6y0) >> 1;
        cx = c6x0 + hw;
        cy = c6y0 + hh;
        drawScaledTexture(gGameTextBoxCornerTexture, (f32)(c6x0 - gGameTextBoxCornerInset), (f32)(c6y0 - gGameTextBoxCornerInset), 0xff, 0x100,
                          hw + gGameTextBoxCornerInset, hh + gGameTextBoxCornerInset, 0);
        drawScaledTexture(gGameTextBoxCornerTexture, (f32)cx, (f32)(c6y0 - gGameTextBoxCornerInset), 0xff, 0x100,
                          hw + gGameTextBoxCornerInset, hh + gGameTextBoxCornerInset, 1);
        drawScaledTexture(gGameTextBoxCornerTexture, (f32)(c6x0 - gGameTextBoxCornerInset), cy, 0xff, 0x100,
                          hw + gGameTextBoxCornerInset, hh + gGameTextBoxCornerInset, 2);
        drawScaledTexture(gGameTextBoxCornerTexture, (f32)cx, cy, 0xff, 0x100,
                          hw + gGameTextBoxCornerInset, hh + gGameTextBoxCornerInset, 3);
        break;
    case 0:
        drawScaledTexture(gGameTextBoxBgTexture, (f32)((GameTextBox*)box)->x, (f32)((GameTextBox*)box)->y, 0xff, 0x100,
                          ((GameTextBox*)box)->width, ((GameTextBox*)box)->height, 0);
        break;
    case 3:
        cur = gameTextGetCurBox();
        if (strPtr != NULL)
        {
            gameTextFn_8001628c(*strPtr, 0, 0, &c3x0, &c3x1, &c3y0, &c3y1);
        }
        else if ((u32)boxId != 0)
        {
            gameTextBoxFn_800164b0(boxId, (int)(box - gTextBoxes) / 0x20, &c3x0, &c3x1, &c3y0, &c3y1);
        }
        gameTextSetWindow(cur);
        drawTexture(gSubtitleBoxTextures[0], (f32)(c3x0 - 0x16), (f32)(c3y0 - 9), ((GameTextBox*)box)->alpha, 0x100);
        drawScaledTexture(gSubtitleBoxTextures[1], (f32)c3x0, (f32)(c3y0 - 9), ((GameTextBox*)box)->alpha, 0x100,
                          c3x1 - c3x0, 0x24, 0);
        drawTexture(gSubtitleBoxTextures[2], (f32)c3x1, (f32)(c3y0 - 9), ((GameTextBox*)box)->alpha, 0x100);
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
        drawTexture(lbl_8033BE40[0], (f32)(x2 - 0x34), (f32)(y2 - 0x23), ((GameTextBox*)box)->alpha, 0x100);
        drawTexture(lbl_8033BE40[4], (f32)xw, (f32)(y2 - 0x23), ((GameTextBox*)box)->alpha, 0x100);
        if (half != 0)
        {
            drawScaledTexture(lbl_8033BE40[1], (f32)x2, (f32)(y2 - 0x13), ((GameTextBox*)box)->alpha, 0x100,
                              half, 0x3a, 0);
            drawPartialTexture(lbl_8033BE40[3], (f32)(xw - half), (f32)(y2 - 0x13), ((GameTextBox*)box)->alpha, 0x100,
                               half, 0x3a, 0xc - half, 0);
        }
        if (rem != 0)
        {
            drawScaledTexture(lbl_8033BE40[2], (f32)(x2 + half), (f32)(y2 - 0x13), ((GameTextBox*)box)->alpha, 0x100,
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

extern int mmSetFreeDelay(int v);
extern void* textureAlloc(u16 w, u16 h, int fmt, u8 mip, u8 maxLod, u8 b8, u8 b9, u8 b10, u8 b11);

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
#pragma peephole off
void setLanguageFn_8001ad64(void* reqp)
{
    u8* req = reqp;
    int** slot;
    u16* p;
    u32 bpp;
    int ofs;
    int* table;
    u32 w;
    u32 h;
    int i;
    u8* txt;
    int* texHdr;
    u8* hdr;
    u16* texStart;
    int* data;
    u16 kind;
    u8* entries;
    int numStrings;
    int* strs;
    int n;
    u32 size;
    u16* newBuf;
    u16* old;
    int delta;
    int* strs2;
    GameTextCharset* cs;

    DCStoreRange(*(void**)(req + 0x3c), *(u32*)(req + 0x40));
    if (req[0x4b] == 1)
    {
        cs = (GameTextCharset*)&gGameTextCharsets[1];
    }
    else if (req[0x4b] == 3)
    {
        cs = (GameTextCharset*)&gGameTextCharsets[3];
    }
    else
    {
        cs = (GameTextCharset*)&gGameTextCharsets[0];
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
    entries = hdr + 8;
    cs->entries = entries;
    table = (int*)(entries + cs->count * 12);
    numStrings = table[0];
    strs = table + 1;
    for (i = 0; i < cs->count; i++)
    {
        *(int**)(cs->entries + i * 12 + 8) = strs + *(int*)(cs->entries + i * 12 + 8);
    }
    txt = (u8*)(table + numStrings) + 4;
    for (i = 0; i < numStrings; i++)
    {
        strs[i] = strs[i] + (int)txt;
    }
    texHdr = (int*)(txt + ofs);
    p = (u16*)((u8*)texHdr + texHdr[0]);
    p = (u16*)((u8*)p + 4);
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
                u8* src8 = (u8*)p;
                u8* dst8 = (u8*)slot[4] + 0x60;
                n = (int)(w * h) >> 1;
                while (n--)
                {
                    *dst8++ = *src8++;
                }
                DCFlushRange((u8*)slot[4] + 0x60, *(u32*)((u8*)slot[4] + 0x44));
            }
            else
            {
                u16* src16 = p;
                u16* dst16 = (u16*)((u8*)slot[4] + 0x60);
                n = w * h;
                while (n--)
                {
                    *dst16++ = *src16++;
                }
                DCFlushRange((u8*)slot[4] + 0x60, *(u32*)((u8*)slot[4] + 0x44));
            }
        }
        p += (int)(w * h * bpp) >> 4;
        slot = slot + 1;
    }
    size = (u32)((u8*)texStart - *(u8**)(req + 0x3c));
    newBuf = mmAlloc(size, 0x1a, 0);
    n = size >> 1;
    {
        u16* d = newBuf;
        u16* s;
        old = *(u16**)(req + 0x3c);
        s = old;
        delta = (int)newBuf - (int)old;
        while (n--)
        {
            *d++ = *s++;
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
        strs2[i] += delta;
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
extern u16 gGameTextSjisGlyphTable[];
extern int lbl_803DB3C4;

#pragma peephole off
#pragma ppc_unroll_speculative off
void gameTextLoadGraphicsFn_8001a918(void)
{
    int wbytes;
    u8* base30;
    u8* base31;
    u8* buf;
    int sizeA;
    int y;
    int x;
    u8* bufA;
    u8* bufB;
    int savedHeap;
    int count;
    u8* glyph;
    int sizeB;
    u8* fontData;
    u8 s[3];
    int width;

    fontData = (u8*)gGameTextFontData;
    base30 = lbl_802C8680;
    base31 = (u8*)gGameTextCharsets;
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
            u16* p = gGameTextSjisGlyphTable;
            int i;
            u32 val;
            int hi;
            u8 lo;
            for (i = 0xfd; i >= 0; i--)
            {
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
                int j2;
                for (j2 = tx; j2 < txEnd; j2++)
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
#pragma ppc_unroll_speculative on


extern int gSubtitleLineIndex;
extern f32 gSubtitleCurTime;
extern int gSubtitleElapsedFrames;
extern int gSubtitleLineCount;
extern int gSubtitleLineStrs[];
extern f32 gSubtitleLineTimes[];
extern f32 gSubtitleFramesPerSecond;

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

    if (gSubtitleActive == 2)
    {
        if (gGameTextSequenceMode != 0)
        {
            charset = gameTextGetCharset();
            gameTextSetCharset(1, 2);
        }
        if (getHudHiddenFrameCount() == 0)
        {
            gSubtitleElapsedFrames += framesThisStep;
        }
        gSubtitleCurTime = gSubtitleElapsedFrames / gSubtitleFramesPerSecond;
        if (gSubtitleLineIndex + 1 < gSubtitleLineCount && gSubtitleCurTime >= gSubtitleLineTimes[gSubtitleLineIndex + 1])
        {
            cmds = subtitleParseControlCmds(gSubtitleLineStrs[gSubtitleLineIndex], &n);
            if (cmds != NULL)
            {
                SubtitleCmd* p = &cmds[n];
                while (p--, n-- != 0)
                {
                    if (p->code == 0xf8ff)
                    {
                        SubtitleCmd* e = &cmds[n];
                        gSubtitleColorR = e->r;
                        gSubtitleColorG = e->g;
                        gSubtitleColorB = e->b;
                        gSubtitleColorA = e->a;
                        break;
                    }
                }
                delay = mmSetFreeDelay(0);
                mm_free(cmds);
                mmSetFreeDelay(delay);
            }
            gSubtitleLineIndex++;
            if (gSubtitleLineIndex + 1 >= gSubtitleLineCount)
            {
                subtitleFn_8001b700();
                if (gGameTextSequenceMode != 0)
                {
                    gameTextSetCharset(charset, 2);
                }
                return;
            }
        }
        gameTextSetColor(gSubtitleColorR, gSubtitleColorG, gSubtitleColorB, gSubtitleColorA);
        gameTextShowStr(gSubtitleLineStrs[gSubtitleLineIndex], 10, 0, 0);
        if (gGameTextSequenceMode != 0)
        {
            gameTextSetCharset(charset, 2);
        }
    }
}

extern int gGameTextBoxInset;
extern int gGameTextBoxColorR;
extern int gGameTextBoxColorG;
extern int gGameTextBoxColorB;
extern int gGameTextBoxColorA;
extern void* gGameTextBoxEdgeTexture;

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
    alpha |= *(u8*)(p + 0x1e);
    x = *(s16*)(p + 0x14);
    y = *(s16*)(p + 0x16);
    halfW = ((x + *(u16*)(p + 0x8)) - *(s16*)(p + 0x14)) >> 1;
    halfH = ((y + *(u16*)(p + 0xa)) - *(s16*)(p + 0x16)) >> 1;
    midX = x + halfW;
    midY = y + halfH;
    setTextColor(0, gGameTextBoxColorR & 0xff, gGameTextBoxColorG & 0xff, gGameTextBoxColorB & 0xff, gGameTextBoxColorA & 0xff);
    textureSetupFn_800799c0();
    textRenderSetupFn_800795e8();
    textRenderSetupFn_80079804();
    ((void (*)(void*, f32, f32, int, int, int, int, int))drawScaledTexture)(
        gGameTextBoxEdgeTexture, (f32)(x - gGameTextBoxInset), (f32)(y - gGameTextBoxInset), alpha, 0x100, halfW + gGameTextBoxInset,
        halfH + gGameTextBoxInset, 0);
    ((void (*)(void*, f32, f32, int, int, int, int, int))drawScaledTexture)(
        gGameTextBoxEdgeTexture, midX, (f32)(y - gGameTextBoxInset), alpha, 0x100, halfW + gGameTextBoxInset, halfH + gGameTextBoxInset, 1);
    ((void (*)(void*, f32, f32, int, int, int, int, int))drawScaledTexture)(
        gGameTextBoxEdgeTexture, (f32)(x - gGameTextBoxInset), midY, alpha, 0x100, halfW + gGameTextBoxInset, halfH + gGameTextBoxInset, 2);
    ((void (*)(void*, f32, f32, int, int, int, int, int))drawScaledTexture)(
        gGameTextBoxEdgeTexture, midX, midY, alpha, 0x100, halfW + gGameTextBoxInset, halfH + gGameTextBoxInset, 3);
}

extern s16 gGameTextBoxTexAssets;
extern u16 gGameTextBoxCornerTexSrc[];
extern u16 lbl_802CA100[];

#pragma opt_strength_reduction off
#pragma optimization_level 1
#pragma scheduling off
#pragma peephole off
void gameTextInitFn_8001c794(void)
{
    void** q;
    s16* p;
    int i;
    int j;
    int x;
    int x0;
    int y;
    int x1;
    int x2;
    int x3;
    int off;
    u16* dst;
    u16* src;
    u8* rowBase;
    void* tex;

    i = 1;
    p = &gGameTextBoxTexAssets + 1;
    q = &gGameTextBoxBgTexture + 1;
    while (p--, q--, i-- != 0)
    {
        *q = textureLoadAsset(*p);
    }

    tex = textureAlloc(0x10, 0x10, 5, 0, 0, 0, 0, 1, 1);
    gGameTextBoxCornerTexture = tex;
    dst = (u16*)((u8*)tex + 0x60);
    y = 0;
    src = gGameTextBoxCornerTexSrc;
    for (i = 0; i < 4; i++)
    {
        x0 = 0;
        for (x = 0; x < 16; x += 8)
        {
            x1 = (x + 1) * 2;
            x2 = (x + 2) * 2;
            x3 = (x + 3) * 2;
            off = y * 32;
            rowBase = (u8*)src + off;
            dst[0] = *(u16*)(rowBase + x0);
            dst[1] = *(u16*)(rowBase + x1);
            dst[2] = *(u16*)(rowBase + x2);
            dst[3] = *(u16*)(rowBase + x3);
            off += 32;
            rowBase = (u8*)src + off;
            dst[4] = *(u16*)(rowBase + x0);
            dst[5] = *(u16*)(rowBase + x1);
            dst[6] = *(u16*)(rowBase + x2);
            dst[7] = *(u16*)(rowBase + x3);
            off += 32;
            rowBase = (u8*)src + off;
            dst[8] = *(u16*)(rowBase + x0);
            dst[9] = *(u16*)(rowBase + x1);
            dst[10] = *(u16*)(rowBase + x2);
            dst[11] = *(u16*)(rowBase + x3);
            off += 32;
            rowBase = (u8*)src + off;
            dst[12] = *(u16*)(rowBase + x0);
            dst[13] = *(u16*)(rowBase + x1);
            dst[14] = *(u16*)(rowBase + x2);
            dst[15] = *(u16*)(rowBase + x3);
            x0 += 8;
            x1 = (x + 5) * 2;
            x2 = (x + 6) * 2;
            x3 = (x + 7) * 2;
            off = y * 32;
            rowBase = (u8*)src + off;
            dst[16] = *(u16*)(rowBase + x0);
            dst[17] = *(u16*)(rowBase + x1);
            dst[18] = *(u16*)(rowBase + x2);
            dst[19] = *(u16*)(rowBase + x3);
            off += 32;
            rowBase = (u8*)src + off;
            dst[20] = *(u16*)(rowBase + x0);
            dst[21] = *(u16*)(rowBase + x1);
            dst[22] = *(u16*)(rowBase + x2);
            dst[23] = *(u16*)(rowBase + x3);
            off += 32;
            rowBase = (u8*)src + off;
            dst[24] = *(u16*)(rowBase + x0);
            dst[25] = *(u16*)(rowBase + x1);
            dst[26] = *(u16*)(rowBase + x2);
            dst[27] = *(u16*)(rowBase + x3);
            off += 32;
            rowBase = (u8*)src + off;
            dst[28] = *(u16*)(rowBase + x0);
            dst[29] = *(u16*)(rowBase + x1);
            dst[30] = *(u16*)(rowBase + x2);
            dst[31] = *(u16*)(rowBase + x3);
            dst += 32;
            x0 += 8;
        }
        y += 4;
    }
    DCFlushRange((u8*)gGameTextBoxCornerTexture + 0x60, 0x200);

    tex = textureAlloc(0x14, 0x14, 5, 0, 0, 0, 0, 1, 1);
    gGameTextBoxEdgeTexture = tex;
    dst = (u16*)((u8*)tex + 0x60);
    y = 0;
    src = lbl_802CA100;
    for (i = 0; i < 5; i++)
    {
        x0 = 0;
        for (x = 0; x < 20; x += 4)
        {
            x1 = (x + 1) * 2;
            x2 = (x + 2) * 2;
            x3 = (x + 3) * 2;
            off = y * 40;
            rowBase = (u8*)src + off;
            dst[0] = *(u16*)(rowBase + x0);
            dst[1] = *(u16*)(rowBase + x1);
            dst[2] = *(u16*)(rowBase + x2);
            dst[3] = *(u16*)(rowBase + x3);
            off += 40;
            rowBase = (u8*)src + off;
            dst[4] = *(u16*)(rowBase + x0);
            dst[5] = *(u16*)(rowBase + x1);
            dst[6] = *(u16*)(rowBase + x2);
            dst[7] = *(u16*)(rowBase + x3);
            off += 40;
            rowBase = (u8*)src + off;
            dst[8] = *(u16*)(rowBase + x0);
            dst[9] = *(u16*)(rowBase + x1);
            dst[10] = *(u16*)(rowBase + x2);
            dst[11] = *(u16*)(rowBase + x3);
            off += 40;
            rowBase = (u8*)src + off;
            dst[12] = *(u16*)(rowBase + x0);
            dst[13] = *(u16*)(rowBase + x1);
            dst[14] = *(u16*)(rowBase + x2);
            dst[15] = *(u16*)(rowBase + x3);
            dst += 16;
            x0 += 8;
        }
        y += 4;
    }
    DCFlushRange((u8*)gGameTextBoxEdgeTexture + 0x60, 800);
}
#pragma optimization_level reset
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803DE730;
extern f32 gSubtitleNoTimeSentinel;
int GameText_CountPrintableChars(u8 * str);
int GameText_FindControlCodeArgs(u8* str, u32 target, int* out);
extern char** textMeasureFn_80016c9c(char* str, f32 width, f32 height, int* outCount, f32* outLineH);

#define SUBTITLE_LINE_COUNT 256

typedef struct SubtitleLineTable
{
    void* blocks[SUBTITLE_LINE_COUNT];
    char* lines[SUBTITLE_LINE_COUNT];
    f32 times[SUBTITLE_LINE_COUNT];
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
    SubtitleLineTable* s = (SubtitleLineTable*)gSubtitleLineTable;
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
    void** blk;

    total = 0;
    curTime = lbl_803DE730;
    if (gGameTextSequenceMode != 0)
    {
        savedCharset = gameTextGetCharset();
        gameTextSetCharset(1, 1);
    }
    t = (SubtitleTextEntry*)gameTextGet(gGameTextPendingTextId);
    win = gTextBoxes + 0x140;
    gSubtitleLineCount = 0;
    gSubtitleBlockCount = 0;
    for (i = 0; i < SUBTITLE_LINE_COUNT; i++)
    {
        s->times[i] = gSubtitleNoTimeSentinel;
    }
    for (i = 0; i < t->count; i++)
    {
        str = t->strs[i];
        n = GameText_FindControlCodeArgs((u8*)str, 0xE018, args);
        if (n != 0)
        {
            q = args[2] / 60;
            s->times[gSubtitleLineCount] = (f32)(args[1] + args[0] * 60 + q);
        }
        strLines = textMeasureFn_80016c9c(str, (f32)(u32) * (u16*)(win + 2), *(f32*)(win + 0xc), &count, NULL);
        if (strLines != NULL)
        {
            for (k = 0; k < count; k++)
            {
                s->lines[gSubtitleLineCount++] = strLines[k];
            }
            blk = (void**)((u8*)s + gSubtitleBlockCount * 4);
            if (*blk != NULL)
            {
                oldDelay = mmSetFreeDelay(0);
                blk = (void**)((u8*)s + gSubtitleBlockCount * 4);
                mm_free(*blk);
                mmSetFreeDelay(oldDelay);
            }
            blk = (void**)((u8*)s + gSubtitleBlockCount++ * 4);
            *blk = strLines;
        }
    }
    for (k = 0; k < gSubtitleLineCount; k++)
    {
        if (gSubtitleNoTimeSentinel != s->times[k])
        {
            curTime = s->times[k];
            total = GameText_CountPrintableChars((u8*)s->lines[k]);
        }
        else
        {
            found = 0;
            m = k;
            for (i = 0; i < SUBTITLE_LINE_COUNT; i++)
            {
                ftotal = total;
                if (m < 255)
                {
                    if (gSubtitleNoTimeSentinel != s->times[m + 1])
                    {
                        delta = s->times[m + 1] - curTime;
                        found = 1;
                    }
                    n = GameText_CountPrintableChars((u8*)s->lines[m]);
                    s->times[m] = n;
                    total += n;
                    if (found != 0)
                    {
                        for (q = m; q >= k; q--)
                        {
                            s->times[q] = s->times[q + 1] - delta * (s->times[q] / total);
                        }
                        break;
                    }
                    m++;
                }
            }
        }
    }
    gSubtitleLineIndex = 0;
    gSubtitleElapsedFrames = 0;
    gSubtitleActive = 2;
    if (gGameTextSequenceMode != 0)
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
            u16* q;

            n++;
            if (n > 0x10)
            {
                break;
            }
            *(u32*)tbl = ch;
            q = (u16*)(tbl + 4);
            n2 = getControlCharLen(ch);
            if (n2 > 4)
            {
                n2 = 4;
            }
            for (i = 0; i < n2; i++)
            {
                u32 hi = ((u8*)str)[off++];
                u32 lo = ((u8*)str)[off++];
                *q++ = (hi << 8) | lo;
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
