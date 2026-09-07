/*
 * dll_80136a40 - EN v1.0 retargeted system/debug leaves.
 *
 * A grab-bag of low-level support code linked into this DLL:
 *   - The fatal-error display thread (errorThreadFunc) plus its installer
 *     (errDisplayInstallHandlers / errDisplayHandler): OSSetErrorHandler hooks dump the
 *     exception type, DSISR/SRR0, the stack trace and a full GPR/SPR
 *     register window straight into the external framebuffers, flipping
 *     them forever in a hang loop.
 *   - The debug text subsystem: an in-memory record log (debugPrintf /
 *     debugPrintfxy / debugPrintSetColor write tagged records into
 *     debugLogBuffer) replayed by debugPrintDraw, which lays the log out
 *     twice (measure then draw) and rasterizes glyphs through
 *     debugPrintDrawGlyph (per-glyph texture select + textRenderChar) and
 *     debugPrintDrawRecord (record interpreter: color/tab/newline/position tags).
 */
#include "main/texture.h"
#include "track/intersect_api.h"
#include "main/frame_timing.h"
#include "main/pi_dolphin.h"
#include "main/lightmap_text_color_api.h"
#include "main/debug.h"
#include "dolphin/gx/GXMisc.h"
#include "dolphin/gx/GXFifo.h"
#include "dolphin/os/OSContext.h"
#include "dolphin/os/OSError.h"
#include "dolphin/os/OSInterrupt.h"
#include "dolphin/os/OSThread.h"
#include "dolphin/gx/GXStruct.h"
#include "dolphin/gx/GXTev.h"
#include "stdarg.h"
#include "dolphin/gx/GXCull.h"
#include "main/dll/dll_80136a40.h"
#include "dlls/objects/201_Baddie.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/printf.h"
#include "dolphin/os/OSCache.h"
#include "dolphin/vi.h"
#include "dolphin/vi/vifuncs.h"
#include "track/intersect_hud_api.h"

extern u8 debugLogBuffer[];

u16 gDebugTabWidth = 0x20;
u8* debugLogEnd = debugLogBuffer;
char sErrDSI[] = "DSI";
char sErrISI[] = "ISI";
char sErrFmtPC[] = "PC\t%x";
char sErrFmtSP[] = "SP\t%x";
char sErrFmtStackAddress[] = "\t%x";
char sErrFmtRegisterRange[] = "%d - %d";

/* debug font glyph-atlas texture asset (gDebugFontTex0) */
#define DEBUG_FONT_TEXTURE0_ID 0x25D

u16 gErrExceptionType;
OSContext* gErrContext;
u32 gErrDsisr;
u32 gErrDar;
u16* debugDrawFrameBuffer;
u16* debugFrameBuffer;
u8 enableDebugText;
void* gDebugFontTex0;
void* gDebugFontTex1;
void* gDebugFontTex2;
u16 debugPrintXpos;
u16 debugPrintYpos;
u16 gDebugRectStartX;
u16 gDebugRectStartY;
int gDebugFixedWidthMode;
int gDebugDrawPass;
u32 gDebugPrintOriginX;
u32 gDebugMarginRight;
u32 gDebugPrintOriginY;
u32 gDebugMarginBottom;
u32 gDebugCurrentFontSet;
u16 gDebugScreenWidth;
u16 gDebugScreenHeight;
u8 gDebugTextColorR;
u8 gDebugTextColorG;
u8 gDebugTextColorB;
u8 gDebugTextColorA;
f32 gDebugGlyphUScale;
f32 gDebugGlyphVScale;
int gDebugRecordCount;
u8 gDebugScaleBiasY;
u8 gDebugScaleBiasX;
f32 gDebugScaleY;
f32 gDebugScaleX;

u8 debugLogBuffer[0x1100];

OSThread gErrDisplayThread;

u8 gErrDisplayThreadStack[0x1000];

STATIC_ASSERT(sizeof(OSThread) == 0x310);

u8 gDebugGlyphMetricsTable[192] = {
    0x02, 0x04, 0x06, 0x08, 0x0A, 0x0F, 0x11, 0x15, 0x17, 0x1F, 0x21, 0x27, 0x29, 0x2B, 0x2D, 0x2F, 0x31, 0x33,
    0x35, 0x38, 0x3A, 0x3F, 0x41, 0x43, 0x45, 0x48, 0x4A, 0x4B, 0x4D, 0x50, 0x52, 0x56, 0x58, 0x5B, 0x5D, 0x62,
    0x64, 0x68, 0x6A, 0x6F, 0x71, 0x76, 0x78, 0x7D, 0x7F, 0x84, 0x86, 0x8B, 0x8D, 0x92, 0x94, 0x96, 0x98, 0x9A,
    0x9D, 0xA2, 0xA5, 0xA9, 0xAB, 0xB0, 0xB3, 0xB8, 0x00, 0x01, 0x00, 0x09, 0x0B, 0x11, 0x13, 0x19, 0x1B, 0x21,
    0x23, 0x29, 0x2B, 0x31, 0x33, 0x38, 0x3A, 0x41, 0x43, 0x49, 0x4B, 0x4C, 0x4E, 0x53, 0x55, 0x5B, 0x5D, 0x62,
    0x64, 0x6B, 0x6D, 0x73, 0x75, 0x7B, 0x7D, 0x83, 0x85, 0x8B, 0x8D, 0x93, 0x95, 0x9B, 0x9D, 0xA3, 0xA5, 0xAA,
    0xAC, 0xB2, 0xB4, 0xBC, 0xBE, 0xC4, 0xC6, 0xCC, 0xCE, 0xD3, 0xD5, 0xD7, 0xD9, 0xDC, 0xDE, 0xE0, 0xE2, 0xE7,
    0xE9, 0xEF, 0x00, 0x01, 0x03, 0x08, 0x09, 0x0F, 0x11, 0x16, 0x18, 0x1D, 0x1F, 0x24, 0x26, 0x28, 0x2A, 0x2F,
    0x31, 0x36, 0x38, 0x39, 0x3B, 0x3D, 0x3F, 0x43, 0x45, 0x46, 0x48, 0x4F, 0x51, 0x56, 0x58, 0x5D, 0x5F, 0x64,
    0x66, 0x6B, 0x6C, 0x70, 0x72, 0x77, 0x79, 0x7C, 0x7E, 0x82, 0x84, 0x89, 0x8B, 0x92, 0x94, 0x99, 0x9B, 0xA0,
    0xA2, 0xA6, 0xA8, 0xAB, 0xAD, 0xAE, 0xB0, 0xB3, 0xB5, 0xB9, 0xB5, 0xB9,
};
u8 gDebugFontGlyphs[580] = {
    12,  12,  12,  0,   12,  51,  51,  0,   0,   0,   38,  63,  38,  63,  38,  44,  14,  46,  44,  14,  51,  40,  29,
    10,  51,  29,  51,  45,  51,  62,  12,  12,  0,   0,   0,   14,  3,   3,   3,   14,  28,  48,  48,  48,  28,  0,
    12,  63,  29,  55,  0,   12,  63,  12,  0,   0,   0,   0,   13,  3,   0,   0,   63,  0,   0,   0,   0,   0,   0,
    12,  48,  56,  25,  11,  3,   30,  41,  45,  37,  30,  12,  15,  12,  12,  63,  31,  48,  30,  3,   63,  31,  48,
    62,  48,  31,  24,  28,  18,  63,  16,  63,  3,   31,  48,  31,  30,  3,   31,  51,  30,  63,  48,  24,  12,  12,
    30,  51,  30,  51,  30,  30,  51,  62,  48,  30,  0,   3,   0,   3,   0,   0,   12,  0,   12,  2,   56,  14,  3,
    14,  56,  0,   63,  0,   63,  0,   7,   28,  48,  28,  7,   30,  51,  24,  0,   12,  60,  129, 189, 161, 28,  30,
    51,  63,  51,  51,  31,  51,  31,  51,  31,  30,  51,  3,   51,  30,  31,  51,  51,  51,  31,  63,  3,   31,  3,
    63,  63,  3,   31,  3,   3,   62,  3,   59,  51,  30,  51,  51,  63,  51,  51,  63,  12,  12,  12,  63,  63,  48,
    51,  51,  46,  51,  51,  31,  51,  51,  3,   3,   3,   3,   63,  51,  63,  45,  33,  33,  51,  55,  63,  59,  51,
    30,  51,  51,  51,  30,  31,  51,  31,  3,   3,   46,  51,  51,  55,  62,  31,  51,  31,  51,  51,  62,  3,   30,
    48,  31,  63,  12,  12,  12,  12,  51,  51,  51,  51,  30,  51,  51,  51,  26,  12,  33,  33,  45,  63,  51,  51,
    51,  30,  51,  51,  51,  51,  30,  12,  12,  63,  24,  30,  6,   63,  63,  3,   3,   3,   63,  6,   12,  24,  48,
    63,  48,  48,  48,  63,  12,  51,  0,   0,   0,   0,   0,   0,   0,   63,  3,   12,  0,   0,   0,   0,   9,   101,
    114, 114, 111, 114, 84,  104, 114, 101, 97,  100, 70,  117, 110, 99,  32,  37,  120, 0,   69,  120, 99,  101, 112,
    116, 105, 111, 110, 58,  0,   0,   83,  121, 115, 116, 101, 109, 32,  114, 101, 115, 101, 116, 0,   0,   0,   0,
    77,  97,  99,  104, 105, 110, 101, 32,  99,  104, 101, 99,  107, 0,   0,   0,   65,  108, 105, 103, 110, 109, 101,
    110, 116, 0,   0,   0,   80,  101, 114, 102, 111, 114, 109, 97,  110, 99,  101, 32,  109, 111, 110, 105, 116, 111,
    114, 0,   83,  121, 115, 116, 101, 109, 32,  109, 97,  110, 97,  103, 101, 109, 101, 110, 116, 32,  105, 110, 116,
    101, 114, 114, 117, 112, 116, 0,   77,  101, 109, 111, 114, 121, 32,  80,  114, 111, 116, 101, 99,  116, 105, 111,
    110, 32,  69,  114,  114, 111, 114, 0,   85,  110, 107, 110, 111, 119, 110, 32,  101, 114, 114, 111, 114, 0,   0,
    0,   83,  116, 97,  99,  107, 32,  116, 114, 97,  99,  101, 0,   83,  116, 97,  99,  107, 32,  37,  120, 59,  32,
    100, 101, 112, 116, 104, 32,  37,  100, 0,   0,   9,   37,  48,  56,  120, 9,   37,  48,  56,  120, 0,   0,   71,
    101, 110, 101, 114, 97,  108, 32,  80,  117, 114, 112, 111, 115, 101, 32,  82,  101, 103, 105, 115, 116, 101, 114,
    115, 0,   0,   0,   9,   37,  48,  56,  120, 9,   37,  48,  56,  120, 9,   37,  48,  56,  120, 9,   37,  48,  56,
    120, 0,   0,   0,   0,
};
void errDisplayHandler(OSError error, OSContext* context, u32 dsisr, u32 dar);
typedef struct ErrStackFrame
{
    struct ErrStackFrame* previous;
    u32 returnAddress;
} ErrStackFrame;

static inline void errDisplayFillBackdrop(void)
{
    int xcb;
    int row;
    int x;
    int n;

    x = 0;
    xcb = x;
    do
    {
        row = 0;
        for (n = 0; n < 60; n++)
        {
            *(u16*)(xcb + (int)debugDrawFrameBuffer + row) = 0x1080;
            *(u16*)(xcb + (int)debugDrawFrameBuffer + row + 0x500) = 0x1080;
            *(u16*)(xcb + (int)debugDrawFrameBuffer + row + 0xA00) = 0x1080;
            *(u16*)(xcb + (int)debugDrawFrameBuffer + row + 0xF00) = 0x1080;
            *(u16*)(xcb + (int)debugDrawFrameBuffer + row + 0x1400) = 0x1080;
            *(u16*)(xcb + (int)debugDrawFrameBuffer + row + 0x1900) = 0x1080;
            *(u16*)(xcb + (int)debugDrawFrameBuffer + row + 0x1E00) = 0x1080;
            *(u16*)(xcb + (int)debugDrawFrameBuffer + row + 0x2300) = 0x1080;
            row += 0x2800;
        }
        xcb += 2;
        x++;
    } while (x < 0x280);
}

int debugPrintDrawGlyph(void* unused, int c);
int debugPrintDrawRecord(void* context, u8* p);
void debugTextDrawToFrameBuffer(int x, int y, u8* grid, int unused);

int debugPrintDrawGlyph(void* unused, int c)
{
    u8* tbl;
    u8 first;
    int px;
    int py;

    if (c <= 0x3f)
    {
        if (gDebugCurrentFontSet != 0)
        {
            if (gDebugDrawPass != 0)
            {
                selectTexture((Texture*)((char*)gDebugFontTex0), 0);
                gDebugGlyphUScale = 1.0f / (32.0f * (f32)((Texture*)gDebugFontTex0)->width);
                gDebugGlyphVScale =
                    1.0f / (32.0f * (f32)((Texture*)gDebugFontTex0)->height);
            }
            gDebugCurrentFontSet = 0;
        }
        c -= 0x21;
    }
    else if (c <= 0x5f)
    {
        if (gDebugCurrentFontSet != 1)
        {
            if (gDebugDrawPass != 0)
            {
                selectTexture((Texture*)((char*)gDebugFontTex1), 0);
                gDebugGlyphUScale = 1.0f / (32.0f * (f32)((Texture*)gDebugFontTex1)->width);
                gDebugGlyphVScale =
                    1.0f / (32.0f * (f32)((Texture*)gDebugFontTex1)->height);
            }
            gDebugCurrentFontSet = 1;
        }
        c -= 0x40;
    }
    else if (c <= 0x7f)
    {
        if (gDebugCurrentFontSet != 2)
        {
            if (gDebugDrawPass != 0)
            {
                selectTexture((Texture*)((char*)gDebugFontTex2), 0);
                gDebugGlyphUScale = 1.0f / (32.0f * (f32)((Texture*)gDebugFontTex2)->width);
                gDebugGlyphVScale =
                    1.0f / (32.0f * (f32)((Texture*)gDebugFontTex2)->height);
            }
            gDebugCurrentFontSet = 2;
        }
        c -= 0x60;
    }
    tbl = gDebugGlyphMetricsTable + gDebugCurrentFontSet * 0x40;
    first = tbl[c * 2];
    c = tbl[c * 2 + 1] - first + 1;
    if (gDebugDrawPass != 0)
    {
        px = (int)((f32)debugPrintXpos * (gDebugScaleX + gDebugScaleBiasX));
        py = (int)((f32)debugPrintYpos * (gDebugScaleY + gDebugScaleBiasY));
        gxSetDebugTextMode();
        textRenderChar(px << 2, py << 2,
                       (int)(4.0f * ((f32)c * (gDebugScaleX + gDebugScaleBiasX) + px)),
                       (int)(4.0f * (10.0f * (gDebugScaleY + gDebugScaleBiasY) + py)),
                       (f32)(first << 5) * gDebugGlyphUScale, 0.0f, gDebugGlyphUScale * (f32)((first + c) << 5),
                       320.0f * gDebugGlyphVScale);
    }
    return c;
}

static inline void debugPrintFillRect(int x1, int y1, int x2, int y2)
{
    GXColor color;

    color.r = gDebugTextColorR;
    color.g = gDebugTextColorG;
    color.b = gDebugTextColorB;
    color.a = gDebugTextColorA;
    hudDrawRect(x1, y1, x2, y2, color);
}

int debugPrintDrawRecord(void* context, u8* p)
{
    u8* start = p;
    u8 c;
    GXColor textColorSource;

    while ((c = *p++) != 0)
    {
        int w;
        f32 sc;
        int rm;
        w = 0;
        switch (c)
        {
        case 0x83:
            gDebugFixedWidthMode = 0;
            break;
        case 0x84:
            gDebugFixedWidthMode = 1;
            break;
        case 0x81:
        {
            u8 red;
            u8 green;
            u8 blue;
            u8 alpha;
            red = p[0];
            green = p[1];
            blue = p[2];
            alpha = p[3];
            p += 4;
            if (gDebugDrawPass != 0)
            {
                textColorSource.r = red;
                textColorSource.g = green;
                textColorSource.b = blue;
                textColorSource.a = alpha;
                GXSetTevColor(GX_TEVREG0, textColorSource);
            }
            break;
        }
        case 0x87:
        {
            u8 biasY;
            gDebugScaleBiasX = p[0];
            biasY = p[1];
            p += 2;
            gDebugScaleBiasY = biasY;
            break;
        }
        case 0x85:
        {
            u8 red;
            u8 green;
            u8 blue;
            u8 alpha;
            red = p[0];
            green = p[1];
            blue = p[2];
            alpha = p[3];
            p += 4;
            if (gDebugDrawPass == 0)
            {
                gDebugTextColorR = red;
                gDebugTextColorG = green;
                gDebugTextColorB = blue;
                gDebugTextColorA = alpha;
                setTextColor(context, red, green, blue, alpha);
            }
            break;
        }
        case 0x82:
        {
            u32 y1;
            u32 x;
            u32 y0;
            u32 x1;
            u32 x0;
            if (gDebugDrawPass == 0)
            {
                y1 = debugPrintYpos + 0xa;
                x = debugPrintXpos;
                x0 = gDebugRectStartX;
                y0 = gDebugRectStartY;
                if ((((x - x0) == 0) | ((y1 - y0) == 0)) == 0)
                {
                    if (x0 >= 2)
                    {
                        x0 -= 2;
                    }
                    x1 = x + 2;
                    x0 = x0 * (sc = gDebugScaleX + gDebugScaleBiasX);
                    x1 = x1 * sc;
                    y0 = y0 * (sc = gDebugScaleY + gDebugScaleBiasY);
                    y1 = y1 * sc;
                    debugPrintFillRect(x0, y0, x1, y1);
                }
            }
            debugPrintXpos = *p++;
            debugPrintXpos |= (*p++ << 8);
            debugPrintYpos = *p++;
            debugPrintYpos |= (*p++ << 8);
            gDebugRectStartX = debugPrintXpos;
            gDebugRectStartY = debugPrintYpos;
            break;
        }
        case 0x86:
            gDebugTabWidth = *p++;
            gDebugTabWidth |= (*p++ << 8);
            break;
        case 0x20:
            w = 6;
            break;
        case 0xa:
        {
            u32 y1;
            u32 x;
            u32 x0;
            u32 x1;
            u32 y0;
            if (gDebugDrawPass == 0)
            {
                y1 = debugPrintYpos + 0xa;
                x = debugPrintXpos;
                x0 = gDebugRectStartX;
                y0 = gDebugRectStartY;
                if ((((x - x0) == 0) | ((y1 - y0) == 0)) == 0)
                {
                    if (x0 >= 2)
                    {
                        x0 -= 2;
                    }
                    x1 = x + 2;
                    x0 = x0 * (sc = gDebugScaleX + gDebugScaleBiasX);
                    x1 *= sc;
                    y0 = y0 * (sc = gDebugScaleY + gDebugScaleBiasY);
                    y1 = y1 * sc;
                    debugPrintFillRect(x0, y0, x1, y1);
                }
            }
            debugPrintXpos = gDebugPrintOriginX;
            debugPrintYpos += 0xb;
            gDebugRectStartX = debugPrintXpos;
            gDebugRectStartY = debugPrintYpos;
            break;
        }
        case 9:
            rm = debugPrintXpos % gDebugTabWidth;
            if (rm == 0)
            {
                w = gDebugTabWidth;
            }
            else
            {
                w = gDebugTabWidth - rm;
            }
            break;
        default:
            w = debugPrintDrawGlyph(context, c);
            break;
        }
        if (gDebugFixedWidthMode != 0 && c >= 0x20 && c <= 0x7f)
        {
            w = 7;
        }
        debugPrintXpos += w;
        if (debugPrintXpos * (sc = gDebugScaleX + gDebugScaleBiasX) > gDebugScreenWidth - 0x10)
        {
            u32 y1;
            u32 x;
            u32 x0;
            u32 x1;
            u32 y0;
            if (gDebugDrawPass == 0)
            {
                y1 = debugPrintYpos + 0xa;
                x = debugPrintXpos;
                y0 = gDebugRectStartY;
                x0 = gDebugRectStartX;
                if ((((x - x0) == 0) | ((y1 - y0) == 0)) == 0)
                {
                    if (x0 >= 2)
                    {
                        x0 -= 2;
                    }
                    x1 = x + 2;
                    x1 = x1 * sc;
                    x0 = x0 * sc;
                    y0 = y0 * (sc = gDebugScaleY + gDebugScaleBiasY);
                    y1 = y1 * sc;
                    debugPrintFillRect(x0, y0, x1, y1);
                }
            }
            debugPrintXpos = gDebugPrintOriginX;
            debugPrintYpos += 0xb;
            gDebugRectStartX = debugPrintXpos;
            gDebugRectStartY = debugPrintYpos;
        }
    }
    return p - start;
}
void debugPrintSetColor(u8 r, u8 g, u8 b, u8 a)
{
    int n;
    n = gDebugRecordCount + 1;
    gDebugRecordCount = n;
    if (n > 0xfa)
        return;
    *debugLogEnd++ = 0x81;
    *debugLogEnd++ = r;
    *debugLogEnd++ = g;
    *debugLogEnd++ = b;
    *debugLogEnd++ = a;
    *debugLogEnd++ = 0;
}
void debugPrintReset(void)
{
    u32 xp;
    u32 yp;
    debugLogEnd = debugLogBuffer;
    xp = gDebugPrintOriginX & 0xffff;
    debugPrintXpos = xp;
    yp = gDebugPrintOriginY & 0xffff;
    debugPrintYpos = yp;
}

/* Lay out the debug log
 * twice (measure pass then draw pass), drawing the backing rect between
 * the passes when the log produced any extent. */
static inline void debugDrawLogRect(void)
{
    u32 y1;
    u32 x;
    u32 x1;
    u32 y0;
    u32 x0;
    f32 sc;
    GXColor col;

    y1 = debugPrintYpos + 0xa;
    x = debugPrintXpos;
    y0 = gDebugRectStartY;
    x0 = gDebugRectStartX;
    if ((((x - x0) == 0) | ((y1 - y0) == 0)) == 0)
    {
        if (x0 >= 2)
        {
            x0 -= 2;
        }
        x1 = x + 2;
        x0 *= (sc = gDebugScaleX + gDebugScaleBiasX);
        x1 *= sc;
        y0 = y0 * (sc = gDebugScaleY + gDebugScaleBiasY);
        y1 *= sc;
        col.r = gDebugTextColorR;
        col.g = gDebugTextColorG;
        col.b = gDebugTextColorB;
        col.a = gDebugTextColorA;
        hudDrawRect(x0, y0, x1, y1, col);
    }
}
void debugPrintDraw(void* context)
{
    u8* p;
    u16 ty, tx;
    int pass;
    u32 res;
    u32 sw;
    u32 sh;

    res = getScreenResolution();
    gDebugScreenHeight = res >> 0x10;
    gDebugScreenWidth = res;
    GXSetScissor(0, 0, (u16)res, gDebugScreenHeight);
    sw = gDebugScreenWidth;
    if (sw <= 0x140)
    {
        gDebugPrintOriginX = 0x10;
        gDebugMarginRight = sw - 0x10;
    }
    else
    {
        gDebugPrintOriginX = 0x20;
        gDebugMarginRight = sw - 0x20;
    }
    sh = gDebugScreenHeight;
    if (sh <= 0xf0)
    {
        gDebugPrintOriginY = 0x10;
        gDebugMarginBottom = sh - 0x10;
    }
    else
    {
        gDebugPrintOriginY = 0x20;
        gDebugMarginBottom = sh - 0x20;
    }
    gxSetDebugTextMode();
    p = debugLogBuffer;
    tx = gDebugPrintOriginX;
    debugPrintXpos = tx;
    ty = gDebugPrintOriginY;
    debugPrintYpos = ty;
    gDebugCurrentFontSet = 0xffffffff;
    pass = 0;
    gDebugFixedWidthMode = pass;
    gDebugRectStartX = tx;
    gDebugRectStartY = ty;
    for (; p != debugLogEnd;)
    {
        gDebugDrawPass = pass;
        p += debugPrintDrawRecord(context, p);
    }
    debugDrawLogRect();
    p = debugLogBuffer;
    debugPrintXpos = gDebugPrintOriginX;
    debugPrintYpos = gDebugPrintOriginY;
    gDebugCurrentFontSet = 0xffffffff;
    gDebugFixedWidthMode = 0;
    pass = 1;
    for (; p != debugLogEnd;)
    {
        gDebugDrawPass = pass;
        p += debugPrintDrawRecord(context, p);
    }
    debugLogEnd = debugLogBuffer;
    gDebugRecordCount = 0;
}

/* When b->_54 carries the spawn flag, build a particle descriptor on the stack from a's heading
 * and the delta to b's position, then emit it 20 times via the partfx
 * interface and clear the flag. */
void debugPrintf(char* fmt, ...)
{
    va_list args;

    if ((int)((u8*)debugLogEnd - debugLogBuffer) <= 0x1000)
    {
        va_start(args, fmt);
        vsprintf((char*)debugLogEnd, fmt, args);
    }
}

void logPrintf(char* fmt, ...)
{
}

void debugPrintInit(void)
{
    getScreenResolution();
    gDebugScaleX = 1.5f;
    gDebugScaleY = 1.5f;
    gDebugScaleBiasX = 0;
    gDebugScaleBiasY = 0;
    gDebugFontTex0 = textureLoadAsset(DEBUG_FONT_TEXTURE0_ID);
    gDebugFontTex1 = textureLoadAsset(1);
    gDebugFontTex2 = textureLoadAsset(2);
    debugLogEnd = debugLogBuffer;
}

/* Title-screen system init. Calls getScreenResolution, primes the two float counters, clears
 * two state bytes, acquires three sized buffers (605/1/2 bytes) and primes the
 * debugLogEnd cursor to the start of the 0x1100-byte arena. */
void debugTextDrawToFrameBuffer(int x, int y, u8* grid, int unused)
{
    int c1;
    int i;
    int a0;
    int a1;
    int a2;
    int a3;
    int c0;
    int bit;
    int row1;
    int row0;

    if (enableDebugText != 0)
    {
        i = 0;
        row1 = (y + 1) * 0x280;
        row0 = y * 0x280;
        for (; i < 5; i++)
        {
            bit = 0;
            c0 = x + row0;
            a0 = c0;
            a1 = c0 + 1;
            c1 = row1 + x;
            a2 = c1;
            a3 = c1 + 1;
            for (; bit < 8; bit++)
            {
                if (((1 << bit) & grid[i]) != 0)
                {
                    debugDrawFrameBuffer[a0] = 0xC080;
                    debugDrawFrameBuffer[a1] = 0xC080;
                    debugDrawFrameBuffer[a2] = 0xC080;
                    debugDrawFrameBuffer[a3] = 0xC080;
                }
                a0++;
                a1++;
                a2++;
                a3++;
            }
            DCStoreRange(debugDrawFrameBuffer + c0, 0x10);
            DCStoreRange(debugDrawFrameBuffer + c1, 0x10);
            row0 += 0x500;
            row1 += 0x500;
        }
    }
}

/* Format and draw debug text into both external framebuffers. */

void debugPrintfxy(int x, int y, char* fmt, ...) {
    int drawX;
    int drawY;
    u16* savedFrameBuffer;
    int lineStartX = x;
    u8* endCursor[1];
    u8* character[1];
    u8* glyphRows;
    va_list args;
    char text[256];

    if (enableDebugText != 0) {
        drawX = lineStartX;
        drawY = y;
        va_start(args, fmt);
        vsprintf(text, fmt, args);
        savedFrameBuffer = debugDrawFrameBuffer;
        endCursor[0] = (u8*)&text[-1];
        character[0] = (u8*)text - 1;
        while (character[0]++, *++endCursor[0] != 0) {
            switch (*character[0]) {
            case 0xa:
                drawY += 0xc;
                drawX = lineStartX;
                break;
            case 9:
                drawX += 0x40 - (drawX & 0x3f);
                break;
            case 0x20:
                drawX += 8;
                break;
            default:
                if (*character[0] >= 0x61 && *character[0] <= 0x7a) {
                    *character[0] -= 0x20;
                }
                if (*character[0] >= 0x21 && *character[0] <= 0x5a) {
                    debugDrawFrameBuffer = externalFrameBuffer0;
                    debugTextDrawToFrameBuffer(drawX, drawY, glyphRows = gDebugFontGlyphs + (*character[0] - 0x21) * 5,
                                               -1);
                    debugDrawFrameBuffer = externalFrameBuffer1;
                    debugTextDrawToFrameBuffer(drawX, drawY, glyphRows, -1);
                    drawX += 0xf;
                }
                break;
            }
        }
        debugDrawFrameBuffer = savedFrameBuffer;
    }
}

void errDisplayInstallHandlers(void)
{
    OSSetErrorHandler(OS_ERROR_SYSTEM_RESET, (OSErrorHandler)errDisplayHandler);
    OSSetErrorHandler(OS_ERROR_MACHINE_CHECK, (OSErrorHandler)errDisplayHandler);
    OSSetErrorHandler(OS_ERROR_DSI, (OSErrorHandler)errDisplayHandler);
    OSSetErrorHandler(OS_ERROR_PERFORMACE_MONITOR, (OSErrorHandler)errDisplayHandler);
    OSSetErrorHandler(OS_ERROR_SYSTEM_INTERRUPT, (OSErrorHandler)errDisplayHandler);
    OSSetErrorHandler(OS_ERROR_PROTECTION, (OSErrorHandler)errDisplayHandler);
    OSSetErrorHandler(OS_ERROR_ISI, (OSErrorHandler)errDisplayHandler);
    OSSetErrorHandler(OS_ERROR_ALIGNMENT, (OSErrorHandler)errDisplayHandler);
    OSCreateThread(&gErrDisplayThread, errorThreadFunc, 0, gErrDisplayThreadStack + 4096, 4096, 0,
                   OS_THREAD_ATTR_DETACH);
}

void reportAllocFail(int region0SizeKb, int region0FreeKb, int region1SizeKb, int region1FreeKb, int region2SizeKb,
                     int region2FreeKb, int memoryState, int tickCount, int requestedSize, int largestFree0,
                     int largestFree1)
{
}
void* errorThreadFunc(void* unused)
{
    char* strs = (char*)gDebugFontGlyphs;
    void* (*self[1])(void*);
    int y;
    u32* sp;
    int depth;
    int hold;
    int h, h2;
    ErrStackFrame* frame;
    int stackLines;
    int n;
    u8 lvl;
    u32 r, rr;
    u32* rp;

    sp = NULL;
    depth = 0;
    hold = 0xb4;
    if (enableDebugText != 0)
    {
        debugDrawFrameBuffer = externalFrameBuffer0;
        debugFrameBuffer = externalFrameBuffer1;
        lvl = OSDisableInterrupts();
        VISetPreRetraceCallback(NULL);
        VISetPostRetraceCallback(NULL);
        GXSetBreakPtCallback(NULL);
        __GXAbortWaitPECopyDone();
        OSRestoreInterrupts(lvl);
        self[0] = errorThreadFunc;
        while (1)
        {
            if (enableDebugText != 0)
            {
                errDisplayFillBackdrop();
            }
            debugPrintfxy(0x10, 0x15, strs + 0x140, self[0]);
            debugPrintfxy(0x10, 0x2a, strs + 0x154);
            switch (gErrExceptionType)
            {
            case 0:
                debugPrintfxy(0xa0, 0x2a, strs + 0x160);
                break;
            case 1:
                debugPrintfxy(0xa0, 0x2a, strs + 0x170);
                break;
            case 2:
                debugPrintfxy(0xa0, 0x2a, sErrDSI);
                break;
            case 3:
                debugPrintfxy(0xa0, 0x2a, sErrISI);
                break;
            case 5:
                debugPrintfxy(0xa0, 0x2a, strs + 0x180);
                break;
            case 0xb:
                debugPrintfxy(0x9b, 0x2a, strs + 0x18c);
                break;
            case 0xd:
                debugPrintfxy(0xa0, 0x2a, strs + 0x1a0);
                break;
            case 0xf:
                debugPrintfxy(0xa0, 0x2a, strs + 0x1bc);
                break;
            default:
                debugPrintfxy(0x9b, 0x2a, strs + 0x1d4);
                break;
            }
            if (enableDebugText != 0)
            {
                h = 0x9100;
                h2 = 0x8e80;
                for (n = 0x280; n != 0; n--)
                {
                    debugDrawFrameBuffer[h] = 0xc080;
                    debugDrawFrameBuffer[h2] = 0xc080;
                    h++;
                    h2++;
                }
            }
            debugPrintfxy(0x10, 0x3f, sErrFmtPC, gErrContext->srr0);
            debugPrintfxy(0x10, 0x4b, sErrFmtSP, gErrContext->gpr[1]);
            if (enableDebugText != 0)
            {
                h = 0xe380;
                h2 = 0xe100;
                for (n = 0xf0; n != 0; n--)
                {
                    debugDrawFrameBuffer[h] = 0xc080;
                    debugDrawFrameBuffer[h2] = 0xc080;
                    h++;
                    h2++;
                }
            }
            debugPrintfxy(0x10, 0x60, strs + 0x1e4);
            y = 0x6c;
            frame = ((ErrStackFrame*)gErrContext->gpr[1])->previous;
            stackLines = 0;
            while (frame != (ErrStackFrame*)-1 && stackLines++ != 8)
            {
                debugPrintfxy(0x10, y, sErrFmtStackAddress, frame->returnAddress);
                y += 0xc;
                frame = frame->previous;
            }
            y += (8 - stackLines) * 0xc;
            if (enableDebugText != 0)
            {
                int lineRows;
                int lineOffset;
                int previousLineOffset;

                lineRows = y + 0x4c;
                lineOffset = lineRows * 0x280;
                previousLineOffset = (y + 0x4b) * 0x280;
                for (n = 0x280; n != 0; n--)
                {
                    debugDrawFrameBuffer[lineOffset] = 0xc080;
                    if (lineRows > 0)
                    {
                        debugDrawFrameBuffer[previousLineOffset] = 0xc080;
                    }
                    lineOffset++;
                    previousLineOffset++;
                }
            }
            if (enableDebugText != 0)
            {
                int b = 0x12700;
                u16 rowColor = 0xc080;
                int rows = y + 0x4c;
                while (rows > 0x3b)
                {
                    *(u16*)((char*)debugDrawFrameBuffer + b + 0x1e0) = rowColor;
                    b += 0x500;
                    rows--;
                }
            }
            y += 0x51;
            if (sp == NULL)
            {
                sp = (u32*)gErrContext->gpr[1];
                depth = 0;
            }
            else if (hold-- == 0)
            {
                hold = 0xb4;
                sp = (u32*)*sp;
                depth++;
                if (sp == (u32*)0xffffffff)
                {
                    sp = (u32*)gErrContext->gpr[1];
                    depth = 0;
                }
            }
            debugPrintfxy(0x100, 0x3f, strs + 0x1f0, sp, depth);
            debugPrintfxy(0x100, 0x4b, strs + 0x204, sp[-1], sp[-2]);
            debugPrintfxy(0x100, 0x57, strs + 0x204, sp[-3], sp[-4]);
            debugPrintfxy(0x100, 0x63, strs + 0x204, sp[-5], sp[-6]);
            debugPrintfxy(0x100, 0x6f, strs + 0x204, sp[-7], sp[-8]);
            debugPrintfxy(0x100, 0x7b, strs + 0x204, sp[-9], sp[-10]);
            debugPrintfxy(0x100, 0x87, strs + 0x204, sp[-0xb], sp[-0xc]);
            debugPrintfxy(0x100, 0x93, strs + 0x204, sp[-0xd], sp[-0xe]);
            debugPrintfxy(0x100, 0x9f, strs + 0x204, sp[-0xf], sp[-0x10]);
            debugPrintfxy(0x100, 0xab, strs + 0x204, sp[-0x11], sp[-0x12]);
            debugPrintfxy(0x100, 0xb7, strs + 0x204, sp[-0x13], sp[-0x14]);
            debugPrintfxy(0x100, 0xc3, strs + 0x204, sp[-0x15], sp[-0x16]);
            debugPrintfxy(0x100, 0xcf, strs + 0x204, sp[-0x17], sp[-0x18]);
            debugPrintfxy(0x100, 0xdb, strs + 0x204, sp[-0x19], sp[-0x1a]);
            debugPrintfxy(0x100, 0xe7, strs + 0x204, sp[-0x1b], sp[-0x1c]);
            debugPrintfxy(0x100, 0xf3, strs + 0x204, sp[-0x1d], sp[-0x1e]);
            debugPrintfxy(0x100, 0xff, strs + 0x204, sp[-0x1f], sp[-0x20]);
            debugPrintfxy(0x10, y, strs + 0x210);
            for (r = 0; (u8)r < 0x20; r += 8)
            {
                rr = r & 0xff;
                debugPrintfxy(0xc, y + 0xc, sErrFmtRegisterRange, rr, rr + 7);
                rp = &gErrContext->gpr[rr];
                debugPrintfxy(0x10, y + 0x18, strs + 0x22c, gErrContext->gpr[(u8)r], rp[1],
                              rp[2], rp[3]);
                y += 0x24;
                rp = &gErrContext->gpr[rr];
                debugPrintfxy(0x10, y, strs + 0x22c, rp[4], rp[5], rp[6], rp[7]);
            }
            if (enableDebugText != 0)
            {
                DCStoreRange(debugDrawFrameBuffer, 0x96000);
                debugDrawFrameBuffer =
                    (debugDrawFrameBuffer == externalFrameBuffer0) ? externalFrameBuffer1 : externalFrameBuffer0;
                debugFrameBuffer =
                    (debugFrameBuffer == externalFrameBuffer0) ? externalFrameBuffer1 : externalFrameBuffer0;
                VISetNextFrameBuffer(debugFrameBuffer);
                VIFlush();
                VIWaitForRetrace();
            }
        }
    }
    while (1)
    {
        if (enableDebugText != 0)
        {
            errDisplayFillBackdrop();
        }
        if (enableDebugText != 0)
        {
            DCStoreRange(debugDrawFrameBuffer, 0x96000);
            debugDrawFrameBuffer =
                (debugDrawFrameBuffer == externalFrameBuffer0) ? externalFrameBuffer1 : externalFrameBuffer0;
            debugFrameBuffer = (debugFrameBuffer == externalFrameBuffer0) ? externalFrameBuffer1 : externalFrameBuffer0;
            VISetNextFrameBuffer(debugFrameBuffer);
            VIFlush();
            VIWaitForRetrace();
        }
    }
}

/* Stash 4 args to four globals and resume
 * the thread at &gErrDisplayThread. */
void errDisplayHandler(OSError error, OSContext* context, u32 dsisr, u32 dar)
{
    gErrExceptionType = error;
    gErrContext = context;
    gErrDsisr = dsisr;
    gErrDar = dar;
    OSResumeThread(&gErrDisplayThread);
}
