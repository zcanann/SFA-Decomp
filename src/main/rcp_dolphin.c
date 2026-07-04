#include "main/asset_load.h"
#include "main/effect_interfaces.h"
#include "main/texture.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/newclouds.h"
#include "main/rcp_dolphin.h"
#include "main/screen_transition.h"
#include "main/sky_interface.h"
#include "main/mm.h"
#include "dolphin/os/OSCache.h"
#include "dolphin/gx/GXDispList.h"

#define GX_CULL_NONE 0
#define GX_CULL_FRONT 1
#define GX_CULL_BACK 2
#define GX_BM_NONE 0
#define GX_BL_ZERO 0
#define GX_BL_ONE 1
#define GX_LO_NOOP 5
#define GX_AOP_AND 0
#define GX_ALWAYS 7
#define GX_EQUAL 2
#define GX_MT_XF_FLUSH 1
#define GX_TF_RGBA8 6
#define GX_FALSE 0
#define GX_TF_I4 0
#define GX_TEXMAP1 1
#define GX_TEV_SWAP1 1
#define GX_CH_ALPHA 3
#define GX_VA_POS 9
#define GX_VA_NRM 10
#define GX_DIRECT 1
#define GX_TRIANGLESTRIP 0x98
#define GX_VTXFMT4 4
#define GX_COLOR0 0
#define GX_COLOR0A0 4
#define GX_COLOR1A1 5
#define GX_TEVREG0 1
#define GX_TEXCOORD_NULL 0xff
#define GX_TEXMAP_NULL 0xff
#define GX_COLOR_NULL 0xff
#define GX_TEV_SWAP0 0
#define GX_TEV_ADD 0
#define GX_TB_ZERO 0
#define GX_CS_SCALE_1 0
#define GX_TRUE 1
#define GX_TEVPREV 0
#define GX_CC_CPREV 0
#define GX_CC_A0 3
#define GX_CC_RASC 0xa
#define GX_CC_KONST 0xe
#define GX_CC_ZERO 0xf
#define GX_CA_APREV 0
#define GX_CA_RASA 5
#define GX_CA_KONST 6
#define GX_CA_ZERO 7
extern u32 FUN_800033a8();
extern u32 FUN_8001763c();
extern int randomGetRange(int lo, int hi);
extern u32 FUN_80017830();
extern int FUN_80042838();
extern u32 FUN_80047d88();
extern u32 FUN_8004812c();
extern void gxSetPeControl_ZCompLoc_(u32 zCompLoc);
extern void gxSetZMode_(u32 compareEnable, int compareFunc, u32 updateEnable);
extern void* FUN_800e87a8();
extern u32 FUN_80258674();
extern u32 FUN_80258944();
extern int FUN_8025a850();
extern u32 FUN_8025aa74();
extern u32 FUN_8025ace8();
extern u32 FUN_8025aeac();
extern u32 FUN_8025b054();
extern u32 FUN_8025be54();
extern u32 FUN_8025be80();
extern u32 FUN_8025c1a4();
extern u32 FUN_8025c224();
extern u32 FUN_8025c2a8();
extern u32 FUN_8025c368();
extern u32 FUN_8025c510();
extern u32 GXSetBlendMode();
extern u32 FUN_8025c5f0();
extern u32 FUN_8025c65c();
extern u32 FUN_8025c6b4();
extern u32 FUN_8025c828();
extern u32 FUN_8025ca04();
extern u32 FUN_8025d8c4();
extern u64 FUN_80286834();
extern u64 FUN_8028683c();
extern u32 FUN_80286880();
extern u32 FUN_80286888();
extern u32 DAT_8030dac4;
extern u32 DAT_8030dac8;
extern u32 DAT_8030dacc;
extern u32 DAT_80378600;
extern u32 lbl_803DC070;
extern u32 gTitleScreenCursorX;
extern u32 gTitleScreenCursorY;
extern u32 DAT_803dd9c9;
extern u32 DAT_803dd9ca;
extern u32 DAT_803dd9cb;
extern u32 DAT_803dd9cc;
extern u32 DAT_803dd9d0;
extern u32 gTitleScreenMainTex;
extern u32 gDebugScaleX;
extern u32 gDebugScaleY;
extern u32 gDebugScaleBiasX;
extern u32 gDebugRecordCount;
extern u32 gDebugGlyphVScale;
extern u32 DAT_803dd9e9;
extern u32 DAT_803dd9ea;
extern u32 DAT_803dd9eb;
extern u32 gDebugGlyphUScale;
extern u32 gDebugTextColorA;
extern u32 gDebugScreenHeight;
extern u32 gDebugCurrentFontSet;
extern u32 gDebugMarginBottom;
extern u32 gDebugPrintOriginX;
extern u32 gDebugMarginRight;
extern u32 gDebugPrintOriginY;
extern u32 gDebugDrawPass;
extern u32 gDebugFixedWidthMode;
extern u32 gErrContext;
extern int* DAT_803dda44;
extern u32 DAT_803dda74;
extern u32 DAT_803dda75;
extern u32 DAT_803dda7b;
extern u32 gTumbleweedBushHitCooldownState;
extern f32 lbl_803DDAC8;
extern f32 lbl_803DDACC;
extern f32 lbl_803DDAD0;
extern f32 lbl_803DF818;
extern f32 lbl_803DF81C;

void FUN_80051868(int tex, float* mtx, int blendMode)
{
    FUN_8025be80(gDebugFixedWidthMode);
    FUN_8025c828(gDebugFixedWidthMode, gDebugPrintOriginY, gDebugDrawPass, 4);
    FUN_8025c65c(gDebugFixedWidthMode, 0, 0);
    if (mtx == (float*)0x0)
    {
        FUN_80258674(gDebugPrintOriginY, 1, gDebugCurrentFontSet, 0x3c, 0, 0x7d);
    }
    else
    {
        FUN_8025d8c4(mtx, gDebugPrintOriginX, 0);
        FUN_80258674(gDebugPrintOriginY, 1, gDebugCurrentFontSet, 0x3c, 0, gDebugPrintOriginX);
        gDebugPrintOriginX = gDebugPrintOriginX + 3;
    }
    if (blendMode == 0)
    {
        FUN_8025c1a4(gDebugFixedWidthMode, 0xf, 8, 10, 0xf);
    }
    else if (blendMode == 8)
    {
        FUN_8025c1a4(gDebugFixedWidthMode, 0xf, 8, 10, 6);
    }
    else if (blendMode == 4)
    {
        FUN_8025c1a4(gDebugFixedWidthMode, 8, 0xf, 0xf, 0);
    }
    else if (blendMode == 6)
    {
        FUN_8025c1a4(gDebugFixedWidthMode, 0xf, 8, 0, 0xf);
    }
    else if (blendMode == 9)
    {
        FUN_8025c1a4(gDebugFixedWidthMode, 8, 0, 1, 0xf);
    }
    else
    {
        FUN_8025c1a4(gDebugFixedWidthMode, 8, 0, 1, 0xf);
    }
    if (DAT_803dd9eb == '\0')
    {
        FUN_8025c224(gDebugFixedWidthMode, 7, 4, 5, 7);
        DAT_803dd9eb = '\x01';
    }
    else
    {
        FUN_8025c224(gDebugFixedWidthMode, 7, 4, 0, 7);
    }
    FUN_8025c2a8(gDebugFixedWidthMode, 0, 0, 0, 1, 0);
    FUN_8025c368(gDebugFixedWidthMode, 0, 0, 0, 1, 0);
    gTitleScreenCursorX = 1;
    if (tex != 0)
    {
        if (*(char*)(tex + 0x48) == '\0')
        {
            FUN_8025b054((u32*)(tex + 0x20), gDebugDrawPass);
        }
        else
        {
            FUN_8025aeac((u32*)(tex + 0x20), *(u32**)(tex + 0x40), gDebugDrawPass);
        }
    }
    gDebugCurrentFontSet = gDebugCurrentFontSet + 1;
    gDebugPrintOriginY = gDebugPrintOriginY + 1;
    gDebugFixedWidthMode = gDebugFixedWidthMode + 1;
    gDebugDrawPass = gDebugDrawPass + 1;
    DAT_803dd9ea = DAT_803dd9ea + '\x01';
    DAT_803dd9e9 = DAT_803dd9e9 + '\x01';
    return;
}

void FUN_80051fc4(u32 unused1, u32 unused2, int blendMode, char* blendSrc, u32 colorIndex,
                  u32 customBlendFlag)
{
    int colorOff;
    int tex;
    u64 mtxPair;
    u32 colorWord;
    int blendModeId;
    int blendArgs[8];

    mtxPair = FUN_8028683c();
    tex = (int)((u64)mtxPair >> 0x20);
    FUN_8025be80(gDebugFixedWidthMode);
    FUN_8025c828(gDebugFixedWidthMode, gDebugPrintOriginY, gDebugDrawPass, 0xff);
    FUN_8025c65c(gDebugFixedWidthMode, 0, 1);
    colorOff = (colorIndex & 0xff) * 0xc; /* DAT_8030dac4/c8/cc: 3 u32 columns of a 0xc-stride color table */
    FUN_8025c6b4(1, *(u32*)(&DAT_8030dac4 + colorOff), *(int*)(&DAT_8030dac8 + colorOff),
                 *(u32*)(&DAT_8030dacc + colorOff), 3);
    if ((float*)mtxPair == (float*)0x0)
    {
        FUN_80258674(gDebugPrintOriginY, 1, gDebugCurrentFontSet, 0x3c, 0, 0x7d);
    }
    else
    {
        FUN_8025d8c4((float*)mtxPair, gDebugPrintOriginX, 0);
        FUN_80258674(gDebugPrintOriginY, 1, gDebugCurrentFontSet, 0x3c, 0, gDebugPrintOriginX);
        gDebugPrintOriginX = gDebugPrintOriginX + 3;
    }
    if ((customBlendFlag & 0xff) == 0)
    {
        colorWord = *(u32*)blendSrc;
        FUN_8025c510(gDebugScreenHeight, (u8*)&colorWord);
        GXSetBlendMode(gDebugFixedWidthMode, gDebugTextColorA);
        if (((Texture*)tex)->imageOffset == 0)
        {
            FUN_8025c5f0(gDebugFixedWidthMode, gDebugGlyphUScale);
        }
        else
        {
            FUN_8025c5f0(gDebugFixedWidthMode + 1, gDebugGlyphUScale);
        }
        gDebugScreenHeight = gDebugScreenHeight + 1;
        gDebugTextColorA = gDebugTextColorA + 1;
        gDebugGlyphUScale = gDebugGlyphUScale + 1;
    }
    else
    {
        FUN_80047d88(blendSrc, '\x01', '\x01', blendArgs, &blendModeId);
        GXSetBlendMode(gDebugFixedWidthMode, blendArgs[0]);
        if (((Texture*)tex)->imageOffset == 0)
        {
            FUN_8025c5f0(gDebugFixedWidthMode, blendModeId);
        }
        else
        {
            FUN_8025c5f0(gDebugFixedWidthMode + 1, blendModeId);
        }
    }
    if (blendMode == 0)
    {
        FUN_8025c1a4(gDebugFixedWidthMode, 0xf, 8, 0xe, 0xf);
    }
    else if (blendMode == 8)
    {
        FUN_8025c1a4(gDebugFixedWidthMode, 0xf, 8, 4, 6);
    }
    else
    {
        FUN_8025c1a4(gDebugFixedWidthMode, 8, 0, 1, 0xf);
    }
    if (DAT_803dd9eb == '\0')
    {
        FUN_8025c224(gDebugFixedWidthMode, 7, 4, 6, 7);
    }
    else
    {
        FUN_8025c224(gDebugFixedWidthMode, 7, 4, 0, 7);
    }
    FUN_8025c2a8(gDebugFixedWidthMode, 0, 0, 0, 1, 0);
    FUN_8025c368(gDebugFixedWidthMode, 0, 0, 0, 1, 0);
    gTitleScreenCursorX = 1;
    if (tex != 0)
    {
        if (*(char*)&((Texture*)tex)->preloaded == '\0')
        {
            FUN_8025b054((u32*)(tex + 0x20), gDebugDrawPass);
        }
        else
        {
            FUN_8025aeac((u32*)(tex + 0x20), *(u32**)(tex + 0x40), gDebugDrawPass);
        }
        if (((Texture*)tex)->imageOffset != 0)
        {
            FUN_800530b8(tex, (u32*)&DAT_80378600);
            FUN_8025b054((u32*)&DAT_80378600, 1);
        }
    }
    if (((Texture*)tex)->imageOffset != 0)
    {
        DAT_803dd9ea = DAT_803dd9ea + '\x01';
        gDebugFixedWidthMode = gDebugFixedWidthMode + 1;
        gDebugDrawPass = gDebugDrawPass + 1;
        FUN_8025be80(gDebugFixedWidthMode);
        FUN_8025c828(gDebugFixedWidthMode, gDebugPrintOriginY, gDebugDrawPass, 0xff);
        FUN_8025c65c(gDebugFixedWidthMode, 0, 0);
        FUN_8025c1a4(gDebugFixedWidthMode, 0xf, 0xf, 0xf, 0);
        FUN_8025c224(gDebugFixedWidthMode, 7, 4, 6, 7);
        FUN_8025c2a8(gDebugFixedWidthMode, 0, 0, 0, 1, 0);
        FUN_8025c368(gDebugFixedWidthMode, 0, 0, 0, 1, 0);
    }
    DAT_803dd9eb = 1;
    gDebugCurrentFontSet = gDebugCurrentFontSet + 1;
    gDebugPrintOriginY = gDebugPrintOriginY + 1;
    gDebugFixedWidthMode = gDebugFixedWidthMode + 1;
    gDebugDrawPass = gDebugDrawPass + 1;
    DAT_803dd9ea = DAT_803dd9ea + '\x01';
    DAT_803dd9e9 = DAT_803dd9e9 + '\x01';
    FUN_80286888();
    return;
}

void FUN_80052778(char* blendSrc)
{
    int blendModeId;
    int blendArgs[4];

    FUN_8025be80(gDebugFixedWidthMode);
    FUN_80047d88(blendSrc, '\x01', '\x01', blendArgs, &blendModeId);
    FUN_8025c5f0(gDebugFixedWidthMode, blendModeId);
    GXSetBlendMode(gDebugFixedWidthMode, blendArgs[0]);
    FUN_8025c828(gDebugFixedWidthMode, 0xff, 0xff, 4);
    FUN_8025c65c(gDebugFixedWidthMode, 0, 0);
    if ((DAT_803dd9ea == '\0') || (gTitleScreenCursorX == '\0'))
    {
        FUN_8025c1a4(gDebugFixedWidthMode, 0xf, 0xf, 0xf, 0xe);
        FUN_8025c224(gDebugFixedWidthMode, 7, 7, 7, 6);
    }
    else
    {
        FUN_8025c1a4(gDebugFixedWidthMode, 0xf, 0, 0xe, 0xf);
        FUN_8025c224(gDebugFixedWidthMode, 7, 0, 6, 7);
    }
    FUN_8025c2a8(gDebugFixedWidthMode, 0, 0, 0, 1, 0);
    FUN_8025c368(gDebugFixedWidthMode, 0, 0, 0, 1, 0);
    gTitleScreenCursorX = 1;
    gDebugFixedWidthMode = gDebugFixedWidthMode + 1;
    DAT_803dd9ea = DAT_803dd9ea + '\x01';
    return;
}

void FUN_800528d0(void)
{
    FUN_80258944((u32)DAT_803dd9e9);
    FUN_8025ca04((u32)DAT_803dd9ea);
    FUN_8025be54((u32)gDebugGlyphVScale);
    return;
}

void FUN_80052904(void)
{
    gDebugScaleX = 0x1e;
    gDebugMarginRight = 0x1e;
    gTitleScreenMainTex = 0x40;
    gDebugPrintOriginX = 0x40;
    gDebugRecordCount = 0;
    gDebugFixedWidthMode = 0;
    gDebugScaleY = 0;
    gDebugPrintOriginY = 0;
    gDebugScaleBiasX = 0;
    gDebugDrawPass = 0;
    DAT_803dd9d0 = 0;
    gDebugMarginBottom = 0;
    DAT_803dd9cc = 4;
    gDebugCurrentFontSet = 4;
    gDebugScreenHeight = 0;
    gDebugTextColorA = 0xc;
    gDebugGlyphUScale = 0x1c;
    DAT_803dd9eb = 0;
    DAT_803dd9cb = 0;
    DAT_803dd9ea = 0;
    DAT_803dd9ca = 0;
    DAT_803dd9e9 = 0;
    DAT_803dd9c9 = 0;
    gDebugGlyphVScale = 0;
    gTitleScreenCursorY = 0;
    gTitleScreenCursorX = 0;
    return;
}

u32 FUN_80053078(u32 texId)
{
    int idx;

    if ((texId & 0x80000000) != 0)
    {
        return texId;
    }
    idx = texId - 1;
    if ((-1 < idx) && (idx < gErrContext))
    {
        return *(u32*)(DAT_803dda44 + idx * 0x10 + 4);
    }
    return 0;
}

void FUN_800530b4(void)
{
}

void FUN_800530b8(int tex, u32* gxTexObj)
{
    bool hasMip;
    double scalar;

    hasMip = 0 < (int)((u32) * (u8*)(tex + 0x1d) - (u32) * (u8*)(tex + 0x1c));
    FUN_8025aa74(gxTexObj, tex + *(int*)(tex + 0x50) + 0x60, (u32) * (u16*)(tex + 10),
                 (u32) * (u16*)(tex + 0xc), 0, (u32) * (u8*)(tex + 0x17),
                 (u32) * (u8*)(tex + 0x18), hasMip);
    if (hasMip)
    {
        FUN_8025ace8((double)(float)((double)(u32) * (u8*)(tex + 0x1c)),
                     (double)(float)((double)(int)(*(u8*)(tex + 0x1d))), (double)lbl_803DF818, gxTexObj,
                     (u32) * (u8*)(tex + 0x19), (u32) * (u8*)(tex + 0x1a), 0, '\0', 0);
    }
    else
    {
        scalar = (double)lbl_803DF81C;
        FUN_8025ace8(scalar, scalar, scalar, gxTexObj, (u32) * (u8*)(tex + 0x19),
                     (u32) * (u8*)(tex + 0x1a), 0, '\0', 0);
    }
    return;
}

int FUN_8005337c(int key)
{
    int* entry;
    int idx;
    int remaining;

    idx = 0;
    entry = DAT_803dda44;
    remaining = gErrContext;
    if (0 < gErrContext)
    {
        do
        {
            if (key == *entry)
            {
                return DAT_803dda44[idx * 4 + 1];
            }
            entry = entry + 4;
            idx = idx + 1;
            remaining = remaining + -1;
        }
        while (remaining != 0);
    }
    return 0;
}

void FUN_800533cc(int animDef, u32* flagsPtr, int* framePtr)
{
    u32 flags;
    int frame;
    u32 reverse;
    int frame2;

    flags = *flagsPtr;
    reverse = flags & 0x80000;
    if ((flags & 0x20000) == 0)
    {
        if ((flags & 0x40000) == 0)
        {
            if (reverse == 0)
            {
                *framePtr = *framePtr + (u32) * (u16*)(animDef + 0x14) * (u32)lbl_803DC070;
                while ((int)(u32) * (u16*)(animDef + 0x10) <= *framePtr)
                {
                    *framePtr = *framePtr - (u32) * (u16*)(animDef + 0x10);
                }
            }
            else
            {
                *framePtr = *framePtr - (u32) * (u16*)(animDef + 0x14) * (u32)lbl_803DC070;
                while (*framePtr < 0)
                {
                    *framePtr = *framePtr + (u32) * (u16*)(animDef + 0x10);
                }
            }
        }
        else
        {
            if (reverse == 0)
            {
                *framePtr = *framePtr + (u32) * (u16*)(animDef + 0x14) * (u32)lbl_803DC070;
            }
            else
            {
                *framePtr = *framePtr - (u32) * (u16*)(animDef + 0x14) * (u32)lbl_803DC070;
            }
            do
            {
                frame = *framePtr;
                if (frame < 0)
                {
                    *framePtr = -frame;
                    *flagsPtr = *flagsPtr & 0xfff7ffff;
                }
                frame2 = *framePtr;
                reverse = (u32) * (u16*)(animDef + 0x10);
                if ((int)reverse <= frame2)
                {
                    *framePtr = (reverse * 2 + -1) - frame2;
                    *flagsPtr = *flagsPtr | 0x80000;
                }
            }
            while ((int)reverse <= frame2 || frame < 0);
        }
    }
    else if ((flags & 0x40000) == 0)
    {
        reverse = randomGetRange(0, 1000);
        if (0x3d9 < (int)reverse)
        {
            *flagsPtr = *flagsPtr & 0xfff7ffff;
            *flagsPtr = *flagsPtr | 0x40000;
        }
    }
    else if (reverse == 0)
    {
        *framePtr = *framePtr + (u32) * (u16*)(animDef + 0x14) * (u32)lbl_803DC070;
        if ((int)(u32) * (u16*)(animDef + 0x10) <= *framePtr)
        {
            *framePtr = ((u32) * (u16*)(animDef + 0x10) * 2 + -1) - *framePtr;
            if (*framePtr < 0)
            {
                *framePtr = 0;
                *flagsPtr = *flagsPtr & 0xfff3ffff;
            }
            else
            {
                *flagsPtr = *flagsPtr | 0x80000;
            }
        }
    }
    else
    {
        *framePtr = *framePtr - (u32) * (u16*)(animDef + 0x14) * (u32)lbl_803DC070;
        if (*framePtr < 0)
        {
            *framePtr = 0;
            *flagsPtr = *flagsPtr & 0xfff3ffff;
        }
    }
    return;
}

void FUN_8005360c(u32 unused1, u32* nodeList, u32* overrideNode, u32 flags,
                  int packed)
{
    u32* curNode;
    u32* scan;
    int i;
    int idx;
    u32 count;
    u32* resultNode;

    if (nodeList != (u32*)0x0)
    {
        idx = packed >> 0x10;
        if (*(u16*)(nodeList + 4) == 0)
        {
            count = 0;
        }
        else
        {
            count = (int)(u32) * (u16*)(nodeList + 4) >> 8;
        }
        curNode = nodeList;
        resultNode = nodeList;
        if ((1 < count) && (idx < (int)count))
        {
            i = 0;
            for (; (i < idx && (resultNode != (u32*)0x0)); resultNode = (u32*)*resultNode)
            {
                i = i + 1;
            }
            if (resultNode != (u32*)0x0)
            {
                curNode = resultNode;
            }
            resultNode = curNode;
            if ((flags & 0x40) != 0)
            {
                if ((flags & 0x80000) == 0)
                {
                    i = idx + 1;
                    if ((int)count <= i)
                    {
                        if ((flags & 0x40000) == 0)
                        {
                            i = count - 1;
                        }
                        else
                        {
                            i = idx + -1;
                        }
                    }
                }
                else
                {
                    i = idx + -1;
                    if (i < 0)
                    {
                        if ((flags & 0x40000) == 0)
                        {
                            i = 0;
                        }
                        else
                        {
                            i = idx + 1;
                        }
                    }
                }
                idx = 0;
                for (scan = nodeList; (idx < i && (scan != (u32*)0x0));
                     scan = (u32*)*scan)
                {
                    idx = idx + 1;
                }
                resultNode = nodeList;
                if (scan != (u32*)0x0)
                {
                    resultNode = scan;
                }
            }
        }
        if (overrideNode != (u32*)0x0)
        {
            resultNode = overrideNode;
        }
        FUN_8004812c((int)curNode, 0);
        FUN_8004812c((int)resultNode, 1);
    }
    return;
}

void FUN_80053754(void)
{
}

/* Debug/effect draw stub, retail build compiles the body out (all args unused). */
void FUN_80053758(u64 arg0, u64 arg1, u64 arg2, u64 arg3,
                  u64 arg4, u64 arg5, u64 arg6, u64 arg7)
{
}

void FUN_800537a0(u32 unused1, u32 unused2, int format, char param4, u32 param5,
                  u8 wrapS, u8 wrapT, u8 minFilter, u8 magFilter)
{
    int tex;
    u64 dims;

    dims = FUN_80286834();
    tex = FUN_8025a850((u32)((u64)dims >> 0x20), (u32)dims, format, param4, param5);
    tex = FUN_80017830(tex + 0x60, 6);
    if (tex != 0)
    {
        FUN_800033a8(tex, 0, 100);
        *(char*)&((Texture*)tex)->format = (char)format;
        *(short*)(tex + 10) = (short)((u64)dims >> 0x20);
        *(short*)(tex + 0xc) = (short)dims;
        *(u16*)(tex + 0x10) = 1;
        *(u16*)(tex + 0xe) = 0;
        *(u8*)(tex + 0x17) = wrapS;
        *(u8*)(tex + 0x18) = wrapT;
        *(u8*)(tex + 0x19) = minFilter;
        *(u8*)(tex + 0x1a) = magFilter;
        *(u32*)(tex + 0x50) = 0;
        FUN_800531e0(tex);
    }
    FUN_80286880();
    return;
}

/* Guarded forwarder to the engine draw (FUN_8001763c): skips the draw while the
 * "file loading" flag (0x100000) is set, otherwise passes the transform/geometry
 * block (arg0..arg7) plus the draw flags through, capturing a result handle.
 * Note drawFlag1 is intentionally not forwarded. */
u32
FUN_8005398c(u64 arg0, double arg1, double arg2, u64 arg3, u64 arg4,
             u64 arg5, u64 arg6, u64 arg7, u32 drawFlag0,
             u32 drawFlag1, u32 drawFlag2, u32 drawFlag3, u32 drawFlag4,
             u32 drawFlag5, u32 drawFlag6, u32 drawFlag7)
{
    u32 fileFlags;
    u32 result[5];

    result[0] = 0;
    fileFlags = FUN_80042838();
    if ((fileFlags & 0x100000) == 0)
    {
        FUN_8001763c(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, result, drawFlag0,
                     drawFlag2, drawFlag3, drawFlag4, drawFlag5, drawFlag6, drawFlag7);
    }
    else
    {
        result[0] = 0;
    }
    return result[0];
}

void FUN_80053b3c(void)
{
    u32* state;

    state = FUN_800e87a8();
    gTumbleweedBushHitCooldownState = 0xffffffff;
    *(u8*)(state + 0x10) = *(u8*)(state + 0x10) & 0xdf;
    return;
}

void FUN_80053ba4(void)
{
    DAT_803dda74 = 0;
    return;
}

void FUN_80053bb0(double red, double green, double blue, u8 flag4, u8 flag5)
{
    DAT_803dda74 = 1;
    lbl_803DDAD0 = (float)red;
    lbl_803DDACC = (float)green;
    lbl_803DDAC8 = (float)blue;
    DAT_803dda75 = flag4;
    DAT_803dda7b = flag5;
    return;
}

/* Effect/light draw stub, retail build compiles the body out (all args unused).
 * Called from light.c with a transform block plus draw flags. */
void FUN_80053c98(u64 arg0, double arg1, double arg2, u64 arg3,
                  u64 arg4, u64 arg5, u64 arg6, u64 arg7,
                  int drawFlag0, char drawFlag1, u32 drawFlag2, u32 drawFlag3,
                  u32 drawFlag4, u32 drawFlag5, u32 drawFlag6, u32 drawFlag7)
{
}

extern u32 bEnableColorFilter;
extern u8 bEnableViewFinderHud;
extern u8 bEnableSpiritVision;
extern u8 bEnableMonochromeFilter;
extern u8 bEnableMotionBlur;
u32 Rcp_GetColorFilterEnabled(void) { return bEnableColorFilter; }
void Rcp_SetColorFilterEnabled(u32 x) { bEnableColorFilter = x; }
u8 Rcp_GetViewFinderHudEnabled(void) { return bEnableViewFinderHud; }
void Rcp_SetViewFinderHudEnabled(u8 x) { bEnableViewFinderHud = x; }
void Rcp_SetSpiritVisionEnabled(u8 x) { bEnableSpiritVision = x; }
void Rcp_SetMonochromeFilterEnabled(u8 x) { bEnableMonochromeFilter = x; }
u8 Rcp_GetMotionBlurEnabled(void) { return bEnableMotionBlur; }

extern f32 lbl_803DB62C;

void setMotionBlur(u8 enabled, f32 amount)
{
    bEnableMotionBlur = enabled;
    lbl_803DB62C = amount;
}

extern u8 bEnableDistortionFilter;
extern u8 bEnableBlurFilter;
void Rcp_DisableDistortionFilter(void) { bEnableDistortionFilter = 0x0; }
void Rcp_DisableBlurFilter(void) { bEnableBlurFilter = 0x0; }

void fn_800541A4(s16* p, s16 v) { *(s16*)((char*)p + 0x14) = v; }

extern u32 gRcpRenderFlags;
extern u32 lbl_803DCDB0;
extern u32 lbl_803DCDB4;

void fn_80053ED0(u32 bits) { gRcpRenderFlags = gRcpRenderFlags | bits; }
#pragma scheduling off
#pragma peephole off
#pragma opt_propagation off
void fn_80053EBC(u32 bits)
{
    u32 nb;
    u32 v;
    v = gRcpRenderFlags;
    nb = ~bits;
    gRcpRenderFlags = v & nb;
}
#pragma opt_propagation reset
#pragma peephole reset

void fn_800542F4(void)
{
    gRcpRenderFlags = 0;
    lbl_803DCDB4 = 0;
    lbl_803DCDB0 = 0;
}

extern f32 lbl_803DCE50;
extern f32 lbl_803DCE4C;
extern f32 blurFilterArea;
extern u8 bBlurFilterUseArea;
extern u8 bBiggerBlurFilter;

void turnOnBlurFilter(u8 useArea, u8 bigger, f32 a, f32 b, f32 area)
{
    bEnableBlurFilter = 1;
    lbl_803DCE50 = a;
    lbl_803DCE4C = b;
    blurFilterArea = area;
    bBlurFilterUseArea = useArea;
    bBiggerBlurFilter = bigger;
}

extern u8 lbl_803DCD68;
extern u8 lbl_803DCD69;
extern u8 lbl_803DCD6A;
extern void GXSetNumTexGens(u8 nTexGens);
extern void GXSetNumTevStages(u8 nStages);
extern void GXSetNumIndStages(u8 nIndStages);
#pragma dont_inline on
void textureFn_800528bc(void)
{
    GXSetNumTexGens(lbl_803DCD69);
    GXSetNumTevStages(lbl_803DCD6A);
    GXSetNumIndStages(lbl_803DCD68);
}
#pragma dont_inline reset

extern void* saveGameGetEnvState(void);
extern s32 lbl_803DCE00;
#pragma peephole off
void timeOfDayFn_80055000(void)
{
    u8* p = saveGameGetEnvState();
    lbl_803DCE00 = -1;
    p[0x40] = (u8)(p[0x40] & ~0x20);
}

void timeOfDayFn_80055038(void)
{
    u8* p = saveGameGetEnvState();
    lbl_803DCE00 = 1;
    p[0x40] = (u8)(p[0x40] | 0x20);
}

extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
#pragma peephole on
void fn_80054F74(int* p, f32* vec)
{
    if (*(void**)((char*)p + 0x30) != NULL) return;
    vec[0] = vec[0] + playerMapOffsetX;
    vec[2] = vec[2] + playerMapOffsetZ;
}

/* Pending warp destination saved by warpToMap from the map-warp tab entry and
 * applied to the player position on map reload (vec3 + two orientation s16s
 * truncated into the pos angle bytes). */
typedef struct WarpDestination {
    f32 x;
    f32 y;
    f32 z;
    s16 angle0;
    s16 angle1;
} WarpDestination;

extern u8 gRcpPendingWarpDest[];
extern u8* lbl_803DCE78;
extern s16 lbl_803DCEBA;
extern u8 gRcpWarpTransitionType;
extern u8 lbl_803DCEBD;

#pragma peephole off
void warpToMap(int idx, s8 transType)
{
    u8* p = lbl_803DCE78;
    getTabEntry(p, 28, idx << 4, 16);
    ((WarpDestination*)gRcpPendingWarpDest)->x = *(f32*)(p + 0);
    ((WarpDestination*)gRcpPendingWarpDest)->y = *(f32*)(p + 4);
    ((WarpDestination*)gRcpPendingWarpDest)->z = *(f32*)(p + 8);
    ((WarpDestination*)gRcpPendingWarpDest)->angle0 = *(s16*)(p + 12);
    ((WarpDestination*)gRcpPendingWarpDest)->angle1 = *(s16*)(p + 14);
    lbl_803DCEBA = (s16)idx;
    lbl_803DCEBD = 1;
    *(s8*)&gRcpWarpTransitionType = transType;
    if (transType != 0)
    {
        (*gScreenTransitionInterface)->start(2, 1);
    }
    Pause_SetDisabled(1);
}

u8 gRcpDistortSlots[0xA8];

#pragma peephole on
void ShaderDef_free(int* def)
{
    void* s;
    void* p1 = (void*)def[0];
    int i;
    void* p2;
    void* s2;
    int j;

    if (p1 != NULL)
    {
        for (i = 0; i < 6; i++)
        {
            s = *(void**)(gRcpDistortSlots + i * 0x1C); /* RcpDistortSlot.texture (typedef declared later) */
            if (((Texture*)s)->refCount != 0 && s == p1)
            {
                (((Texture*)*(void**)(gRcpDistortSlots + i * 0x1C))->refCount)--;
                break;
            }
        }
    }
    p2 = (void*)def[1];
    if (p2 == NULL) return;
    for (j = 0; j < 6; j++)
    {
        if (((Texture*)*(void**)(gRcpDistortSlots + j * 0x1C))->refCount != 0 &&
            *(void**)(gRcpDistortSlots + j * 0x1C) == p2)
        {
            (((Texture*)*(void**)(gRcpDistortSlots + j * 0x1C))->refCount)--;
            return;
        }
    }
}

typedef struct LoadedTextureEntry
{
    int key;
    u8* texture;
    u8 flag;
    u8 padding[3];
    u32 size;
} LoadedTextureEntry;

extern int gLoadedTextureCount;
extern LoadedTextureEntry* gLoadedTextures;
#pragma peephole off
void* textureIdxToPtr(int idx)
{
    int i;
    if ((u32)idx & 0x80000000) return (void*)idx;
    i = idx - 1;
    if (i < 0 || i >= gLoadedTextureCount) return NULL;
    return gLoadedTextures[i].texture;
}

void* getLoadedTexture(int key)
{
    LoadedTextureEntry* base;
    int i;

    i = 0;
    base = gLoadedTextures;
    for (; i < gLoadedTextureCount; i++)
    {
        if (key == base[i].key)
        {
            return base[i].texture;
        }
    }
    return NULL;
}

extern int getLoadedFileFlags(int);
extern void loadTextureFile(void** out, int asset);
#pragma dont_inline on
void* textureLoadAsset(int asset)
{
    void* out = NULL;
    if (getLoadedFileFlags(0) & 0x100000) return NULL;
    loadTextureFile(&out, asset);
    return out;
}
#pragma dont_inline reset

extern f32 distortionFilterVector[3];
extern f32 distortionFilterAngle1;
extern f32 distortionFilterAngle2;
extern u8 distortionFilterColor[3];

void turnOnDistortionFilter(f32* vec, u8* color, f32 angle2, f32 angle1)
{
    distortionFilterVector[0] = vec[0];
    distortionFilterVector[1] = vec[1];
    distortionFilterVector[2] = vec[2];
    distortionFilterAngle2 = angle2;
    distortionFilterColor[0] = color[0];
    distortionFilterColor[1] = color[1];
    distortionFilterColor[2] = color[2];
    distortionFilterAngle1 = angle1;
    bEnableDistortionFilter = 1;
}

extern int lbl_803DCD58, lbl_803DCD84;
extern int lbl_803DCD54, lbl_803DCD80;
extern int lbl_803DCD64, lbl_803DCD90;
extern int lbl_803DCD5C, lbl_803DCD88;
extern int lbl_803DCD60, lbl_803DCD8C;
extern int lbl_803DCD50, lbl_803DCD7C;
extern int lbl_803DCD4C, lbl_803DCD78;
extern int lbl_803DCD74;
extern int lbl_803DCD70;
extern int lbl_803DCD6C;
extern u8 lbl_803DCD6B, lbl_803DCD4B;
extern u8 lbl_803DCD4A;
extern u8 lbl_803DCD49;
extern u8 lbl_803DCD48;
extern u8 lbl_803DCD30;
#pragma dont_inline on
void resetLotsOfRenderVars(void)
{
    lbl_803DCD58 = 30;
    lbl_803DCD84 = 30;
    lbl_803DCD54 = 64;
    lbl_803DCD80 = 64;
    lbl_803DCD64 = 0;
    lbl_803DCD90 = 0;
    lbl_803DCD5C = 0;
    lbl_803DCD88 = 0;
    lbl_803DCD60 = 0;
    lbl_803DCD8C = 0;
    lbl_803DCD50 = 0;
    lbl_803DCD7C = 0;
    lbl_803DCD4C = 4;
    lbl_803DCD78 = 4;
    lbl_803DCD74 = 0;
    lbl_803DCD70 = 12;
    lbl_803DCD6C = 28;
    lbl_803DCD6B = 0;
    lbl_803DCD4B = 0;
    lbl_803DCD6A = 0;
    lbl_803DCD4A = 0;
    lbl_803DCD69 = 0;
    lbl_803DCD49 = 0;
    lbl_803DCD68 = 0;
    lbl_803DCD48 = 0;
    lbl_803DCD30 = 0;
}
#pragma dont_inline reset

extern void GXSetScissor(u32 left, u32 top, u32 wd, u32 ht);

void gxSetScissorRect(int p1, int p2, int x, int y, int x2, int y2)
{
    if (x < 0) x = 0;
    if (y < 0) y = 0;
    if (x2 < 0) x2 = 0;
    if (y2 < 0) y2 = 0;
    GXSetScissor(x, y, x2 - x, y2 - y);
}

extern void GXSetTevDirect(int tev);
extern void GXSetTevOrder(int tev, int tc, int tm, int color);
extern void GXSetTevSwapMode(int tev, int ras, int tex);
extern void GXSetTevColorIn(int tev, int a, int b, int c, int d);
extern void GXSetTevAlphaIn(int tev, int a, int b, int c, int d);
extern void GXSetTevColorOp(int tev, int op, int bias, int scale, int clamp, int outreg);
extern void GXSetTevAlphaOp(int tev, int op, int bias, int scale, int clamp, int outreg);

void gxColorFn_800523d0(void)
{
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR0A0);
    GXSetTevSwapMode(lbl_803DCD90, GX_TEV_SWAP0, GX_TEV_SWAP0);
    if (lbl_803DCD6A == 0 || lbl_803DCD30 == 0)
    {
        GXSetTevColorIn(lbl_803DCD90, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_RASC);
        GXSetTevAlphaIn(lbl_803DCD90, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_RASA);
    }
    else
    {
        GXSetTevColorIn(lbl_803DCD90, GX_CC_ZERO, GX_CC_CPREV, GX_CC_RASC, GX_CC_ZERO);
        GXSetTevAlphaIn(lbl_803DCD90, GX_CA_ZERO, GX_CA_APREV, GX_CA_RASA, GX_CA_ZERO);
    }
    GXSetTevColorOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    lbl_803DCD30 = 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD6A++;
}

extern void GXSetTevColor(int id, int* color);
extern void GXSetTevKColorSel(int tev, int sel);
extern f32 LastCommandWasRead_803DEB60;
extern f32 sDvdfsCurrentDirEntry;

typedef struct F32Pair
{
    f32 lo;
    f32 hi;
} F32Pair;

extern F32Pair LastReadIssued_803DEB58;
extern f32 lbl_803DEB5C;
extern f32 lbl_803DEB7C;
#pragma dont_inline on
#pragma opt_common_subs off
void gxFn_80052dc0(void)
{
    f32 omtx[4][4];
    f32 pmtx[3][4];
    GXSetViewport(LastCommandWasRead_803DEB60, LastCommandWasRead_803DEB60,
                  sDvdfsCurrentDirEntry, sDvdfsCurrentDirEntry,
                  LastCommandWasRead_803DEB60, lbl_803DEB5C);
    GXSetScissor(0, 0, 32, 32);
    GXSetDispCopySrc(0, 0, 32, 32);
    GXSetDispCopyDst(32, 32);
    GXSetTexCopySrc(0, 0, 32, 32);
    C_MTXOrtho(omtx, lbl_803DEB5C, lbl_803DEB7C,
               lbl_803DEB5C, lbl_803DEB7C,
               lbl_803DEB5C, LastReadIssued_803DEB58.lo);
    GXSetProjection(omtx, 1);
    GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
    gxSetZMode_(0, GX_EQUAL, 0);
    GXSetCullMode(GX_CULL_NONE);
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_NRM, GX_DIRECT);
    PSMTXIdentity(pmtx);
    GXLoadPosMtxImm(pmtx, 0);
    GXLoadNrmMtxImm(pmtx, 0);
    GXSetCurrentMtx(0);
}
#pragma opt_common_subs reset
#pragma dont_inline reset
void gxTextureFn_80052638(int* param)
{
    int sel;
    int v1;
    int color;
    GXSetTevDirect(lbl_803DCD90);
    color = param[0];
    GXSetTevColor(GX_TEVREG0, &color);
    gxTextureFn_8004bf88(param, 1, 0, &sel, &v1);
    GXSetTevKColorSel(lbl_803DCD90, sel);
    GXSetTevOrder(lbl_803DCD90, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
    GXSetTevSwapMode(lbl_803DCD90, GX_TEV_SWAP0, GX_TEV_SWAP0);
    if (lbl_803DCD6A != 0 && lbl_803DCD30 != 0)
    {
        GXSetTevColorIn(lbl_803DCD90, GX_CC_CPREV, GX_CC_KONST, GX_CC_A0, GX_CC_ZERO);
        GXSetTevAlphaIn(lbl_803DCD90, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    }
    GXSetTevColorOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    lbl_803DCD30 = 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD6A++;
}

extern void GXSetTevKAlphaSel(int tev, int sel);
#pragma dont_inline on
void textureFn_800524ec(int* param)
{
    int sel_color;
    int sel_alpha;
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR0A0);
    GXSetTevSwapMode(lbl_803DCD90, GX_TEV_SWAP0, GX_TEV_SWAP0);
    gxTextureFn_8004bf88(param, 0, 1, &sel_color, &sel_alpha);
    GXSetTevKAlphaSel(lbl_803DCD90, sel_alpha);
    if (lbl_803DCD6A == 0 || lbl_803DCD30 == 0)
    {
        GXSetTevColorIn(lbl_803DCD90, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_RASC);
        GXSetTevAlphaIn(lbl_803DCD90, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_KONST);
    }
    else
    {
        GXSetTevColorIn(lbl_803DCD90, GX_CC_ZERO, GX_CC_CPREV, GX_CC_RASC, GX_CC_ZERO);
        GXSetTevAlphaIn(lbl_803DCD90, GX_CA_ZERO, GX_CA_APREV, GX_CA_KONST, GX_CA_ZERO);
    }
    GXSetTevColorOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    lbl_803DCD30 = 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD6A++;
}
#pragma dont_inline reset

void gxColorFn_80052764(int* param)
{
    int sel_color;
    int sel_alpha;
    GXSetTevDirect(lbl_803DCD90);
    gxTextureFn_8004bf88(param, 1, 1, &sel_color, &sel_alpha);
    GXSetTevKAlphaSel(lbl_803DCD90, sel_alpha);
    GXSetTevKColorSel(lbl_803DCD90, sel_color);
    GXSetTevOrder(lbl_803DCD90, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR0A0);
    GXSetTevSwapMode(lbl_803DCD90, GX_TEV_SWAP0, GX_TEV_SWAP0);
    if (lbl_803DCD6A == 0 || lbl_803DCD30 == 0)
    {
        GXSetTevColorIn(lbl_803DCD90, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_KONST);
        GXSetTevAlphaIn(lbl_803DCD90, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_KONST);
    }
    else
    {
        GXSetTevColorIn(lbl_803DCD90, GX_CC_ZERO, GX_CC_CPREV, GX_CC_KONST, GX_CC_ZERO);
        GXSetTevAlphaIn(lbl_803DCD90, GX_CA_ZERO, GX_CA_APREV, GX_CA_KONST, GX_CA_ZERO);
    }
    GXSetTevColorOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    lbl_803DCD30 = 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD6A++;
}

extern u32 GXGetTexBufferSize(u16 w, u16 h, u32 format, u8 mipmap, u8 max_lod);
extern void* memset(void*, int, u32);
extern void textureFn_80053d58(void* obj);
#pragma dont_inline on
void* textureAlloc(u16 w, u16 h, int fmt, u8 mip, u8 maxLod, u8 wrapS, u8 wrapT, u8 minFilter, u8 magFilter)
{
    u8* obj;
    u32 size = GXGetTexBufferSize(w, h, fmt, mip, maxLod) + 96;
    obj = (u8*)mmAlloc(size, 6, 0);
    if (obj == NULL) return NULL;
    memset(obj, 0, 100);
    ((Texture*)obj)->format = fmt;
    ((Texture*)obj)->width = w;
    ((Texture*)obj)->height = h;
    *(u16*)(obj + 16) = 1; /* 0x10: mip-chain word (count<<8), not named in Texture */
    ((Texture*)obj)->refCount = 0;
    ((Texture*)obj)->wrapS = wrapS;
    ((Texture*)obj)->wrapT = wrapT;
    ((Texture*)obj)->minFilter = minFilter;
    ((Texture*)obj)->magFilter = magFilter;
    ((Texture*)obj)->imageOffset = 0;
    textureFn_80053d58(obj);
    return obj;
}

extern void GXInitTexObj(void* obj, void* img, u16 w, u16 h, int fmt, u8 ws, u8 wt, u8 mipmap);
extern void GXInitTexObjLOD(void* obj, int mn, int mg, f32 minLod, f32 maxLod, f32 lodBias, u8 bclamp, u8 edgeLod,
                            u8 aniso);
extern void GXInitTexObjUserData(void* obj, void* udata);
extern int GXGetTexObjFmt(void* obj);
extern u16 GXGetTexObjWidth(void* obj);
extern u16 GXGetTexObjHeight(void* obj);
extern f32 lbl_803DEB98;
extern f32 lbl_803DEB9C;
#pragma dont_inline reset
#pragma dont_inline on
void textureFn_80053d58(void* vobj)
{
    u8* obj = (u8*)vobj;
    u8 mipmap = 0;
    void* texObj;
    *(int*)(obj + 64) = mipmap; /* clears Texture.tmemAddr (0x40) */
    ((Texture*)obj)->preloaded = mipmap;
    texObj = (void*)(obj + 32); /* 0x20: embedded GXTexObj, not named in Texture */
    if ((int)((Texture*)obj)->maxLod - (int)((Texture*)obj)->minLod > 0) mipmap = 1;
    GXInitTexObj(texObj, obj + 96,
                 ((Texture*)obj)->width, ((Texture*)obj)->height,
                 ((Texture*)obj)->format, ((Texture*)obj)->wrapS, ((Texture*)obj)->wrapT, mipmap);
    if (mipmap != 0)
    {
        GXInitTexObjLOD(texObj, ((Texture*)obj)->minFilter, ((Texture*)obj)->magFilter,
                        (f32)(u32)obj[28], (f32)(s32)obj[29], /* minLod/maxLod: member form here ticks MWCC's @NNN counter */
                        lbl_803DEB98, 0, 0, 0);
    }
    else
    {
        GXInitTexObjLOD(texObj, ((Texture*)obj)->minFilter, ((Texture*)obj)->magFilter,
                        lbl_803DEB9C, lbl_803DEB9C, lbl_803DEB9C, 0, 0, 0);
    }
    GXInitTexObjUserData(texObj, obj);
    {
        u16 w;
        u16 h;
        int fmt = GXGetTexObjFmt(texObj);
        w = GXGetTexObjWidth(texObj);
        h = GXGetTexObjHeight(texObj);
        *(u32*)(obj + 68) = GXGetTexBufferSize(w, h, fmt, 0, 0);
    }
}
#pragma dont_inline reset

extern void findSomething(int);

#pragma peephole on
void textureFree(u8* tex)
{
    u8* iter;
    u8* next;
    if (tex == gLoadedTextures[0].texture) return;
    if (tex == NULL)
    {
        ((Texture*)tex)->evictTimer = 10;
        return;
    }
    if (((Texture*)tex)->refCount == 0)
    {
        ((Texture*)tex)->evictTimer = 10;
        return;
    }
    if (((Texture*)tex)->cached != 0 && ((Texture*)tex)->refCount <= 1)
    {
        ((Texture*)tex)->evictTimer = 10;
    }
    (((Texture*)tex)->refCount)--;
    if (((Texture*)tex)->refCount != 0) return;
    {
        int i;
        for (i = 0; i < gLoadedTextureCount; i++)
        {
            if (gLoadedTextures[i].texture == tex)
            {
                iter = *(u8**)tex;
                while (iter != NULL)
                {
                    if ((u32)iter < 0x80000000 || (u32)iter > 0x81800000) iter = NULL;
                    if ((u32)iter < 0x80000000 || (u32)iter >= 0xa0000000) { iter = NULL; continue; }
                    if (iter == NULL) continue;
                    next = *(u8**)iter;
                    if (((Texture*)iter)->preloaded != 0) findSomething((int)((Texture*)iter)->tmemAddr);
                    if (((Texture*)iter)->cached == 0) mm_free(iter);
                    iter = next;
                }
                if (((Texture*)tex)->preloaded != 0) findSomething(*(int*)&((Texture*)tex)->tmemAddr);
                if (((Texture*)tex)->cached == 0) mm_free(tex);
                gLoadedTextures[i].key = -1;
                gLoadedTextures[i].texture = NULL;
                return;
            }
        }
    }
}
#pragma peephole reset

#pragma scheduling on
int textureCrazyPointerFollowFn_80054c30(int* p, int n)
{
    int limit = *(u16*)((char*)p + 16);
    int i;
    if (n >= limit) n = limit - 1;
    n >>= 8;
    for (i = 0; i < n; i++)
    {
        p = *(int**)p;
    }
    return (int)p;
}

#pragma scheduling off
void shaderInit(u8* def, void** out, u8* obj)
{
    void** slot;
    void* s;

    if (*(void**)(def + 0x8) != NULL)
    {
        if (obj != NULL)
            slot = (void**)(gRcpDistortSlots + (6 - (obj[0xf2] + 1)) * 0x1C);
        else
            slot = (void**)(gRcpDistortSlots + 0x8C);
        s = *slot;
        (((Texture*)s)->refCount)++;
        out[0] = *slot;
    }
    if (*(void**)(def + 0x14) == NULL)
        return;
    if (def[0x20] >= 6)
        slot = (void**)gRcpDistortSlots;
    else
        slot = (void**)(gRcpDistortSlots + (def[0x20] >> 1) * 0x1C);
    s = *slot;
    (((Texture*)s)->refCount)++;
    out[1] = *slot;
}

extern void selectTexture(int handle, int slot);

void textureFn_800541ac(int p1 /* unused; target never reads r3 */, int* tex, void* forceTex, int flags, int packed)
{
    int i;
    int idx, count;
    int* node;
    int* cur;
    int* result;
    int* walk;
    u16 f10;

    if (tex == NULL)
        return;
    idx = packed >> 16;
    f10 = *(u16*)((char*)tex + 0x10);
    if (f10 != 0)
        count = f10 >> 8;
    else
        count = 0;
    cur = tex;
    result = tex;
    if (count > 1 && idx < count)
    {
        node = tex;
        for (i = 0; i < idx && node != NULL; i++)
            node = *(int**)node;
        if (node != NULL)
            cur = node;
        if (flags & 0x40)
        {
            if (flags & 0x80000)
            {
                idx--;
                if (idx < 0)
                {
                    if (flags & 0x40000)
                        idx += 2;
                    else
                        idx = 0;
                }
            }
            else
            {
                idx++;
                if (idx >= count)
                {
                    if (flags & 0x40000)
                        idx -= 2;
                    else
                        idx = count - 1;
                }
            }
            walk = tex;
            for (i = 0; i < idx && walk != NULL; i++)
                walk = *(int**)walk;
            if (walk != NULL)
                result = walk;
        }
        else
        {
            result = cur;
        }
    }
    if (forceTex != NULL)
        result = forceTex;
    selectTexture((int)cur, 0);
    selectTexture((int)result, 1);
}

extern u8 framesThisStep;

void textureAnimFn_80053f2c(u8* def, u32* node, int* cnt)
{
    u32 a, b, c;
    u32 v;
    int r;
    int flag2;

    v = node[0];
    a = v & 0x80000;
    b = v & 0x40000;
    c = v & 0x20000;
    if (c != 0)
    {
        if (b == 0)
        {
            r = randomGetRange(0, 0x3e8);
            if (r > 0x3d9)
            {
                node[0] &= ~0x80000LL;
                node[0] |= 0x40000LL;
            }
        }
        else if (a == 0)
        {
            *cnt += *(u16*)(def + 0x14) * framesThisStep;
            if (*cnt >= *(u16*)(def + 0x10))
            {
                *cnt = *(u16*)(def + 0x10) * 2 - 1 - *cnt;
                if (*cnt < 0)
                {
                    *cnt = 0;
                    node[0] &= ~0xc0000LL;
                }
                else
                {
                    node[0] |= 0x80000LL;
                }
            }
        }
        else
        {
            *cnt -= *(u16*)(def + 0x14) * framesThisStep;
            if (*cnt < 0)
            {
                *cnt = 0;
                node[0] &= ~0xc0000LL;
            }
        }
    }
    else if (b != 0)
    {
        if (a == 0)
            *cnt += *(u16*)(def + 0x14) * framesThisStep;
        else
            *cnt -= *(u16*)(def + 0x14) * framesThisStep;
        do
        {
            flag2 = 0;
            if (*cnt < 0)
            {
                *cnt = -*cnt;
                node[0] &= ~0x80000LL;
                flag2 = 1;
            }
            if (*cnt >= *(u16*)(def + 0x10))
            {
                *cnt = *(u16*)(def + 0x10) * 2 - 1 - *cnt;
                node[0] |= 0x80000LL;
                flag2 = 1;
            }
        }
        while (flag2 != 0);
    }
    else if (a == 0)
    {
        *cnt += *(u16*)(def + 0x14) * framesThisStep;
        while (*cnt >= *(u16*)(def + 0x10))
            *cnt -= *(u16*)(def + 0x10);
    }
    else
    {
        *cnt -= *(u16*)(def + 0x14) * framesThisStep;
        while (*cnt < 0)
            *cnt += *(u16*)(def + 0x10);
    }
}

extern char lbl_803822C8[];
extern void* gLoadedRomListPages[];
extern int* Obj_SetupObject(int* obj, int p1, int p2, int p3, int p4);

void mapInstantiateObjects(int* p1, int mapId, int index, int p4)
{
    int* seg = (int*)(lbl_803822C8 + mapId * 0x8c);
    int i;
    char* p;
    char* end;
    char* romBase;
    char* objStart;
    int objIndex;
    char* obj;
    int visible;
    int v;
    int flag;
    int byteIdx;
    int bit;
    s8* vis;

    if (seg[index] == -1)
        return;
    objIndex = 0;
    romBase = *(char**)((char*)p1 + 0x20);
    p = romBase;
    objStart = romBase + seg[index];
    while (p < objStart)
    {
        objIndex++;
        p += *(u8*)(p + 2) * 4;
    }
    for (i = index + 1; i <= 0x20; i++)
    {
        if (seg[i] != -1)
            break;
    }
    obj = objStart;
    end = romBase + seg[i];

    while (obj < end)
    {
        if (objIndex < 0)
        {
            visible = 0;
        }
        else
        {
            void* bm = gLoadedRomListPages[mapId];
            byteIdx = objIndex >> 3;
            if (byteIdx >= 0xc4)
            {
                visible = 0;
            }
            else
            {
                bit = 1 << (objIndex & 7);
                vis = *(s8**)((char*)bm + 0x10);
                if ((bit & vis[byteIdx]) != 0)
                    visible = 1;
                else
                    visible = 0;
            }
        }
        if (visible == 0)
        {
            v = (*gMapEventInterface)->getMapAct(mapId);
            if (v == -1)
            {
                flag = 0;
            }
            else if (v != 0)
            {
                if (v < 9)
                {
                    if ((*(u8*)(obj + 3) >> (v - 1)) & 1)
                        flag = 0;
                    else
                        goto flag1;
                }
                else if ((*(u8*)(obj + 5) >> (0x10 - v)) & 1)
                {
                    flag = 0;
                }
                else
                {
                flag1:
                    flag = 1;
                }
            }
            else
            {
                goto flag1;
            }
            if (flag != 0)
            {
                if (objIndex >= 0)
                {
                    void* bm2 = gLoadedRomListPages[mapId];
                    byteIdx = objIndex >> 3;
                    bit = 1 << (objIndex & 7);
                    vis = *(s8**)((char*)bm2 + 0x10);
                    vis[byteIdx] = vis[byteIdx] & ~bit;
                    vis = *(s8**)((char*)bm2 + 0x10);
                    vis[byteIdx] = vis[byteIdx] | bit;
                }
                Obj_SetupObject((int*)obj, 1, mapId, objIndex, p4);
            }
        }
        objIndex++;
        obj += *(u8*)(obj + 2) * 4;
    }
}

extern void GXLoadTexMtxImm(f32* mtx, int id, int type);
extern void GXSetTexCoordGen2(int dst, int fn, int src, int mtx, int normalize, int pt);
extern void GXLoadTexObjPreLoaded(u8* obj, u32* region, int map);
extern void GXLoadTexObj(u8* obj, int map);

void fn_80051868(u8* tex, f32* mtx, int mode)
{
    int map;
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 4);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    if (mtx != NULL)
    {
        GXLoadTexMtxImm(mtx, lbl_803DCD80, 0);
        GXSetTexCoordGen2(lbl_803DCD88, 1, lbl_803DCD78, 0x3c, 0, lbl_803DCD80);
        lbl_803DCD80 = lbl_803DCD80 + 3;
    }
    else
    {
        GXSetTexCoordGen2(lbl_803DCD88, 1, lbl_803DCD78, 0x3c, 0, 0x7d);
    }
    if (mode == 0)
    {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 8, 0xa, 0xf);
    }
    else if (mode == 8)
    {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 8, 0xa, 6);
    }
    else if (mode == 4)
    {
        GXSetTevColorIn(lbl_803DCD90, 8, 0xf, 0xf, 0);
    }
    else if (mode == 6)
    {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 8, 0, 0xf);
    }
    else if (mode == 9)
    {
        GXSetTevColorIn(lbl_803DCD90, 8, 0, 1, 0xf);
    }
    else
    {
        GXSetTevColorIn(lbl_803DCD90, 8, 0, 1, 0xf);
    }
    if (lbl_803DCD6B != 0)
    {
        GXSetTevAlphaIn(lbl_803DCD90, 7, 4, 0, 7);
    }
    else
    {
        GXSetTevAlphaIn(lbl_803DCD90, 7, 4, 5, 7);
        lbl_803DCD6B = 1;
    }
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    lbl_803DCD30 = 1;
    map = lbl_803DCD8C;
    if (tex != NULL)
    {
        u8* to = tex + 0x20;
        if (((Texture*)tex)->preloaded != 0)
        {
            GXLoadTexObjPreLoaded(to, ((Texture*)tex)->tmemAddr, map);
        }
        else
        {
            GXLoadTexObj(to, map);
        }
    }
    lbl_803DCD78 = lbl_803DCD78 + 1;
    lbl_803DCD88 = lbl_803DCD88 + 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD8C = lbl_803DCD8C + 1;
    lbl_803DCD6A++;
    lbl_803DCD69++;
}

void fn_80051B00(u8* tex, f32* mtx, int mode, int* kparam)
{
    int sel;
    int v1;
    int map;
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 4);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    if (mtx != NULL)
    {
        GXLoadTexMtxImm(mtx, lbl_803DCD80, 0);
        GXSetTexCoordGen2(lbl_803DCD88, 1, lbl_803DCD78, 0x3c, 0, lbl_803DCD80);
        lbl_803DCD80 = lbl_803DCD80 + 3;
    }
    else
    {
        GXSetTexCoordGen2(lbl_803DCD88, 1, lbl_803DCD78, 0x3c, 0, 0x7d);
    }
    gxTextureFn_8004bf88(kparam, 1, 0, &sel, &v1);
    GXSetTevKColorSel(lbl_803DCD90, sel);
    if (mode == 0)
    {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 8, 0xe, 0xf);
    }
    else if (mode == 8)
    {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 8, 0xe, 6);
    }
    else
    {
        GXSetTevColorIn(lbl_803DCD90, 8, 0, 1, 0xf);
    }
    if (lbl_803DCD6B != 0)
    {
        GXSetTevAlphaIn(lbl_803DCD90, 7, 4, 0, 7);
    }
    else
    {
        GXSetTevAlphaIn(lbl_803DCD90, 7, 4, 5, 7);
        lbl_803DCD6B = 1;
    }
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    lbl_803DCD30 = 1;
    map = lbl_803DCD8C;
    if (tex != NULL)
    {
        u8* to = tex + 0x20;
        if (((Texture*)tex)->preloaded != 0)
        {
            GXLoadTexObjPreLoaded(to, ((Texture*)tex)->tmemAddr, map);
        }
        else
        {
            GXLoadTexObj(to, map);
        }
    }
    lbl_803DCD78 = lbl_803DCD78 + 1;
    lbl_803DCD88 = lbl_803DCD88 + 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD8C = lbl_803DCD8C + 1;
    lbl_803DCD6A++;
    lbl_803DCD69++;
}

void fn_80051D5C(u8* tex, f32* mtx, int mode, int* kparam)
{
    int sel;
    int v1;
    int map;
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 4);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    if (mtx != NULL)
    {
        GXLoadTexMtxImm(mtx, lbl_803DCD80, 0);
        GXSetTexCoordGen2(lbl_803DCD88, 1, lbl_803DCD78, 0x3c, 0, lbl_803DCD80);
        lbl_803DCD80 = lbl_803DCD80 + 3;
    }
    else
    {
        GXSetTexCoordGen2(lbl_803DCD88, 1, lbl_803DCD78, 0x3c, 0, 0x7d);
    }
    gxTextureFn_8004bf88(kparam, 0, 1, &sel, &v1);
    GXSetTevKAlphaSel(lbl_803DCD90, v1);
    if (mode == 0)
    {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 8, 0xa, 0xf);
    }
    else if (mode == 8)
    {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 8, 0xa, 6);
    }
    else
    {
        GXSetTevColorIn(lbl_803DCD90, 8, 0, 1, 0xf);
    }
    if (lbl_803DCD6B != 0)
    {
        GXSetTevAlphaIn(lbl_803DCD90, 7, 4, 0, 7);
    }
    else
    {
        GXSetTevAlphaIn(lbl_803DCD90, 7, 4, 6, 7);
        lbl_803DCD6B = 1;
    }
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    lbl_803DCD30 = 1;
    map = lbl_803DCD8C;
    if (tex != NULL)
    {
        u8* to = tex + 0x20;
        if (((Texture*)tex)->preloaded != 0)
        {
            GXLoadTexObjPreLoaded(to, ((Texture*)tex)->tmemAddr, map);
        }
        else
        {
            GXLoadTexObj(to, map);
        }
    }
    lbl_803DCD78 = lbl_803DCD78 + 1;
    lbl_803DCD88 = lbl_803DCD88 + 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD8C = lbl_803DCD8C + 1;
    lbl_803DCD6A++;
    lbl_803DCD69++;
}

extern void GXSetTevSwapModeTable(int table, int r, int g, int b, int a);
extern void GXSetTevKColor(int id, int* color);

typedef struct TevSwapEntry
{
    int r;
    int g;
    int b;
} TevSwapEntry;

char sThreadStateAttrSuspendFormat[] = "thread: state=%d attr=%d suspend=%d\n";

u8 lbl_8030C880[288] = {
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
    0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
    0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
    0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
    0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
    0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
    0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
    0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08,
};

u16 lbl_8030C9A0[512] = {
    0x0100, 0x0100, 0x0100, 0x0100, 0x0101, 0x0101, 0x0101, 0x0101, 0x0102, 0x0102, 0x0102, 0x0102,
    0x0103, 0x0103, 0x0103, 0x0103, 0x0104, 0x0104, 0x0104, 0x0104, 0x0105, 0x0105, 0x0105, 0x0105,
    0x0106, 0x0106, 0x0106, 0x0106, 0x0107, 0x0107, 0x0107, 0x0107, 0x0108, 0x0108, 0x0108, 0x0108,
    0x0109, 0x0109, 0x0109, 0x0109, 0x010A, 0x010A, 0x010A, 0x010A, 0x010B, 0x010B, 0x010B, 0x010B,
    0x010C, 0x010C, 0x010C, 0x010C, 0x010D, 0x010D, 0x010D, 0x010D, 0x010E, 0x010E, 0x010E, 0x010E,
    0x010F, 0x010F, 0x010F, 0x010F, 0x0110, 0x0110, 0x0110, 0x0110, 0x0111, 0x0111, 0x0111, 0x0111,
    0x0112, 0x0112, 0x0112, 0x0112, 0x0113, 0x0113, 0x0113, 0x0113, 0x0114, 0x0114, 0x0114, 0x0114,
    0x0115, 0x0115, 0x0115, 0x0115, 0x0116, 0x0116, 0x0116, 0x0116, 0x0117, 0x0117, 0x0117, 0x0117,
    0x0000, 0x0000, 0x0001, 0x0001, 0x0002, 0x0002, 0x0003, 0x0003, 0x0004, 0x0004, 0x0005, 0x0005,
    0x0006, 0x0006, 0x0007, 0x0007, 0x0008, 0x0008, 0x0009, 0x0009, 0x000A, 0x000A, 0x000B, 0x000B,
    0x000C, 0x000C, 0x000D, 0x000D, 0x000E, 0x000E, 0x000F, 0x000F, 0x0010, 0x0010, 0x0011, 0x0011,
    0x0012, 0x0012, 0x0013, 0x0013, 0x0014, 0x0014, 0x0015, 0x0015, 0x0016, 0x0016, 0x0017, 0x0017,
    0x0018, 0x0018, 0x0019, 0x0019, 0x001A, 0x001A, 0x001B, 0x001B, 0x001C, 0x001C, 0x001D, 0x001D,
    0x001E, 0x001E, 0x001F, 0x001F, 0x0020, 0x0020, 0x0021, 0x0021, 0x0022, 0x0022, 0x0023, 0x0023,
    0x0024, 0x0024, 0x0025, 0x0025, 0x0026, 0x0026, 0x0027, 0x0027, 0x0028, 0x0028, 0x0029, 0x0029,
    0x002A, 0x002A, 0x002B, 0x002B, 0x002C, 0x002C, 0x002D, 0x002D, 0x002E, 0x002E, 0x002F, 0x002F,
    0x0030, 0x0030, 0x0031, 0x0031, 0x0032, 0x0032, 0x0033, 0x0033, 0x0034, 0x0034, 0x0035, 0x0035,
    0x0036, 0x0036, 0x0037, 0x0037, 0x0038, 0x0038, 0x0039, 0x0039, 0x003A, 0x003A, 0x003B, 0x003B,
    0x003C, 0x003C, 0x003D, 0x003D, 0x003E, 0x003E, 0x003F, 0x003F, 0x0040, 0x0040, 0x0041, 0x0041,
    0x0042, 0x0042, 0x0043, 0x0043, 0x0044, 0x0044, 0x0045, 0x0045, 0x0046, 0x0046, 0x0047, 0x0047,
    0x0048, 0x0048, 0x0049, 0x0049, 0x004A, 0x004A, 0x004B, 0x004B, 0x004C, 0x004C, 0x004D, 0x004D,
    0x004E, 0x004E, 0x004F, 0x004F, 0x0050, 0x0050, 0x0051, 0x0051, 0x0052, 0x0052, 0x0053, 0x0053,
    0x0054, 0x0054, 0x0055, 0x0055, 0x0056, 0x0056, 0x0057, 0x0057, 0x0058, 0x0058, 0x0059, 0x0059,
    0x005A, 0x005A, 0x005B, 0x005B, 0x005C, 0x005C, 0x005D, 0x005D, 0x005E, 0x005E, 0x005F, 0x005F,
    0x0060, 0x0060, 0x0061, 0x0061, 0x0062, 0x0062, 0x0063, 0x0063, 0x0064, 0x0064, 0x0065, 0x0065,
    0x0066, 0x0066, 0x0067, 0x0067, 0x0068, 0x0068, 0x0069, 0x0069, 0x006A, 0x006A, 0x006B, 0x006B,
    0x006C, 0x006C, 0x006D, 0x006D, 0x006E, 0x006E, 0x006F, 0x006F, 0x0070, 0x0070, 0x0071, 0x0071,
    0x0072, 0x0072, 0x0073, 0x0073, 0x0074, 0x0074, 0x0075, 0x0075, 0x0076, 0x0076, 0x0077, 0x0077,
    0x0078, 0x0078, 0x0079, 0x0079, 0x007A, 0x007A, 0x007B, 0x007B, 0x007C, 0x007C, 0x007D, 0x007D,
    0x007E, 0x007E, 0x007F, 0x007F, 0x0080, 0x0080, 0x0081, 0x0081, 0x0082, 0x0082, 0x0083, 0x0083,
    0x0084, 0x0084, 0x0085, 0x0085, 0x0086, 0x0086, 0x0087, 0x0087, 0x0088, 0x0088, 0x0089, 0x0089,
    0x008A, 0x008A, 0x008B, 0x008B, 0x008C, 0x008C, 0x008D, 0x008D, 0x008E, 0x008E, 0x008F, 0x008F,
    0x0118, 0x0118, 0x0119, 0x0119, 0x011A, 0x011A, 0x011B, 0x011B, 0x011C, 0x011C, 0x011D, 0x011D,
    0x011E, 0x011E, 0x011F, 0x011F, 0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095, 0x0096, 0x0097,
    0x0098, 0x0099, 0x009A, 0x009B, 0x009C, 0x009D, 0x009E, 0x009F, 0x00A0, 0x00A1, 0x00A2, 0x00A3,
    0x00A4, 0x00A5, 0x00A6, 0x00A7, 0x00A8, 0x00A9, 0x00AA, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0x00AF,
    0x00B0, 0x00B1, 0x00B2, 0x00B3, 0x00B4, 0x00B5, 0x00B6, 0x00B7, 0x00B8, 0x00B9, 0x00BA, 0x00BB,
    0x00BC, 0x00BD, 0x00BE, 0x00BF, 0x00C0, 0x00C1, 0x00C2, 0x00C3, 0x00C4, 0x00C5, 0x00C6, 0x00C7,
    0x00C8, 0x00C9, 0x00CA, 0x00CB, 0x00CC, 0x00CD, 0x00CE, 0x00CF, 0x00D0, 0x00D1, 0x00D2, 0x00D3,
    0x00D4, 0x00D5, 0x00D6, 0x00D7, 0x00D8, 0x00D9, 0x00DA, 0x00DB, 0x00DC, 0x00DD, 0x00DE, 0x00DF,
    0x00E0, 0x00E1, 0x00E2, 0x00E3, 0x00E4, 0x00E5, 0x00E6, 0x00E7, 0x00E8, 0x00E9, 0x00EA, 0x00EB,
    0x00EC, 0x00ED, 0x00EE, 0x00EF, 0x00F0, 0x00F1, 0x00F2, 0x00F3, 0x00F4, 0x00F5, 0x00F6, 0x00F7,
    0x00F8, 0x00F9, 0x00FA, 0x00FB, 0x00FC, 0x00FD, 0x00FE, 0x00FF,
};

u8 lbl_8030CDA0[32] = {
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
    0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
};

u8 lbl_8030CDC0[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
};

u8 lbl_8030CDE0[256] = {
    0x00, 0x80, 0x40, 0xC0, 0x20, 0xA0, 0x60, 0xE0, 0x10, 0x90, 0x50, 0xD0, 0x30, 0xB0, 0x70, 0xF0,
    0x08, 0x88, 0x48, 0xC8, 0x28, 0xA8, 0x68, 0xE8, 0x18, 0x98, 0x58, 0xD8, 0x38, 0xB8, 0x78, 0xF8,
    0x04, 0x84, 0x44, 0xC4, 0x24, 0xA4, 0x64, 0xE4, 0x14, 0x94, 0x54, 0xD4, 0x34, 0xB4, 0x74, 0xF4,
    0x0C, 0x8C, 0x4C, 0xCC, 0x2C, 0xAC, 0x6C, 0xEC, 0x1C, 0x9C, 0x5C, 0xDC, 0x3C, 0xBC, 0x7C, 0xFC,
    0x02, 0x82, 0x42, 0xC2, 0x22, 0xA2, 0x62, 0xE2, 0x12, 0x92, 0x52, 0xD2, 0x32, 0xB2, 0x72, 0xF2,
    0x0A, 0x8A, 0x4A, 0xCA, 0x2A, 0xAA, 0x6A, 0xEA, 0x1A, 0x9A, 0x5A, 0xDA, 0x3A, 0xBA, 0x7A, 0xFA,
    0x06, 0x86, 0x46, 0xC6, 0x26, 0xA6, 0x66, 0xE6, 0x16, 0x96, 0x56, 0xD6, 0x36, 0xB6, 0x76, 0xF6,
    0x0E, 0x8E, 0x4E, 0xCE, 0x2E, 0xAE, 0x6E, 0xEE, 0x1E, 0x9E, 0x5E, 0xDE, 0x3E, 0xBE, 0x7E, 0xFE,
    0x01, 0x81, 0x41, 0xC1, 0x21, 0xA1, 0x61, 0xE1, 0x11, 0x91, 0x51, 0xD1, 0x31, 0xB1, 0x71, 0xF1,
    0x09, 0x89, 0x49, 0xC9, 0x29, 0xA9, 0x69, 0xE9, 0x19, 0x99, 0x59, 0xD9, 0x39, 0xB9, 0x79, 0xF9,
    0x05, 0x85, 0x45, 0xC5, 0x25, 0xA5, 0x65, 0xE5, 0x15, 0x95, 0x55, 0xD5, 0x35, 0xB5, 0x75, 0xF5,
    0x0D, 0x8D, 0x4D, 0xCD, 0x2D, 0xAD, 0x6D, 0xED, 0x1D, 0x9D, 0x5D, 0xDD, 0x3D, 0xBD, 0x7D, 0xFD,
    0x03, 0x83, 0x43, 0xC3, 0x23, 0xA3, 0x63, 0xE3, 0x13, 0x93, 0x53, 0xD3, 0x33, 0xB3, 0x73, 0xF3,
    0x0B, 0x8B, 0x4B, 0xCB, 0x2B, 0xAB, 0x6B, 0xEB, 0x1B, 0x9B, 0x5B, 0xDB, 0x3B, 0xBB, 0x7B, 0xFB,
    0x07, 0x87, 0x47, 0xC7, 0x27, 0xA7, 0x67, 0xE7, 0x17, 0x97, 0x57, 0xD7, 0x37, 0xB7, 0x77, 0xF7,
    0x0F, 0x8F, 0x4F, 0xCF, 0x2F, 0xAF, 0x6F, 0xEF, 0x1F, 0x9F, 0x5F, 0xDF, 0x3F, 0xBF, 0x7F, 0xFF,
};

int lbl_8030CEE0[9] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8,
};

TevSwapEntry gRcpTevSwapTable[24] = {
    {0, 1, 2},
    {0, 2, 1},
    {1, 0, 2},
    {2, 0, 1},
    {1, 2, 0},
    {2, 1, 0},
    {0, 0, 2},
    {0, 2, 0},
    {2, 0, 0},
    {0, 0, 1},
    {0, 1, 0},
    {1, 0, 0},
    {1, 1, 2},
    {1, 2, 1},
    {2, 1, 1},
    {1, 1, 0},
    {1, 0, 1},
    {0, 1, 1},
    {2, 2, 0},
    {2, 0, 2},
    {0, 2, 2},
    {2, 2, 1},
    {2, 1, 2},
    {1, 2, 2},
};
u8 lbl_8030D028[48] = {
    0x3F, 0x00, 0x00, 0x00, 0x3F, 0x80, 0x00, 0x00, 0x3F, 0x00, 0x00, 0x00, 0x3F, 0x00, 0x00, 0x00,
    0x3E, 0xCC, 0xCC, 0xCD, 0x3F, 0x80, 0x00, 0x00, 0x3E, 0x99, 0x99, 0x9A, 0x3F, 0x4C, 0xCC, 0xCD,
    0x3E, 0x4C, 0xCC, 0xCD, 0x3F, 0x80, 0x00, 0x00, 0x3E, 0xCC, 0xCC, 0xCD, 0x3F, 0x00, 0x00, 0x00,
};
extern u8 lbl_803779A0[];
void fn_80053C40(u8 * tex, u8 * obj);

void gxFn_80051fb8(u8* tex, f32* mtx, int mode, int* kparam, u8 swapsel, u8 useK)
{
    int sel;
    int v1;
    int color;
    int map;
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 0xff);
    GXSetTevSwapMode(lbl_803DCD90, 0, 1);
    GXSetTevSwapModeTable(GX_TEV_SWAP1, gRcpTevSwapTable[swapsel].r, gRcpTevSwapTable[swapsel].g,
                          gRcpTevSwapTable[swapsel].b, GX_CH_ALPHA);
    if (mtx != NULL)
    {
        GXLoadTexMtxImm(mtx, lbl_803DCD80, 0);
        GXSetTexCoordGen2(lbl_803DCD88, 1, lbl_803DCD78, 0x3c, 0, lbl_803DCD80);
        lbl_803DCD80 = lbl_803DCD80 + 3;
    }
    else
    {
        GXSetTexCoordGen2(lbl_803DCD88, 1, lbl_803DCD78, 0x3c, 0, 0x7d);
    }
    if (useK != 0)
    {
        gxTextureFn_8004bf88(kparam, 1, 1, &sel, &v1);
        GXSetTevKColorSel(lbl_803DCD90, sel);
        if (*(void**)&((Texture*)tex)->imageOffset != NULL)
        {
            GXSetTevKAlphaSel(lbl_803DCD90 + 1, v1);
        }
        else
        {
            GXSetTevKAlphaSel(lbl_803DCD90, v1);
        }
    }
    else
    {
        color = *kparam;
        GXSetTevKColor(lbl_803DCD74, &color);
        GXSetTevKColorSel(lbl_803DCD90, lbl_803DCD70);
        if (*(void**)&((Texture*)tex)->imageOffset != NULL)
        {
            GXSetTevKAlphaSel(lbl_803DCD90 + 1, lbl_803DCD6C);
        }
        else
        {
            GXSetTevKAlphaSel(lbl_803DCD90, lbl_803DCD6C);
        }
        lbl_803DCD74 = lbl_803DCD74 + 1;
        lbl_803DCD70 = lbl_803DCD70 + 1;
        lbl_803DCD6C = lbl_803DCD6C + 1;
    }
    if (mode == 0)
    {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 8, 0xe, 0xf);
    }
    else if (mode == 8)
    {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 8, 4, 6);
    }
    else
    {
        GXSetTevColorIn(lbl_803DCD90, 8, 0, 1, 0xf);
    }
    if (lbl_803DCD6B != 0)
    {
        GXSetTevAlphaIn(lbl_803DCD90, 7, 4, 0, 7);
    }
    else
    {
        GXSetTevAlphaIn(lbl_803DCD90, 7, 4, 6, 7);
    }
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    lbl_803DCD30 = 1;
    map = lbl_803DCD8C;
    if (tex != NULL)
    {
        u8* to = tex + 0x20;
        if (((Texture*)tex)->preloaded != 0)
        {
            GXLoadTexObjPreLoaded(to, ((Texture*)tex)->tmemAddr, map);
        }
        else
        {
            GXLoadTexObj(to, map);
        }
        if (*(void**)&((Texture*)tex)->imageOffset != NULL)
        {
            fn_80053C40(tex, lbl_803779A0);
            GXLoadTexObj(lbl_803779A0, GX_TEXMAP1);
        }
    }
    if (*(void**)&((Texture*)tex)->imageOffset != NULL)
    {
        lbl_803DCD6A++;
        lbl_803DCD90 = lbl_803DCD90 + 1;
        lbl_803DCD8C = lbl_803DCD8C + 1;
        GXSetTevDirect(lbl_803DCD90);
        GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 0xff);
        GXSetTevSwapMode(lbl_803DCD90, 0, 0);
        GXSetTevColorIn(lbl_803DCD90, 0xf, 0xf, 0xf, 0);
        GXSetTevAlphaIn(lbl_803DCD90, 7, 4, 6, 7);
        GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
        GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    }
    lbl_803DCD6B = 1;
    lbl_803DCD78 = lbl_803DCD78 + 1;
    lbl_803DCD88 = lbl_803DCD88 + 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD8C = lbl_803DCD8C + 1;
    lbl_803DCD6A++;
    lbl_803DCD69++;
}

void fn_80053C40(u8* tex, u8* obj)
{
    u8 mipmap;
    if ((int)((Texture*)tex)->maxLod - (int)((Texture*)tex)->minLod > 0)
    {
        mipmap = 1;
    }
    else
    {
        mipmap = 0;
    }
    GXInitTexObj(obj, (u8*)(tex + ((Texture*)tex)->imageOffset + 0x60),
                 ((Texture*)tex)->width, ((Texture*)tex)->height,
                 GX_TF_I4, ((Texture*)tex)->wrapS, ((Texture*)tex)->wrapT, mipmap);
    if (mipmap != 0)
    {
        GXInitTexObjLOD(obj, ((Texture*)tex)->minFilter, ((Texture*)tex)->magFilter,
                        (f32)(u32)((Texture*)tex)->minLod, (f32)(s32)((Texture*)tex)->maxLod,
                        lbl_803DEB98, 0, 0, 0);
    }
    else
    {
        GXInitTexObjLOD(obj, ((Texture*)tex)->minFilter, ((Texture*)tex)->magFilter,
                        0.0f, 0.0f, 0.0f, 0, 0, 0);
    }
}

extern void GXSetMisc(int token, u32 val);
extern void GXBegin(int prim, int vtxfmt, u16 nverts);
extern f32 sqrtf(f32 x);
extern u8 gRcpWarpDistortListBuilt;
extern u32 gRcpWarpDistortListSize;
u8 gRcpWarpDistortDisplayList[0x6640];
extern F32Pair LastReadFinished_803DEB50;
extern f32 lbl_803DEB54;
extern f32 lbl_803DEB64;

#pragma opt_loop_invariants off
#pragma opt_propagation off
void lightFn_80052974(f32 a, f32 b) /* params unused; callers pass (i*32, 0.0f) */
{
    f32 z;
    f32 step;
    f32 half;
    f32 span;
    f32 x0;
    f32 y;
    f32 ySq;
    f32 x1;
    f32 distSq;
    f32 bulge;
    f32 col0;
    f32 col1;
    u32 i;
    u32 j;

    if (gRcpWarpDistortListBuilt == 0)
    {
        GXSetMisc(GX_MT_XF_FLUSH, 0);
        DCInvalidateRange(gRcpWarpDistortDisplayList, 0x6640);
        GXBeginDisplayList(gRcpWarpDistortDisplayList, 0x6640);
        span = LastReadIssued_803DEB58.lo;
        half = lbl_803DEB5C;
        step = lbl_803DEB54;
        z = lbl_803DEB64;
        for (i = 0; i < 0x10; i++)
        {
            GXBegin(GX_TRIANGLESTRIP, GX_VTXFMT4, 0x22);
            col0 = step * (f32)i;
            col1 = step * (f32)(i + 1);
            x0 = col0 / span - half;
            x1 = col1 / span - half;
            for (j = 0; j <= 0x10; j++)
            {
                y = (step * (f32)j) / span - half;
                ySq = y * y;
                distSq = x0 * x0 + ySq;
                if (distSq < half)
                {
                    bulge = sqrtf(half - distSq);
                }
                else
                {
                    bulge = LastCommandWasRead_803DEB60;
                }
                *(volatile f32*)0xCC008000 = x0;
                *(volatile f32*)0xCC008000 = y;
                *(volatile f32*)0xCC008000 = z;
                *(volatile f32*)0xCC008000 = x0;
                *(volatile f32*)0xCC008000 = y;
                *(volatile f32*)0xCC008000 = bulge;
                distSq = x1 * x1 + ySq;
                if (distSq < half)
                {
                    bulge = sqrtf(half - distSq);
                }
                else
                {
                    bulge = LastCommandWasRead_803DEB60;
                }
                *(volatile f32*)0xCC008000 = x1;
                *(volatile f32*)0xCC008000 = y;
                *(volatile f32*)0xCC008000 = z;
                *(volatile f32*)0xCC008000 = x1;
                *(volatile f32*)0xCC008000 = y;
                *(volatile f32*)0xCC008000 = bulge;
            }
        }
        gRcpWarpDistortListSize = GXEndDisplayList();
        gRcpWarpDistortListBuilt = 1;
        GXSetMisc(GX_MT_XF_FLUSH, 8);
    }
    GXCallDisplayList(gRcpWarpDistortDisplayList, gRcpWarpDistortListSize);
}
#pragma opt_propagation reset
#pragma opt_loop_invariants reset

extern void* fn_80089A58(void);
extern void* fn_80089A50(void);
extern void modelLightStruct_setSpecularAttenuation(void* light, f32 a, f32 b);
extern void modelLightStruct_setAngularAttenuation(void* light, f32 a, f32 b, f32 c);
extern void modelLightStruct_setSpecularColor(void* light, int r, int g, int b, int a);
extern void modelLightStruct_loadChannelLight(int idx, void* light, int model);
extern f32 lbl_803DEB70;
extern f32 lbl_803DEB74;

#pragma dont_inline on
#pragma opt_common_subs off
int textureFn_80052bb4(int model, f32* params)
{
    void* la;
    void* lb;
    la = fn_80089A58();
    lb = fn_80089A50();
    if (la == NULL || lb == NULL)
    {
        return 0;
    }
    modelLightChannels_reset(1);
    modelLightChannel_configure(0, 1, 0);
    modelLightChannel_configure(2, 0, 0);
    modelLightStruct_setSpecularAttenuation(la, params[0], LastCommandWasRead_803DEB60);
    modelLightStruct_setSpecularColor(la, 0xff, 0, 0, 0xff);
    modelLightStruct_loadChannelLight(0, la, model);
    modelLightStruct_setSpecularAttenuation(la, params[1], LastCommandWasRead_803DEB60);
    modelLightStruct_setSpecularColor(la, 0, 0, 0xff, 0xff);
    modelLightStruct_loadChannelLight(0, la, model);
    modelLightStruct_setAngularAttenuation(la, lbl_803DEB70, LastCommandWasRead_803DEB60, LastCommandWasRead_803DEB60);
    modelLightStruct_loadChannelLight(2, la, model);
    modelLightChannel_configure(1, 1, 0);
    modelLightChannel_configure(3, 0, 0);
    modelLightStruct_setSpecularAttenuation(lb, params[0], LastCommandWasRead_803DEB60);
    modelLightStruct_setSpecularColor(lb, 0xff, 0, 0, 0xff);
    modelLightStruct_loadChannelLight(1, lb, model);
    modelLightStruct_setSpecularAttenuation(lb, params[1], LastCommandWasRead_803DEB60);
    modelLightStruct_setSpecularColor(lb, 0, 0, 0xff, 0xff);
    modelLightStruct_loadChannelLight(1, lb, model);
    modelLightStruct_setAngularAttenuation(lb, lbl_803DEB74, LastCommandWasRead_803DEB60, LastCommandWasRead_803DEB60);
    modelLightStruct_loadChannelLight(3, lb, model);
    modelLightChannels_applyGXControls();
    modelLightStruct_setAngularAttenuation(la, lbl_803DEB5C, LastCommandWasRead_803DEB60,
                                           LastCommandWasRead_803DEB60);
    modelLightStruct_setAngularAttenuation(lb, lbl_803DEB5C, LastCommandWasRead_803DEB60,
                                           LastCommandWasRead_803DEB60);
    return 0;
}
#pragma opt_common_subs reset
#pragma dont_inline reset

/* Declared here (not at top of file): a typedef parsed before fn_80053C40
 * renumbers MWCC's internal @NNN constant-pool symbol for its 0.0f
 * (strtab byte diff). ShaderDef_free/shaderInit above therefore keep raw
 * slot arithmetic on gRcpDistortSlots. */
typedef struct RcpDistortSlot
{
    u8* texture;   // 0x00
    int model;     // 0x04
    int unk8;      // 0x08
    u8 colR;       // 0x0c
    u8 colG;       // 0x0d
    u8 colB;       // 0x0e
    u8 unkF;       // 0x0f
    f32 params[2]; // 0x10
    u8 scaleR;     // 0x18
    u8 scaleB;     // 0x19
    u8 group;      // 0x1a
    u8 mode;       // 0x1b
} RcpDistortSlot;

extern f32 powfCoreHighPrecision(f32 base, f32 exp);
extern f32 gRcpDistortScaleA;
extern f32 gRcpDistortPowExp;
extern u8 lbl_8030D028[];
extern u8 gRcpDistortSlotIndex;
extern void* gRcpDistortTexture;

void initFn_800534f8(void)
{
    int i;
    RcpDistortSlot* slots;
    u8* cfg;
    u32 pairIdx;
    RcpDistortSlot* slot;
    f32 strengthScale;
    f32 radiusScale;
    f32 strength;
    f32 falloff;

    i = 0;
    slots = (RcpDistortSlot*)gRcpDistortSlots;
    for (; i < 6; i++)
    {
        slots[i].texture = (u8*)textureAlloc(0x20, 0x20, 6, 0, 0, 0, 0, 1, 1);
        slots[i].group = 0;
    }
    gRcpDistortSlotIndex = i = 0;
    cfg = lbl_8030D028; /* 6 pairs of {f32 radius, f32 strength} */
    for (; i < 6; i++)
    {
        radiusScale = gRcpDistortScaleA;
        strengthScale = LastReadFinished_803DEB50.lo;
        strength = *(f32*)(cfg + i * 8 + 4);
        slot = (RcpDistortSlot*)(gRcpDistortSlots + gRcpDistortSlotIndex * 0x1c);
        slot->colR = 0xff;
        slot->colG = 0xff;
        slot->colB = 0xff;
        falloff = radiusScale / powfCoreHighPrecision(*(f32*)(cfg + i * 8), gRcpDistortPowExp);
        slot = (RcpDistortSlot*)(gRcpDistortSlots + gRcpDistortSlotIndex * 0x1c);
        pairIdx = i & 1;
        slot->params[pairIdx] = falloff;
        *(s8*)(&slot->scaleR + pairIdx) = strengthScale * strength;
        slot->mode = 1;
        if (pairIdx != 0)
        {
            gRcpDistortSlotIndex = gRcpDistortSlotIndex + 1;
        }
    }
    /* mode = 0 for the three remaining slots; member form (stb 0x1b(base+idx))
     * diverges - target hoists base+0x1b and emits stbx. */
    (gRcpDistortSlots + 0x1b)[gRcpDistortSlotIndex++ * 0x1c] = 0;
    (gRcpDistortSlots + 0x1b)[gRcpDistortSlotIndex++ * 0x1c] = 0;
    (gRcpDistortSlots + 0x1b)[gRcpDistortSlotIndex++ * 0x1c] = 0;
    gRcpDistortTexture = textureLoadAsset(0x5dc);
}

extern void* getCurrentDataFile(int id);
extern void loadAssetFileById(void* out, int id);
int* gRcpTexBankTable[3];
int gRcpTexBankCount[3];
extern u16* gRcpTexIdRemap;
extern void* gRcpTexHeaderBuffer;
void* textureLoad(int texId, u8 flag);

void loadTextureFiles(void)
{
    int* p;
    int** q;
    int* out;
    int n;

    gLoadedTextures = (LoadedTextureEntry*)mmAlloc(0x2bc0, 6, 0);
    gLoadedTextureCount = n = 0;
    p = getCurrentDataFile(0x24);
    gRcpTexBankTable[0] = p;
    if (gRcpTexBankTable != NULL)
        goto countBank0;
    goto doneBank0;
countBank0:
    while (*p != -1)
    {
        p++;
        n++;
    }
    gRcpTexBankCount[0] = n - 1;
doneBank0:
    n = 0;
    p = getCurrentDataFile(0x21);
    gRcpTexBankTable[1] = p;
    if (gRcpTexBankTable != NULL)
        goto countBank1;
    goto doneBank1;
countBank1:
    while (*p != -1)
    {
        p++;
        n++;
    }
    gRcpTexBankCount[1] = n - 1;
doneBank1:
    n = 0;
    p = getCurrentDataFile(0x50);
    gRcpTexBankTable[2] = p;
    while (*p != -1)
    {
        p++;
        n++;
    }
    gRcpTexBankCount[2] = n - 1;
    loadAssetFileById(&gRcpTexIdRemap, 0x22);
    q = gRcpTexBankTable;
    out = gRcpTexBankCount;
    for (n = 0; n < 2; n++)
    {
        int m = 0;
        p = *q;
        while (*p != -1)
        {
            p++;
            m++;
        }
        *out = m - 1;
        q++;
        out++;
    }
    gRcpTexHeaderBuffer = (void*)mmAlloc(0x120, 6, 0);
    textureLoad(0, 0);
}

extern s16 lbl_803DCEB8;
extern u8 lbl_803DCDE0;
extern u8 lbl_803DCA40;
extern void mapReload(void);
extern void blankScreen(int);

void loadNextMap(void)
{
    u8* pos;
    pos = (*gMapEventInterface)->getCurCharPos();
    if (lbl_803DCEB8 != -1)
    {
        lbl_803DCDE0 -= 1;
        if ((s8)lbl_803DCDE0 < 0)
        {
            if (lbl_803DCEB8 > -1 && (s8)gRcpWarpTransitionType != 0)
            {
                (*gScreenTransitionInterface)->step(3, 1);
            }
            lbl_803DCEB8 = -1;
            Pause_SetDisabled(0);
        }
    }
    if ((s8)lbl_803DCEBD != 0)
    {
        if ((*gScreenTransitionInterface)->isFinished() != 0 || (s8)gRcpWarpTransitionType == 0)
        {
            (*gCloudActionInterface)->freeCloudObjects();
            (*gCloudActionInterface)->onMapSetup();
            (*gSky2Interface)->onMapSetup();
            (*gSkyInterface)->loadLights();
            (*gNewCloudsInterface)->onMapSetup();
            gameUiResetMenuState();
            lbl_803DCEBD = 0;
            *(f32*)(pos + 0) = ((WarpDestination*)gRcpPendingWarpDest)->x;
            *(f32*)(pos + 4) = ((WarpDestination*)gRcpPendingWarpDest)->y;
            *(f32*)(pos + 8) = ((WarpDestination*)gRcpPendingWarpDest)->z;
            *(s8*)(pos + 0xd) = (s8)((WarpDestination*)gRcpPendingWarpDest)->angle0;
            *(s8*)(pos + 0xc) = (s8)((WarpDestination*)gRcpPendingWarpDest)->angle1;
            mapReload();
            lbl_803DCEB8 = lbl_803DCEBA;
            lbl_803DCEBA = -1;
            lbl_803DCDE0 = 8;
            lbl_803DCA40 = 1;
            blankScreen(1);
        }
    }
}

extern float fastFloorf(float x);
extern f32 gMapBlockWorldSize;
#define MAP_BLOCK_LAYER_COUNT 5
extern u8* gMapBlockLayerTables[MAP_BLOCK_LAYER_COUNT];
extern f32 lbl_803DEBB8;

typedef struct WarpVec
{
    f32 x;
    f32 y;
    f32 z;
    f32 pad;
} WarpVec;

extern WarpVec lbl_80386648[];

int objShouldUnload(u8* obj)
{
    u8* def;
    u8* p;
    u8* src;
    u8** tp;
    int m;
    int keep;
    int bx;
    int bz;
    int k;
    int flags;
    int idx2;
    s8 found;
    f32 x;
    f32 y;
    f32 z;
    f32 dist;

    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    if (def == NULL)
    {
        return 0;
    }
    if (def[4] & 2)
    {
        return 0;
    }
    m = (*gMapEventInterface)->getMapAct(((GameObject*)obj)->anim.mapEventSlot);
    if (m == -1)
    {
        keep = 0;
    }
    else if (m != 0)
    {
        if (m < 9)
        {
            if ((def[3] >> (m - 1)) & 1)
            {
                keep = 0;
            }
            else
            {
                goto keep1;
            }
        }
        else if ((def[5] >> (0x10 - m)) & 1)
        {
            keep = 0;
        }
        else
        {
        keep1:
            keep = 1;
        }
    }
    else
    {
        goto keep1;
    }
    if (keep == 0)
    {
        return 1;
    }
    flags = def[4];
    if (flags & 1)
    {
        return 0;
    }
    if (flags & 0x10)
    {
        return !(u8)(*gMapEventInterface)->getObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, def[6]);
    }
    if (((GameObject*)obj)->pendingParentObj != NULL && ((GameObject*)obj)->seqIndex < 0)
    {
        return 0;
    }
    if (((GameObject*)obj)->ownerObj != NULL)
    {
        return 0;
    }
    if (((GameObject*)obj)->anim.parent == NULL)
    {
        bx = (int)fastFloorf((((GameObject*)obj)->anim.localPosX - playerMapOffsetX) / gMapBlockWorldSize);
        bz = (int)fastFloorf((((GameObject*)obj)->anim.localPosZ - playerMapOffsetZ) / gMapBlockWorldSize);
        if (bx < 0 || bz < 0 || bx >= 0x10 || bz >= 0x10)
        {
            return 1;
        }
        found = 0;
        bx = bx + (bz << 4);
        tp = gMapBlockLayerTables;
        for (k = 0; k < MAP_BLOCK_LAYER_COUNT; k++)
        {
            if (*(s8*)((u8*)bx + (int)*tp) >= 0)
            {
                found = 1;
            }
            tp++;
        }
        if (found == 0)
        {
            return 1;
        }
    }
    flags = def[4];
    if (flags & 0x20)
    {
        return 0;
    }
    if ((flags & 4) && (p = (u8*)Obj_GetPlayerObject()) != NULL && ((GameObject*)obj)->anim.parent == NULL)
    {
        x = *(f32*)(p + 0x18);
        y = *(f32*)(p + 0x1c);
        z = *(f32*)(p + 0x20);
    }
    else
    {
        src = *(u8**)&((GameObject*)obj)->anim.parent;
        if (src != NULL)
        {
            idx2 = (s8)src[0x35] + 1;
        }
        else
        {
            idx2 = 0;
        }
        x = lbl_80386648[idx2].x;
        y = lbl_80386648[idx2].y;
        z = lbl_80386648[idx2].z;
    }
    dist = *(f32*)(obj + 0x3c);
    if (((GameObject*)obj)->anim.parent != NULL)
    {
        x -= ((GameObject*)obj)->anim.localPosX;
        y -= ((GameObject*)obj)->anim.localPosY;
        z -= ((GameObject*)obj)->anim.localPosZ;
    }
    else
    {
        x -= ((GameObject*)obj)->anim.worldPosX;
        y -= ((GameObject*)obj)->anim.worldPosY;
        z -= ((GameObject*)obj)->anim.worldPosZ;
    }
    if (x * x + y * y + z * z < (lbl_803DEBB8 + dist) * (lbl_803DEBB8 + dist))
    {
        return 0;
    }
    return 1;
}

typedef struct GXColor8
{
    u8 r;
    u8 g;
    u8 b;
    u8 a;
} GXColor8;

extern void PSMTXScale(f32* m, f32 x, f32 y, f32 z);
extern void GXSetChanAmbColor(int chan, GXColor8 c);
extern void GXSetChanMatColor(int chan, GXColor8 c);
extern void GXSetTexCopyDst(int w, int h, int fmt, int mip);
extern void modelTextureFn_80089970(int slot);
extern void textureFn_8004ff20(void* asset, f32* mtx, void* out, int p4);
extern void GXCopyTex(void* dst, int clear);
extern void GXPreLoadEntireTexture(void* obj, u32* region);
extern void modelLightStruct_selectObjectLights(int model, int* lights, int max, int* count, int p5);
extern void Camera_ApplyFullViewport(void);
extern u32 gRcpDistortAmbColor;
extern int gRcpDistortMatColor;
extern u8 gRcpDistortGroup;
extern f32 lbl_803DEB80;
extern f32 gRcpScreenWidth;
extern f32 gRcpScreenHeight;

void gxTextureFn_80052efc(void)
{
    union { f32 m[12]; f64 a8; } mtxu;
#define mtx mtxu.m
    int lights[8];
    GXColor8 outColor;
    GXColor8 matColor;
    u8* e;   /* raw u8* + per-site casts are load-bearing: typed decls swap r28/r31 */
    u8* slots;
    int i;
    int clearSlot;
    int k;
    int n;
    int model;
    u8* tex;
    int* lightPtr;

    gxFn_80052dc0();
    PSMTXScale(mtx, lbl_803DEB74, lbl_803DEB80, lbl_803DEB74);
    mtx[3] = lbl_803DEB74;
    mtx[7] = lbl_803DEB74;
    GXLoadTexMtxImm(mtx, 0x1e, 1);
    GXSetChanAmbColor(GX_COLOR0A0, *(GXColor8*)&gRcpDistortAmbColor);
    GXSetChanAmbColor(GX_COLOR1A1, *(GXColor8*)&gRcpDistortAmbColor);
    GXSetTexCopyDst(0x20, 0x20, GX_TF_RGBA8, GX_FALSE);
    modelTextureFn_80089970(2);
    i = 0;
    slots = gRcpDistortSlots;
    for (; i < 6; i++)
    {
        tex = ((RcpDistortSlot*)slots)[i].texture;
        if (((Texture*)tex)->refCount != 0 && ((RcpDistortSlot*)slots)[i].mode == 1 &&
            gRcpDistortGroup == ((RcpDistortSlot*)slots)[i].group)
        {
            matColor.r = (((RcpDistortSlot*)slots)[i].colR * ((RcpDistortSlot*)slots)[i].scaleR) >> 8;
            matColor.g = 0;
            matColor.b = (((RcpDistortSlot*)slots)[i].colB * ((RcpDistortSlot*)slots)[i].scaleB) >> 8;
            matColor.a = 0xff;
            GXSetChanMatColor(4, matColor);
            GXSetChanMatColor(5, matColor);
            textureFn_80052bb4(((RcpDistortSlot*)slots)[i].model, ((RcpDistortSlot*)slots)[i].params);
            resetLotsOfRenderVars();
            textureFn_8004ff20(gRcpDistortTexture, mtx, &outColor, 0);
            textureFn_800528bc();
            lightFn_80052974((f32)(i * 0x20), LastCommandWasRead_803DEB60);
            GXCopyTex(((RcpDistortSlot*)slots)[i].texture + 0x60, 0);
            tex = ((RcpDistortSlot*)slots)[i].texture;
            if (((Texture*)tex)->preloaded != 0)
            {
                GXPreLoadEntireTexture(tex + 0x20, ((Texture*)tex)->tmemAddr);
            }
        }
    }
    resetLotsOfRenderVars();
    textureFn_800524ec(&gRcpDistortMatColor);
    textureFn_800528bc();
    GXSetChanMatColor(0, *(GXColor8*)&gRcpDistortMatColor);
    clearSlot = 5;
    k = 5;
    e = gRcpDistortSlots + 0x8c; /* &slots[5]; +0 texture, +0xe tex refCount, +0x1a group, +0x1b mode */
    for (; k >= 0; k--)
    {
        if (*(u16*)(*(u8**)e + 0xe) != 0 && e[0x1b] == 0 && gRcpDistortGroup == e[0x1a])
        {
            clearSlot = k;
            break;
        }
        e -= 0x1c;
    }
    i = 0;
    for (; i < 6; i++)
    {
        if (((Texture*)((RcpDistortSlot*)slots)[i].texture)->refCount != 0 &&
            ((RcpDistortSlot*)slots)[i].mode == 0 && gRcpDistortGroup == ((RcpDistortSlot*)slots)[i].group)
        {
            int count;
            model = ((RcpDistortSlot*)slots)[i].model;
            modelTextureFn_80089970(2 - (i - 3));
            modelLightStruct_selectObjectLights(model, lights, 8, &count, 4);
            modelLightChannels_reset(1);
            modelLightChannel_configure(0, 0, 0);
            lightPtr = lights;
            for (n = 0; n < count; n++)
            {
                modelLightStruct_loadChannelLight(0, (void*)*lightPtr, model);
                lightPtr++;
            }
            modelLightChannels_applyGXControls();
            lightGetColor(0, &outColor.r, &outColor.g, &outColor.b);
            GXSetChanAmbColor(GX_COLOR0, outColor);
            lightFn_80052974((f32)(i * 0x20), LastCommandWasRead_803DEB60);
            GXCopyTex(((RcpDistortSlot*)slots)[i].texture + 0x60, (i == clearSlot) ? 1 : 0);
            tex = ((RcpDistortSlot*)slots)[i].texture;
            if (((Texture*)tex)->preloaded != 0)
            {
                GXPreLoadEntireTexture(tex + 0x20, ((Texture*)tex)->tmemAddr);
            }
        }
    }
    GXSetViewport(LastCommandWasRead_803DEB60, LastCommandWasRead_803DEB60, gRcpScreenWidth,
                  gRcpScreenHeight, LastCommandWasRead_803DEB60, lbl_803DEB5C);
    GXSetScissor(0, 0, 0x280, 0x1e0);
    GXSetDispCopySrc(0, 0, 0x280, 0x1e0);
    GXSetDispCopyDst(0x280, 0x1e0);
    GXSetTexCopySrc(0, 0, 0x280, 0x1e0);
    Camera_ApplyFullViewport();
    gRcpDistortGroup = 0;
}
#undef mtx

extern void OSReport(const char* msg, ...);
extern void printHeapStats(int mode);
extern int mmSetFreeDelay(int v);
extern void defragMemory(int mode);
extern char sRcpTexRestructStrings[];

void texRestructRefs(int mode)
{
    u8* na;
    int i;
    char* strs;
    int done;
    int pass;
    u8* tex;
    int off;
    u32 size;
    int d;

    /* gLoadedTextures walks below keep the byte-offset (off += 16) launder
     * form - plain gLoadedTextures[i].field indexing diverges (induction-var
     * shape). */
    strs = (char*)(int)sRcpTexRestructStrings;
    done = 0;
    pass = 0;
    texFlagFn_80023cbc(2);
    OSReport(strs + 0x1164);
    printHeapStats(1);
    OSReport(strs + 0x1194);
    testAndSet_onlyUseHeaps1and2(1);
    off = 0;
    i = 0;
    for (off = 0; i < gLoadedTextureCount; off += 16, i++)
    {
        tex = ((LoadedTextureEntry*)((u8*)gLoadedTextures + off))->texture;
        if (tex != NULL && ((LoadedTextureEntry*)((u8*)gLoadedTextures + off))->flag != 0 &&
            ((Texture*)tex)->cached == 0 &&
            (int)((LoadedTextureEntry*)((u8*)gLoadedTextures + off))->size != -1 &&
            mmGetRegionForPtr(tex) == 0 && *(void**)tex == NULL)
        {
            size = ((LoadedTextureEntry*)((u8*)gLoadedTextures + off))->size;
            na = (u8*)mmAlloc(size, 0xa0a0a0a0, 0);
            if (na == NULL)
            {
                OSReport(strs + 0x11b4, tex, getHeapItemSize(tex));
            }
            else if (na != NULL)
            {
                OSReport(strs + 0x11f4, tex, na, getHeapItemSize(tex));
                done = 0;
                memcpy(na, tex, size);
                DCStoreRange(na, size);
                textureFn_80053d58(na);
                d = mmSetFreeDelay(0);
                mm_free(((LoadedTextureEntry*)((u8*)gLoadedTextures + off))->texture);
                mmSetFreeDelay(d);
                ((LoadedTextureEntry*)((u8*)gLoadedTextures + off))->texture = na;
            }
        }
    }
    testAndSet_onlyUseHeaps1and2(-1);
    OSReport(strs + 0x1238);
    printHeapStats(1);
    defragMemory(2);
    while (done == 0 && pass < 4)
    {
        done = 1;
        i = 0;
        off = i;
        for (; i < gLoadedTextureCount; off += 16, i++)
        {
            tex = ((LoadedTextureEntry*)((u8*)gLoadedTextures + off))->texture;
            if (tex != NULL && ((LoadedTextureEntry*)((u8*)gLoadedTextures + off))->flag != 0 &&
                ((Texture*)tex)->cached == 0 &&
                (int)((LoadedTextureEntry*)((u8*)gLoadedTextures + off))->size != -1)
            {
                if (mmGetRegionForPtr(tex) == 0 && *(void**)tex == NULL)
                {
                    size = ((LoadedTextureEntry*)((u8*)gLoadedTextures + off))->size;
                    na = (u8*)mmAlloc(size, 0xa0a0a0a0, 0);
                    if (na == NULL)
                    {
                        OSReport(strs + 0x125c, tex, getHeapItemSize(tex));
                    }
                    else if (mmGetRegionForPtr(na) != 0)
                    {
                        OSReport(strs + 0x129c, tex, na, getHeapItemSize(tex));
                        d = mmSetFreeDelay(0);
                        mm_free(na);
                        mmSetFreeDelay(d);
                    }
                    else if (na < tex)
                    {
                        OSReport(strs + 0x12d8, tex, na, getHeapItemSize(tex));
                        d = mmSetFreeDelay(0);
                        mm_free(na);
                        mmSetFreeDelay(d);
                    }
                    else if (na != NULL)
                    {
                        OSReport(strs + 0x1320, tex, na, getHeapItemSize(tex));
                        done = 0;
                        memcpy(na, tex, size);
                        DCStoreRange(na, size);
                        textureFn_80053d58(na);
                        d = mmSetFreeDelay(0);
                        mm_free(((LoadedTextureEntry*)((u8*)gLoadedTextures + off))->texture);
                        mmSetFreeDelay(d);
                        ((LoadedTextureEntry*)((u8*)gLoadedTextures + off))->texture = na;
                    }
                }
                else if (mode == 0)
                {
                    if (mmGetRegionForPtr(tex) == 1 || mmGetRegionForPtr(tex) == 2)
                    {
                        if (*(void**)tex == NULL && getHeapItemSize(tex) >= 0x3000)
                        {
                            size = ((LoadedTextureEntry*)((u8*)gLoadedTextures + off))->size;
                            na = (u8*)mmAlloc(size, 0xa0a0a0a0, 0);
                            if (na == NULL)
                            {
                                OSReport(strs + 0x125c, tex, getHeapItemSize(tex));
                            }
                            else if (mmGetRegionForPtr(na) != 0)
                            {
                                OSReport(strs + 0x1368, tex, na, getHeapItemSize(tex));
                                d = mmSetFreeDelay(0);
                                mm_free(na);
                                mmSetFreeDelay(d);
                            }
                            else if (na != NULL)
                            {
                                OSReport(strs + 0x13c8, tex, na, getHeapItemSize(tex));
                                done = 0;
                                memcpy(na, tex, size);
                                DCStoreRange(na, size);
                                textureFn_80053d58(na);
                                d = mmSetFreeDelay(0);
                                mm_free(((LoadedTextureEntry*)((u8*)gLoadedTextures + off))->texture);
                                mmSetFreeDelay(d);
                                ((LoadedTextureEntry*)((u8*)gLoadedTextures + off))->texture = na;
                            }
                        }
                    }
                }
            }
        }
        printHeapStats(1);
        pass++;
    }
    OSReport(strs + 0x1420, pass);
    texFlagFn_80023cbc(0);
}

extern char sDebugIntLineFormat;
extern u8 gRcpTexAllocFailed;
extern u32 gRcpTexAllocTag;
extern int OSDisableInterrupts(void);
extern asm BOOL OSRestoreInterrupts(register BOOL level);
extern void tex0GetFrame(int word, int id, int* sizeOut, int* frameOut, int mip, void* hdr, int mode);
extern void tex1GetFrame(int word, int id, int* sizeOut, int* frameOut, int mip, void* hdr, int mode);
extern void texPreGetMipmap(int word, int id, int* sizeOut, int* frameOut, int mip, void* hdr, int mode);

#pragma opt_propagation off
void* textureLoad(int texId, u8 flagIn)
{
    int restore;
    int disabled;
    u8 flag;
    int file;
    int bank;
    int id16;
    u32 size;
    u8* buf;
    u8* firstTex;
    u8* prevTex;
    int slot;
    LoadedTextureEntry* entry;
    u8* walk;
    int bankWord;
    int bankWordSaved;
    int bankWordHeld;
    int origTexId;
    int mipChainWord;
    u16 remapped;
    int dataByteOffset;
    int mips;
    int mipLevel;
    int frameSize;
    int n;
    int* bankPtr;
    int sizeOut;
    int frameOut;

    flag = flagIn;
    restore = 1;
    disabled = 0;
    if (texId < 0)
    {
        n = -texId;
        if (n & 0x8000)
        {
            slot = n & 0x7fff;
            if (slot == 0x82e)
            {
                OSReport(&sDebugIntLineFormat);
            }
        }
    }
    n = 0;
    entry = gLoadedTextures;
    for (; n < gLoadedTextureCount; n++, entry++)
    {
        if (texId == entry->key)
        {
            buf = gLoadedTextures[n].texture;
            ((Texture*)buf)->refCount += 1;
            if (flag != 0 && gLoadedTextures[n].flag != 0)
            {
                return (void*)(n + 1);
            }
            return buf;
        }
    }
    if (getLoadedFileFlags(0) != 0)
    {
        restore = OSDisableInterrupts();
        disabled = 1;
    }
    origTexId = texId;
    if (texId < 0)
    {
        texId = -texId;
    }
    else
    {
        if (texId >= 0xbb8)
        {
            remapped = gRcpTexIdRemap[texId];
            if (remapped != 0)
            {
                texId = remapped + 1;
                goto resolved;
            }
        }
        texId = gRcpTexIdRemap[texId];
    }
resolved:
    id16 = texId & 0xffff;
    if (texId & 0x8000)
    {
        bank = 1;
        file = 0x20;
        id16 = id16 & 0x7fff;
    }
    else if (origTexId >= 0xbb8)
    {
        bank = 2;
        file = 0x4f;
    }
    else
    {
        bank = 0;
        file = 0x23;
    }
    if (id16 >= gRcpTexBankCount[bank] || id16 < 0)
    {
        id16 = 0;
    }
    n = 0;
    bankPtr = getCurrentDataFile(0x24);
    gRcpTexBankTable[0] = bankPtr;
    if (gRcpTexBankTable != NULL)
        goto countBank0;
    goto doneBank0;
countBank0:
    while (*bankPtr != -1)
    {
        bankPtr++;
        n++;
    }
    gRcpTexBankCount[0] = n - 1;
doneBank0:
    n = 0;
    bankPtr = getCurrentDataFile(0x21);
    gRcpTexBankTable[1] = bankPtr;
    if (gRcpTexBankTable != NULL)
        goto countBank1;
    goto doneBank1;
countBank1:
    while (*bankPtr != -1)
    {
        bankPtr++;
        n++;
    }
    gRcpTexBankCount[1] = n - 1;
doneBank1:
    bankWord = gRcpTexBankTable[bank][id16];
    mips = (bankWord >> 24) & 0x3f;
    bankWordSaved = bankWord;
    if (mips == 1)
    {
        if (bank == 0)
        {
            tex0GetFrame(bankWord, id16, &sizeOut, &frameOut, mips, 0, 0);
        }
        else if (bank == 2)
        {
            texPreGetMipmap(bankWord, id16, &sizeOut, &frameOut, mips, 0, 0);
        }
        else
        {
            tex1GetFrame(bankWord, id16, &sizeOut, &frameOut, mips, 0, 0);
        }
        *(int*)gRcpTexHeaderBuffer = 0;
        *((int*)gRcpTexHeaderBuffer + 1) = sizeOut;
        if (frameOut == -1)
        {
            *((int*)gRcpTexHeaderBuffer + 2) = sizeOut;
        }
        else
        {
            *((int*)gRcpTexHeaderBuffer + 2) = frameOut;
        }
    }
    else if (bank == 0)
    {
        tex0GetFrame(bankWord, id16, &sizeOut, &frameOut, mips, gRcpTexHeaderBuffer, 2);
    }
    else if (bank == 2)
    {
        texPreGetMipmap(bankWord, id16, &sizeOut, &frameOut, mips, gRcpTexHeaderBuffer, 2);
    }
    else
    {
        tex1GetFrame(bankWord, id16, &sizeOut, &frameOut, mips, gRcpTexHeaderBuffer, 2);
    }
    firstTex = NULL;
    prevTex = NULL;
    mipLevel = 0;
    bankWordHeld = bankWordSaved;
    mipChainWord = mips << 8;
    dataByteOffset = (bankWordSaved & 0xffffff) << 1;
    for (; mipLevel < mips; mipLevel++)
    {
        if (mips > 1)
        {
            if (bank == 0)
            {
                tex0GetFrame(bankWordHeld, id16, &sizeOut, &frameOut, mipLevel, gRcpTexHeaderBuffer, 1);
            }
            else if (bank == 2)
            {
                texPreGetMipmap(bankWordHeld, id16, &sizeOut, &frameOut, mipLevel, gRcpTexHeaderBuffer, 1);
            }
            else
            {
                tex1GetFrame(bankWordHeld, id16, &sizeOut, &frameOut, mipLevel, gRcpTexHeaderBuffer, 1);
            }
        }
        size = sizeOut;
        if (frameOut == -1)
        {
            frameSize = sizeOut;
        }
        else
        {
            frameSize = frameOut;
            texFlagFn_80023cbc(1);
            buf = (u8*)mmAlloc(size, gRcpTexAllocTag, 0);
            texFlagFn_80023cbc(0);
            if (buf == NULL)
            {
                gRcpTexAllocFailed = 1;
                if (getLoadedFileFlags(0) != 0)
                {
                    if (disabled == 1)
                    {
                        OSRestoreInterrupts(restore);
                    }
                }
                else if (disabled == 1)
                {
                    OSRestoreInterrupts(restore);
                }
                if (flag != 0)
                {
                    return (void*)1;
                }
                return gLoadedTextures[0].texture;
            }
        }
        if (frameOut != -1 && buf == NULL)
        {
            if (mipLevel == 0)
            {
                gRcpTexAllocFailed = 1;
                if (getLoadedFileFlags(0) != 0)
                {
                    if (disabled == 1)
                    {
                        OSRestoreInterrupts(restore);
                    }
                }
                else if (disabled == 1)
                {
                    OSRestoreInterrupts(restore);
                }
                if (flag != 0)
                {
                    return (void*)1;
                }
                return gLoadedTextures[0].texture;
            }
            else
            {
                *(u16*)(firstTex + 0x10) = mipChainWord;
                mipLevel = mips;
                continue;
            }
        }
        if (frameOut == -1)
        {
            buf = (u8*)loadAndDecompressDataFile(file, 0, dataByteOffset + ((int*)gRcpTexHeaderBuffer)[mipLevel], frameSize, 0,
                                                 id16, 0);
            buf[0x49] = 1;
            if (flag != 0)
            {
                flag = 0;
            }
            *(u16*)(buf + 0xe) = 1;
        }
        else
        {
            loadAndDecompressDataFile(file, (int)buf, dataByteOffset + ((int*)gRcpTexHeaderBuffer)[mipLevel], frameSize, 0, id16,
                                      0);
        }
        if (frameOut != -1)
        {
            DCStoreRange(buf, size);
        }
        *(void**)buf = NULL;
        if (prevTex != NULL)
        {
            *(u8**)prevTex = buf;
        }
        prevTex = buf;
        if (mipLevel == 0)
        {
            firstTex = buf;
            *(u16*)(buf + 0x10) = mipChainWord;
        }
        else
        {
            *(u16*)(buf + 0x10) = 1;
        }
    }
    walk = firstTex;
    *(u32*)(firstTex + 0x4c) = size;
    slot = 0;
    entry = gLoadedTextures;
    for (; slot < gLoadedTextureCount; slot++, entry++)
    {
        if (entry->key == -1)
        {
            break;
        }
    }
    if (slot == gLoadedTextureCount)
    {
        gLoadedTextureCount += 1;
    }
    gLoadedTextures[slot].key = origTexId;
    gLoadedTextures[slot].texture = firstTex;
    gLoadedTextures[slot].flag = flag;
    gLoadedTextures[slot].size = getHeapItemSize(gLoadedTextures[slot].texture);
    if (gLoadedTextureCount > 0x2bc)
    {
        if (getLoadedFileFlags(0) != 0)
        {
            if (disabled == 1)
            {
                OSRestoreInterrupts(restore);
            }
        }
        else if (disabled == 1)
        {
            OSRestoreInterrupts(restore);
        }
        if (flag != 0)
        {
            return (void*)1;
        }
        return gLoadedTextures[0].texture;
    }
    while (walk != NULL)
    {
        textureFn_80053d58(walk);
        walk = *(u8**)walk;
    }
    if (getLoadedFileFlags(0) != 0)
    {
        if (disabled == 1)
        {
            OSRestoreInterrupts(restore);
        }
    }
    else if (disabled == 1)
    {
        OSRestoreInterrupts(restore);
    }
    if (flag != 0)
    {
        return (void*)(slot + 1);
    }
    return firstTex;
}
#pragma opt_propagation reset

char sRcpTexRestructStrings[] = {
    0xFC, 0x12, 0x16, 0x03, 0xFF, 0xFF, 0xFF, 0xF8,
    0xFC, 0x12, 0x16, 0x03, 0xFF, 0xFF, 0xFF, 0xF8,
};
extern u32 lbl_8030D068[];
extern u32 lbl_8030D0E8[];
extern u32 lbl_8030D168[];
extern u32 lbl_8030D178[];
extern u32 lbl_8030D1F8[];
extern u32 lbl_8030D208[];
extern u32 lbl_8030D288[];
extern u32 lbl_8030D298[];
extern u32 lbl_8030D318[];
extern u32 lbl_8030D328[];
extern u32 lbl_8030D368[];
extern u32 lbl_8030D378[];
extern u32 lbl_8030D3B8[];
extern u32 lbl_8030D3C8[];
extern u32 lbl_8030D408[];
extern u32 lbl_8030D418[];
extern u32 lbl_8030D458[];
extern u32 lbl_8030D468[];
extern u32 lbl_8030D4E8[];
extern u32 lbl_8030D4F8[];
extern u32 lbl_8030D578[];
extern u32 lbl_8030D588[];
extern u32 lbl_8030D598[];
extern u32 lbl_8030D5A8[];
extern u32 lbl_8030D5B8[];
extern u32 lbl_8030D5C8[];
extern u32 lbl_8030D648[];
extern u32 lbl_8030D6C8[];
extern u32 lbl_8030D748[];
extern u32 lbl_8030D758[];
extern u32 lbl_8030D7D8[];
extern u32 lbl_8030D858[];
extern u32 lbl_8030D868[];
extern u32 lbl_8030D8E8[];
extern u32 lbl_8030D8F8[];
extern u32 lbl_8030D978[];
extern u32 lbl_8030D9B8[];
extern u32 lbl_8030D9C8[];
extern u32 lbl_8030DA48[];
extern u32 lbl_8030DA58[];
extern u32 lbl_8030DAD8[];
extern u32 lbl_8030DAE8[];
extern u32 lbl_8030DB68[];
extern u32 lbl_8030DB78[];
extern u32 lbl_8030DBF8[];
extern u32 lbl_8030DC08[];

u32 lbl_8030D068[32] = { 0xef182c00, 0x03024000, 0xef182c00, 0x00112008, 0xef182c00, 0x00112230, 0xef182c00, 0x00112038, 0xef182c00, 0x00104240, 0xef182c00, 0x001041c8, 0xef182c00, 0x00104a50, 0xef182c00, 0x001049d8, 0xef182c00, 0xcb024000, 0xef182c00, 0xc8112008, 0xef182c00, 0xc8112230, 0xef182c00, 0xc8112038, 0xef182c00, 0xc8104240, 0xef182c00, 0xc81041c8, 0xef182c00, 0xc8104a50, 0xef182c00, 0xc81049d8 };
u32 lbl_8030D0E8[32] = { 0xef182c00, 0x03024000, 0xef182c00, 0x00112008, 0xef182c00, 0x00112230, 0xef182c00, 0x00112038, 0xef182c00, 0x00104340, 0xef182c00, 0x00104340, 0xef182c00, 0x00104b50, 0xef182c00, 0x00104b50, 0xef182c00, 0xcb024000, 0xef182c00, 0xc8112008, 0xef182c00, 0xc8112230, 0xef182c00, 0xc8112038, 0xef182c00, 0xc8104340, 0xef182c00, 0xc8104340, 0xef182c00, 0xc8104b50, 0xef182c00, 0xc8104b50 };
u32 lbl_8030D168[4] = { 0xfc41ffff, 0xfffff638, 0xfc41ffff, 0xfffff638 };
u32 lbl_8030D178[32] = { 0xef180c00, 0x03024000, 0xef180c00, 0x00112008, 0xef180c00, 0x00112230, 0xef180c00, 0x00112038, 0xef180c00, 0x00104240, 0xef180c00, 0x001041c8, 0xef180c00, 0x00104a50, 0xef180c00, 0x001049d8, 0xef180c00, 0xcb024000, 0xef180c00, 0xc8112008, 0xef180c00, 0xc8112230, 0xef180c00, 0xc8112038, 0xef180c00, 0xc8104240, 0xef180c00, 0xc81041c8, 0xef180c00, 0xc8104a50, 0xef180c00, 0xc81049d8 };
u32 lbl_8030D1F8[4] = { 0xfc121803, 0xff0fffff, 0xfc121803, 0xff0fffff };
u32 lbl_8030D208[32] = { 0xef182c00, 0x00104240, 0xef182c00, 0x001041c8, 0xef182c00, 0x00104a50, 0xef182c00, 0x001049d8, 0xef182c00, 0x00104240, 0xef182c00, 0x001041c8, 0xef182c00, 0x00104a50, 0xef182c00, 0x001049d8, 0xef182c00, 0x00104240, 0xef182c00, 0x001041c8, 0xef182c00, 0x00104a50, 0xef182c00, 0x001049d8, 0xef182c00, 0x00104240, 0xef182c00, 0x001041c8, 0xef182c00, 0x00104a50, 0xef182c00, 0x001049d8 };
u32 lbl_8030D288[4] = { 0xfc41c683, 0xff8fffff, 0xfc41c683, 0xff8fffff };
u32 lbl_8030D298[32] = { 0xef080c00, 0x0c184240, 0xef080c00, 0x005461c8, 0xef080c00, 0x00546a70, 0xef080c00, 0x005469f8, 0xef080c00, 0x00504240, 0xef080c00, 0x005041c8, 0xef080c00, 0x00504a50, 0xef080c00, 0x005049d8, 0xef080c00, 0x0c184240, 0xef080c00, 0x005461c8, 0xef080c00, 0x00546a70, 0xef080c00, 0x005469f8, 0xef080c00, 0x00504240, 0xef080c00, 0x005041c8, 0xef080c00, 0x00504a50, 0xef080c00, 0x005049d8 };
u32 lbl_8030D318[4] = { 0xfc12160b, 0xfffffff8, 0xfc12160b, 0xfffffff8 };
u32 lbl_8030D328[16] = { 0xef182c00, 0x03024000, 0xef182c00, 0x00112008, 0xef182c00, 0x00112230, 0xef182c00, 0x00112038, 0xef182c00, 0x00104240, 0xef182c00, 0x001041c8, 0xef182c00, 0x00104a50, 0xef182c00, 0x001049d8 };
u32 lbl_8030D368[4] = { 0xfc45ffff, 0xfffff638, 0xfc45ffff, 0xfffff638 };
u32 lbl_8030D378[16] = { 0xef180c00, 0x03024000, 0xef180c00, 0x00112008, 0xef180c00, 0x00112230, 0xef180c00, 0x00112038, 0xef180c00, 0x00104240, 0xef180c00, 0x001041c8, 0xef180c00, 0x00104a50, 0xef180c00, 0x001049d8 };
u32 lbl_8030D3B8[4] = { 0xfc12166b, 0xf0fffe38, 0xfc12166b, 0xf0fffe38 };
u32 lbl_8030D3C8[16] = { 0xef182c00, 0x03024000, 0xef182c00, 0x00112008, 0xef182c00, 0x00112230, 0xef182c00, 0x00112038, 0xef182c00, 0x00104240, 0xef182c00, 0x001041c8, 0xef182c00, 0x00104a50, 0xef182c00, 0x001049d8 };
u32 lbl_8030D408[4] = { 0xfc35ffff, 0x4ffc7638, 0xfc35ffff, 0x4ffc7638 };
u32 lbl_8030D418[16] = { 0xef180c00, 0x03024000, 0xef180c00, 0x00112008, 0xef180c00, 0x00112230, 0xef180c00, 0x00112038, 0xef180c00, 0x00104240, 0xef180c00, 0x001041c8, 0xef180c00, 0x00104a50, 0xef180c00, 0x001049d8 };
u32 lbl_8030D458[4] = { 0xfc26a04d, 0x11409249, 0xfc26a004, 0x1f0c93ff };
u32 lbl_8030D468[32] = { 0xef192c00, 0x03024000, 0xef192c00, 0x00112008, 0xef192c00, 0x00112230, 0xef192c00, 0x00112038, 0xef192c00, 0x00104240, 0xef192c00, 0x001041c8, 0xef192c00, 0x00104a50, 0xef192c00, 0x001049d8, 0xef192c00, 0xcb024000, 0xef192c00, 0xc8112008, 0xef192c00, 0xc8112230, 0xef192c00, 0xc8112038, 0xef192c00, 0xc8104240, 0xef192c00, 0xc81041c8, 0xef192c00, 0xc8104a50, 0xef192c00, 0xc81049d8 };
u32 lbl_8030D4E8[4] = { 0xfc22aa04, 0x1f0c93ff, 0xfc22aa04, 0x1f0c93ff };
u32 lbl_8030D4F8[32] = { 0xef182c00, 0x03024000, 0xef182c00, 0x00112008, 0xef182c00, 0x00112230, 0xef182c00, 0x00112038, 0xef182c00, 0x00104240, 0xef182c00, 0x001041c8, 0xef182c00, 0x00104a50, 0xef182c00, 0x001049d8, 0xef182c00, 0xcb024000, 0xef182c00, 0xc8112008, 0xef182c00, 0xc8112230, 0xef182c00, 0xc8112038, 0xef182c00, 0xc8104240, 0xef182c00, 0xc81041c8, 0xef182c00, 0xc8104a50, 0xef182c00, 0xc81049d8 };
u32 lbl_8030D578[4] = { 0xfc22aa04, 0x1f1093ff, 0xfc22aa04, 0x1f1093ff };
u32 lbl_8030D588[4] = { 0xfc25a804, 0x1f0c93ff, 0xfc25a804, 0x1f0c93ff };
u32 lbl_8030D598[4] = { 0xfc25a803, 0x1f0c93ff, 0xfc25a803, 0x1f0c93ff };
u32 lbl_8030D5A8[4] = { 0xfc119623, 0xff2fffff, 0xfc1196ac, 0xf0fffe38 };
u32 lbl_8030D5B8[4] = { 0xfc367ea0, 0x5f0ef3ff, 0xfc367ea0, 0x5f0ef3ff };
u32 lbl_8030D5C8[32] = { 0xef082c00, 0x00504240, 0xef082c00, 0x005041c8, 0xef082c00, 0x00553078, 0xef082c00, 0x005045d8, 0xef082c00, 0x00504240, 0xef082c00, 0x005041c8, 0xef082c00, 0x00553078, 0xef082c00, 0x005045d8, 0xef182c00, 0xc8104240, 0xef182c00, 0xc81041c8, 0xef182c00, 0xc8113078, 0xef182c00, 0xc81045d8, 0xef182c00, 0xc8104240, 0xef182c00, 0xc81041c8, 0xef182c00, 0xc81045f8, 0xef182c00, 0xc81045d8 };
u32 lbl_8030D648[32] = { 0xef080c00, 0x00504240, 0xef080c00, 0x005041c8, 0xef080c00, 0x00553078, 0xef080c00, 0x005045d8, 0xef080c00, 0x00504240, 0xef080c00, 0x005041c8, 0xef080c00, 0x00553078, 0xef080c00, 0x005045d8, 0xef180c00, 0xc8104240, 0xef180c00, 0xc81041c8, 0xef180c00, 0xc8113078, 0xef180c00, 0xc81045d8, 0xef180c00, 0xc8104240, 0xef180c00, 0xc81041c8, 0xef180c00, 0xc81045f8, 0xef180c00, 0xc81045d8 };
u32 lbl_8030D6C8[32] = { 0xef082c80, 0x00504240, 0xef082c80, 0x005041c8, 0xef082c80, 0x00553078, 0xef082c80, 0x00504b50, 0xef082c80, 0x00504240, 0xef082c80, 0x005041c8, 0xef082c80, 0x00553078, 0xef082c80, 0x00504b50, 0xef182c80, 0xc8104240, 0xef182c80, 0xc81041c8, 0xef182c80, 0xc8113078, 0xef182c80, 0xc8104b50, 0xef182c80, 0xc8104240, 0xef182c80, 0xc81041c8, 0xef182c80, 0xc81045f8, 0xef182c80, 0xc8104b50 };
u32 lbl_8030D748[4] = { 0xfc22aa04, 0x1f0c93ff, 0xfc22aa04, 0x1f0c93ff };
u32 lbl_8030D758[32] = { 0xef182c00, 0x00104240, 0xef182c00, 0x001041c8, 0xef182c00, 0x00113078, 0xef182c00, 0x001045d8, 0xef182c00, 0x00104240, 0xef182c00, 0x001041c8, 0xef182c00, 0x001045f8, 0xef182c00, 0x001045d8, 0xef182c00, 0xc8104240, 0xef182c00, 0xc81041c8, 0xef182c00, 0xc8113078, 0xef182c00, 0xc81045d8, 0xef182c00, 0xc8104240, 0xef182c00, 0xc81041c8, 0xef182c00, 0xc81045f8, 0xef182c00, 0xc81045d8 };
u32 lbl_8030D7D8[32] = { 0xef180c00, 0x00104240, 0xef180c00, 0x001041c8, 0xef180c00, 0x00113078, 0xef180c00, 0x001045d8, 0xef180c00, 0x00104240, 0xef180c00, 0x001041c8, 0xef180c00, 0x001045f8, 0xef180c00, 0x001045d8, 0xef180c00, 0xc8104240, 0xef180c00, 0xc81041c8, 0xef180c00, 0xc8113078, 0xef180c00, 0xc81045d8, 0xef180c00, 0xc8104240, 0xef180c00, 0xc81041c8, 0xef180c00, 0xc81045f8, 0xef180c00, 0xc81045d8 };
u32 lbl_8030D858[4] = { 0xfc121603, 0xfffffff8, 0xfc121603, 0xfffffff8 };
u32 lbl_8030D868[32] = { 0xef182c00, 0x00112e10, 0xef182c00, 0x00112d18, 0xef182c00, 0x00112e10, 0xef182c00, 0x00112d18, 0xef182c00, 0x00104e50, 0xef182c00, 0x00104dd8, 0xef182c00, 0x00104e50, 0xef182c00, 0x00104dd8, 0xef182c00, 0xc8112e10, 0xef182c00, 0xc8112d18, 0xef182c00, 0xc8112e10, 0xef182c00, 0xc8112d18, 0xef182c00, 0xc8104e50, 0xef182c00, 0xc8104dd8, 0xef182c00, 0xc8104e50, 0xef182c00, 0xc8104dd8 };
u32 lbl_8030D8E8[4] = { 0xfc121603, 0xfffffff8, 0xfc121603, 0xfffffff8 };
u32 lbl_8030D8F8[32] = { 0xef182c00, 0x00104240, 0xef182c00, 0x001041c8, 0xef182c00, 0x00111338, 0xef182c00, 0x00111038, 0xef182c00, 0x00104240, 0xef182c00, 0x001041c8, 0xef182c00, 0x00111338, 0xef182c00, 0x00111038, 0xef182c00, 0xc8104240, 0xef182c00, 0xc81041c8, 0xef182c00, 0xc8111338, 0xef182c00, 0xc8111038, 0xef182c00, 0xc8104240, 0xef182c00, 0xc81041c8, 0xef182c00, 0xc8111338, 0xef182c00, 0xc8111038 };
u32 lbl_8030D978[16] = { 0xef182c00, 0xc8104240, 0xef182c00, 0xc81041c8, 0xef182c00, 0xc8113078, 0xef182c00, 0xc8105858, 0xef182c00, 0xc8104240, 0xef182c00, 0xc81041c8, 0xef182c00, 0xc8113078, 0xef182c00, 0xc8105858 };
u32 lbl_8030D9B8[4] = { 0xfc121803, 0xff0fffff, 0xfc121803, 0xff0fffff };
u32 lbl_8030D9C8[32] = { 0xef182c00, 0x00104e50, 0xef182c00, 0x00104dd8, 0xef182c00, 0x00104e50, 0xef182c00, 0x00104dd8, 0xef182c00, 0x00104b50, 0xef182c00, 0x00104b50, 0xef182c00, 0x00104b50, 0xef182c00, 0x00104b50, 0xef182c00, 0x00104e50, 0xef182c00, 0x00104dd8, 0xef182c00, 0x00104e50, 0xef182c00, 0x00104dd8, 0xef182c00, 0x00104b50, 0xef182c00, 0x00104b50, 0xef182c00, 0x00104b50, 0xef182c00, 0x00104b50 };
u32 lbl_8030DA48[4] = { 0xfc26a004, 0x1f1093ff, 0xfc26a004, 0x1f1093ff };
u32 lbl_8030DA58[32] = { 0xef192c00, 0x00104e50, 0xef192c00, 0x00104dd8, 0xef192c00, 0x00104e50, 0xef192c00, 0x00104dd8, 0xef192c00, 0x00104a50, 0xef192c00, 0x001049d8, 0xef192c00, 0x00104a50, 0xef192c00, 0x001049d8, 0xef192c00, 0x00104e50, 0xef192c00, 0x00104dd8, 0xef192c00, 0x00104e50, 0xef192c00, 0x00104dd8, 0xef192c00, 0x00104a50, 0xef192c00, 0x001049d8, 0xef192c00, 0x00104a50, 0xef192c00, 0x001049d8 };
u32 lbl_8030DAD8[4] = { 0xfc121603, 0xff0fffff, 0xfc121603, 0xff0fffff };
u32 lbl_8030DAE8[32] = { 0xef182c00, 0x03024000, 0xef182c00, 0x00112248, 0xef182c00, 0x00112230, 0xef182c00, 0x00112278, 0xef182c00, 0x00104240, 0xef182c00, 0x001041c8, 0xef182c00, 0x00104a50, 0xef182c00, 0x001049d8, 0xef182c00, 0xcb024000, 0xef182c00, 0xc8112248, 0xef182c00, 0xc8112230, 0xef182c00, 0xc8112278, 0xef182c00, 0xc8104240, 0xef182c00, 0xc81041c8, 0xef182c00, 0xc8104a50, 0xef182c00, 0xc81049d8 };
u32 lbl_8030DB68[4] = { 0xfc26a004, 0x1f0c93ff, 0xfc26a004, 0x1f0c93ff };
u32 lbl_8030DB78[32] = { 0xef192c00, 0x03024000, 0xef192c00, 0x00112248, 0xef192c00, 0x00112230, 0xef192c00, 0x00112278, 0xef192c00, 0x00104240, 0xef192c00, 0x001041c8, 0xef192c00, 0x00104a50, 0xef192c00, 0x001049d8, 0xef192c00, 0xcb024000, 0xef192c00, 0xc8112248, 0xef192c00, 0xc8112230, 0xef192c00, 0xc8112278, 0xef192c00, 0xc8104240, 0xef192c00, 0xc81041c8, 0xef192c00, 0xc8104a50, 0xef192c00, 0xc81049d8 };
u32 lbl_8030DBF8[4] = { 0xfc55fe04, 0x1ffcfdfe, 0xfc55fe04, 0x1ffcfdfe };
u32 lbl_8030DC08[554] = { 0xef182c00, 0x03024000, 0xef182c00, 0x00112008, 0xef182c00, 0x00112230, 0xef182c00, 0x00112038, 0xef182c00, 0x00104240, 0xef182c00, 0x001041c8, 0xef182c00, 0x00104a50, 0xef182c00, 0x001049d8, 0xef182c00, 0x03024000, 0xef182c00, 0x00112008, 0xef182c00, 0x00112230, 0xef182c00, 0x00112038, 0xef182c00, 0x00104240, 0xef182c00, 0x001041c8, 0xef182c00, 0x00104a50, 0xef182c00, 0x001049d8, (u32)sRcpTexRestructStrings, (u32)lbl_8030D068, 0x0000000f, 0x00000000, (u32)lbl_8030D1F8, (u32)lbl_8030D208, 0x00000007, 0x00000004, (u32)lbl_8030D318, (u32)lbl_8030D328, 0x00000007, 0x00000000, (u32)lbl_8030D3B8, (u32)lbl_8030D3C8, 0x00000007, 0x00000000, (u32)lbl_8030D4E8, (u32)lbl_8030D4F8, 0x0000000f, 0x00000000, (u32)lbl_8030D578, (u32)lbl_8030D4F8, 0x00000007, 0x00000004, (u32)lbl_8030D588, (u32)lbl_8030D4F8, 0x00000007, 0x00000000, (u32)lbl_8030D598, (u32)lbl_8030D4F8, 0x00000007, 0x00000000, (u32)lbl_8030D858, (u32)lbl_8030D868, 0x0000000f, 0x00000002, (u32)lbl_8030D858, (u32)lbl_8030D868, 0x0000000f, 0x00000002, (u32)lbl_8030D858, (u32)lbl_8030D868, 0x0000000f, 0x00000002, (u32)lbl_8030D858, (u32)lbl_8030D868, 0x0000000f, 0x00000002, (u32)lbl_8030D4E8, (u32)lbl_8030D868, 0x0000000f, 0x00000002, (u32)lbl_8030D578, (u32)lbl_8030D868, 0x0000000f, 0x00000006, (u32)lbl_8030D588, (u32)lbl_8030D868, 0x0000000f, 0x00000002, (u32)lbl_8030D598, (u32)lbl_8030D868, 0x0000000f, 0x00000002, (u32)lbl_8030D8E8, (u32)lbl_8030D8F8, 0x0000000f, 0x00000000, (u32)lbl_8030D8E8, (u32)lbl_8030D8F8, 0x0000000f, 0x00000000, (u32)lbl_8030D8E8, (u32)lbl_8030D8F8, 0x0000000f, 0x00000000, (u32)lbl_8030D8E8, (u32)lbl_8030D8F8, 0x0000000f, 0x00000000, (u32)lbl_8030D4E8, (u32)lbl_8030D978, 0x00000007, 0x00000000, (u32)lbl_8030D578, (u32)lbl_8030D978, 0x00000007, 0x00000004, (u32)lbl_8030D588, (u32)lbl_8030D978, 0x00000007, 0x00000000, (u32)lbl_8030D598, (u32)lbl_8030D978, 0x00000007, 0x00000000, (u32)lbl_8030DAD8, (u32)lbl_8030DAE8, 0x0000000f, 0x00000000, (u32)lbl_8030D1F8, (u32)lbl_8030DAE8, 0x0000000f, 0x00000004, (u32)lbl_8030D318, (u32)lbl_8030DAE8, 0x0000000f, 0x00000000, (u32)lbl_8030D3B8, (u32)lbl_8030DAE8, 0x0000000f, 0x00000000, (u32)lbl_8030D4E8, (u32)lbl_8030DAE8, 0x0000000f, 0x00000000, (u32)lbl_8030D578, (u32)lbl_8030DAE8, 0x0000000f, 0x00000004, (u32)lbl_8030D588, (u32)lbl_8030DAE8, 0x0000000f, 0x00000000, (u32)lbl_8030D598, (u32)lbl_8030DAE8, 0x0000000f, 0x00000000, (u32)lbl_8030D458, (u32)lbl_8030D468, 0x0000000f, 0x00000000, (u32)lbl_8030DB68, (u32)lbl_8030DB78, 0x00000007, 0x00000000, (u32)lbl_8030D9B8, (u32)lbl_8030D9C8, 0x00000007, 0x00000002, (u32)lbl_8030DA48, (u32)lbl_8030DA58, 0x00000007, 0x00000002, (u32)lbl_8030DBF8, (u32)lbl_8030DC08, 0x0000000b, 0x00000000, (u32)sRcpTexRestructStrings, (u32)lbl_8030D0E8, 0x0000000f, 0x00000000, (u32)lbl_8030D168, (u32)lbl_8030D178, 0x0000000f, 0x00000000, (u32)lbl_8030D288, (u32)lbl_8030D298, 0x00000007, 0x00000004, (u32)lbl_8030D368, (u32)lbl_8030D378, 0x00000007, 0x00000000, (u32)lbl_8030D408, (u32)lbl_8030D418, 0x00000007, 0x00000000, (u32)lbl_8030D168, (u32)lbl_8030D178, 0x0000000f, 0x00000000, (u32)lbl_8030D288, (u32)lbl_8030D298, 0x00000007, 0x00000004, (u32)lbl_8030D368, (u32)lbl_8030D378, 0x00000007, 0x00000000, (u32)lbl_8030D408, (u32)lbl_8030D418, 0x00000007, 0x00000000, (u32)lbl_8030D5A8, (u32)lbl_8030D5C8, 0x0000000f, 0x00000000, (u32)lbl_8030D748, (u32)lbl_8030D758, 0x0000000f, 0x00000000, (u32)lbl_8030D5A8, (u32)lbl_8030D648, 0x0000000f, 0x00000000, (u32)lbl_8030D748, (u32)lbl_8030D7D8, 0x0000000f, 0x00000000, (u32)lbl_8030D5B8, (u32)lbl_8030D5C8, 0x0000000f, 0x00000000, (u32)lbl_8030D5B8, (u32)lbl_8030D6C8, 0x0000000f, 0x00000000, 0xf5101000, 0x00014050, 0xf2000000, 0x0007c07c, 0xf5100900, 0x01010441, 0xf2000000, 0x0103c03c, 0xf5100540, 0x0200c832, 0xf2000000, 0x0201c01c, 0xf5100350, 0x03008c23, 0xf2000000, 0x0300c00c, 0xf5101000, 0x00080050, 0xf2000000, 0x0007c07c, 0xf5100900, 0x01080441, 0xf2000000, 0x0103c03c, 0xf5100540, 0x02080832, 0xf2000000, 0x0201c01c, 0xf5100350, 0x03080c23, 0xf2000000, 0x0300c00c, 0xf5101000, 0x00014200, 0xf2000000, 0x0007c07c, 0xf5100900, 0x01010601, 0xf2000000, 0x0103c03c, 0xf5100540, 0x0200ca02, 0xf2000000, 0x0201c01c, 0xf5100350, 0x03008e03, 0xf2000000, 0x0300c00c, 0xf5100400, 0x00018050, 0xf2000000, 0x0007c07c, 0xf5100280, 0x01414441, 0xf2000000, 0x0103c03c, 0xf51002a0, 0x02810832, 0xf2000000, 0x0201c01c, 0xf51002a8, 0x03c0cc23, 0xf2000000, 0x0300c00c, 0xf5100400, 0x00080050, 0xf2000000, 0x0007c07c, 0xf5100280, 0x01480441, 0xf2000000, 0x0103c03c, 0xf51002a0, 0x02880832, 0xf2000000, 0x0201c01c, 0xf51002a8, 0x03c80c23, 0xf2000000, 0x0300c00c, 0xf5100400, 0x00018200, 0xf2000000, 0x0007c07c, 0xf5100280, 0x01414601, 0xf2000000, 0x0103c03c, 0xf51002a0, 0x02810a02, 0xf2000000, 0x0201c01c, 0xf51002a8, 0x03c0ce03, 0xf2000000, 0x0300c00c, 0xf5180800, 0x00010040, 0xf5180440, 0x0100c431, 0xf5180250, 0x02008822, 0xf5180254, 0x03008822, 0xf2000000, 0x0003c03c, 0xf2000000, 0x0001c01c, 0xf2000000, 0x0000c00c, 0xf2000000, 0x0000c00c, 0x4661696c, 0x65642074, 0x6f20616c, 0x6c6f6361, 0x7465206d, 0x656d6f72, 0x792d3e66, 0x6f726369, 0x6e672074, 0x65787475, 0x72652066, 0x7265650a, 0x00000000, 0x5e5e5e5e, 0x5e5e5e5e, 0x5e5e5e5e, 0x5e5e5e5e, 0x20205265, 0x73747275, 0x63742074, 0x65787475, 0x72657320, 0x52756e6e, 0x696e670a, 0x00000000, 0x5e5e5e5e, 0x5e5e5e5e, 0x5e5e5e5e, 0x5e5e5e5e, 0x20205245, 0x52454749, 0x4f4e200a, 0x00000000, 0x74657852, 0x65737472, 0x75637452, 0x65667320, 0x204e6f20, 0x53706163, 0x6520746f, 0x20526552, 0x6567696f, 0x6e206672, 0x6f6d2030, 0x78257820, 0x73697a65, 0x20256421, 0x2121210a, 0x00000000, 0x74657852, 0x65737472, 0x75637452, 0x65667320, 0x20204f70, 0x74696d61, 0x6c205265, 0x52656769, 0x6f6e2066, 0x726f6d20, 0x30782578, 0x20746f20, 0x30782578, 0x2073697a, 0x65202564, 0x21212121, 0x0a000000, 0x5e5e5e5e, 0x5e5e5e5e, 0x5e5e5e5e, 0x5e5e5e5e, 0x20204146, 0x54455220, 0x52455245, 0x47494f4e, 0x200a0000, 0x74657852, 0x65737472, 0x75637452, 0x65667320, 0x204e6f20, 0x53706163, 0x6520746f, 0x20526573, 0x74727563, 0x74757265, 0x2066726f, 0x6d203078, 0x25782073, 0x697a6520, 0x25642121, 0x21210a00, 0x74657852, 0x65737472, 0x75637452, 0x65667320, 0x57726f6e, 0x67207265, 0x67696f6e, 0x2066726f, 0x6d203078, 0x25782074, 0x6f203078, 0x25782073, 0x697a6520, 0x25642121, 0x21210a00, 0x74657852, 0x65737472, 0x75637452, 0x65667320, 0x20205375, 0x624f7074, 0x696d616c, 0x20526573, 0x74727563, 0x74757265, 0x2066726f, 0x6d203078, 0x25782074, 0x6f203078, 0x25782073, 0x697a6520, 0x25642121, 0x21210a00, 0x74657852, 0x65737472, 0x75637452, 0x65667320, 0x20204f70, 0x74696d61, 0x6c205265, 0x73747275, 0x63747572, 0x65206672, 0x6f6d2030, 0x78257820, 0x746f2030, 0x78257820, 0x73697a65, 0x20256421, 0x2121210a, 0x00000000, 0x74657852, 0x65737472, 0x75637452, 0x65667320, 0x52655265, 0x67696f6e, 0x65642061, 0x6c6c6f63, 0x2063616e, 0x27742067, 0x65742062, 0x61636b20, 0x696e746f, 0x20726567, 0x696f6e20, 0x30206672, 0x6f6d2030, 0x78257820, 0x746f2030, 0x78257820, 0x73697a65, 0x20256421, 0x2121210a, 0x00000000, 0x74657852, 0x65737472, 0x75637452, 0x65667320, 0x20205265, 0x52656769, 0x6f6e6564, 0x20616c6c, 0x6f63204f, 0x7074696d, 0x616c2052, 0x65737472, 0x75637475, 0x72652066, 0x726f6d20, 0x30782578, 0x20746f20, 0x30782578, 0x2073697a, 0x65202564, 0x21212121, 0x0a000000, 0x5e5e5e5e, 0x5e5e5e5e, 0x5e5e5e5e, 0x5e5e5e5e, 0x20205265, 0x73747275, 0x63742074, 0x65787475, 0x72657320, 0x46696e69, 0x73686564, 0x20706173, 0x73657320, 0x25640a00 };
