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
extern u32 DAT_803dc070;
extern u32 DAT_803dd9b0;
extern u32 DAT_803dd9c8;
extern u32 DAT_803dd9c9;
extern u32 DAT_803dd9ca;
extern u32 DAT_803dd9cb;
extern u32 DAT_803dd9cc;
extern u32 DAT_803dd9d0;
extern u32 DAT_803dd9d4;
extern u32 DAT_803dd9d8;
extern u32 DAT_803dd9dc;
extern u32 DAT_803dd9e0;
extern u32 DAT_803dd9e4;
extern u32 DAT_803dd9e8;
extern u32 DAT_803dd9e9;
extern u32 DAT_803dd9ea;
extern u32 DAT_803dd9eb;
extern u32 DAT_803dd9ec;
extern u32 DAT_803dd9f0;
extern u32 DAT_803dd9f4;
extern u32 DAT_803dd9f8;
extern u32 DAT_803dd9fc;
extern u32 DAT_803dda00;
extern u32 DAT_803dda04;
extern u32 DAT_803dda08;
extern u32 DAT_803dda0c;
extern u32 DAT_803dda10;
extern u32 DAT_803dda3c;
extern int* DAT_803dda44;
extern u32 DAT_803dda74;
extern u32 DAT_803dda75;
extern u32 DAT_803dda7b;
extern u32 DAT_803dda80;
extern f32 lbl_803DDAC8;
extern f32 lbl_803DDACC;
extern f32 lbl_803DDAD0;
extern f32 lbl_803DF818;
extern f32 lbl_803DF81C;

void FUN_80051868(int param_1, float* param_2, int param_3)
{
    FUN_8025be80(DAT_803dda10);
    FUN_8025c828(DAT_803dda10, DAT_803dda08, DAT_803dda0c, 4);
    FUN_8025c65c(DAT_803dda10, 0, 0);
    if (param_2 == (float*)0x0)
    {
        FUN_80258674(DAT_803dda08, 1, DAT_803dd9f8, 0x3c, 0, 0x7d);
    }
    else
    {
        FUN_8025d8c4(param_2, DAT_803dda00, 0);
        FUN_80258674(DAT_803dda08, 1, DAT_803dd9f8, 0x3c, 0, DAT_803dda00);
        DAT_803dda00 = DAT_803dda00 + 3;
    }
    if (param_3 == 0)
    {
        FUN_8025c1a4(DAT_803dda10, 0xf, 8, 10, 0xf);
    }
    else if (param_3 == 8)
    {
        FUN_8025c1a4(DAT_803dda10, 0xf, 8, 10, 6);
    }
    else if (param_3 == 4)
    {
        FUN_8025c1a4(DAT_803dda10, 8, 0xf, 0xf, 0);
    }
    else if (param_3 == 6)
    {
        FUN_8025c1a4(DAT_803dda10, 0xf, 8, 0, 0xf);
    }
    else if (param_3 == 9)
    {
        FUN_8025c1a4(DAT_803dda10, 8, 0, 1, 0xf);
    }
    else
    {
        FUN_8025c1a4(DAT_803dda10, 8, 0, 1, 0xf);
    }
    if (DAT_803dd9eb == '\0')
    {
        FUN_8025c224(DAT_803dda10, 7, 4, 5, 7);
        DAT_803dd9eb = '\x01';
    }
    else
    {
        FUN_8025c224(DAT_803dda10, 7, 4, 0, 7);
    }
    FUN_8025c2a8(DAT_803dda10, 0, 0, 0, 1, 0);
    FUN_8025c368(DAT_803dda10, 0, 0, 0, 1, 0);
    DAT_803dd9b0 = 1;
    if (param_1 != 0)
    {
        if (*(char*)(param_1 + 0x48) == '\0')
        {
            FUN_8025b054((u32*)(param_1 + 0x20), DAT_803dda0c);
        }
        else
        {
            FUN_8025aeac((u32*)(param_1 + 0x20), *(u32**)(param_1 + 0x40), DAT_803dda0c);
        }
    }
    DAT_803dd9f8 = DAT_803dd9f8 + 1;
    DAT_803dda08 = DAT_803dda08 + 1;
    DAT_803dda10 = DAT_803dda10 + 1;
    DAT_803dda0c = DAT_803dda0c + 1;
    DAT_803dd9ea = DAT_803dd9ea + '\x01';
    DAT_803dd9e9 = DAT_803dd9e9 + '\x01';
    return;
}

void FUN_80051fc4(u32 param_1, u32 param_2, int param_3, char* param_4, u32 param_5,
                  u32 param_6)
{
    int colorIdx;
    int tex;
    u64 mtxPair;
    u32 colorWord;
    int blendModeId;
    int blendArgs[8];

    mtxPair = FUN_8028683c();
    tex = (int)((u64)mtxPair >> 0x20);
    FUN_8025be80(DAT_803dda10);
    FUN_8025c828(DAT_803dda10, DAT_803dda08, DAT_803dda0c, 0xff);
    FUN_8025c65c(DAT_803dda10, 0, 1);
    colorIdx = (param_5 & 0xff) * 0xc;
    FUN_8025c6b4(1, *(u32*)(&DAT_8030dac4 + colorIdx), *(int*)(&DAT_8030dac8 + colorIdx),
                 *(u32*)(&DAT_8030dacc + colorIdx), 3);
    if ((float*)mtxPair == (float*)0x0)
    {
        FUN_80258674(DAT_803dda08, 1, DAT_803dd9f8, 0x3c, 0, 0x7d);
    }
    else
    {
        FUN_8025d8c4((float*)mtxPair, DAT_803dda00, 0);
        FUN_80258674(DAT_803dda08, 1, DAT_803dd9f8, 0x3c, 0, DAT_803dda00);
        DAT_803dda00 = DAT_803dda00 + 3;
    }
    if ((param_6 & 0xff) == 0)
    {
        colorWord = *(u32*)param_4;
        FUN_8025c510(DAT_803dd9f4, (u8*)&colorWord);
        GXSetBlendMode(DAT_803dda10, DAT_803dd9f0);
        if (((Texture*)tex)->imageOffset == 0)
        {
            FUN_8025c5f0(DAT_803dda10, DAT_803dd9ec);
        }
        else
        {
            FUN_8025c5f0(DAT_803dda10 + 1, DAT_803dd9ec);
        }
        DAT_803dd9f4 = DAT_803dd9f4 + 1;
        DAT_803dd9f0 = DAT_803dd9f0 + 1;
        DAT_803dd9ec = DAT_803dd9ec + 1;
    }
    else
    {
        FUN_80047d88(param_4, '\x01', '\x01', blendArgs, &blendModeId);
        GXSetBlendMode(DAT_803dda10, blendArgs[0]);
        if (((Texture*)tex)->imageOffset == 0)
        {
            FUN_8025c5f0(DAT_803dda10, blendModeId);
        }
        else
        {
            FUN_8025c5f0(DAT_803dda10 + 1, blendModeId);
        }
    }
    if (param_3 == 0)
    {
        FUN_8025c1a4(DAT_803dda10, 0xf, 8, 0xe, 0xf);
    }
    else if (param_3 == 8)
    {
        FUN_8025c1a4(DAT_803dda10, 0xf, 8, 4, 6);
    }
    else
    {
        FUN_8025c1a4(DAT_803dda10, 8, 0, 1, 0xf);
    }
    if (DAT_803dd9eb == '\0')
    {
        FUN_8025c224(DAT_803dda10, 7, 4, 6, 7);
    }
    else
    {
        FUN_8025c224(DAT_803dda10, 7, 4, 0, 7);
    }
    FUN_8025c2a8(DAT_803dda10, 0, 0, 0, 1, 0);
    FUN_8025c368(DAT_803dda10, 0, 0, 0, 1, 0);
    DAT_803dd9b0 = 1;
    if (tex != 0)
    {
        if (*(char*)&((Texture*)tex)->preloaded == '\0')
        {
            FUN_8025b054((u32*)(tex + 0x20), DAT_803dda0c);
        }
        else
        {
            FUN_8025aeac((u32*)(tex + 0x20), *(u32**)(tex + 0x40), DAT_803dda0c);
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
        DAT_803dda10 = DAT_803dda10 + 1;
        DAT_803dda0c = DAT_803dda0c + 1;
        FUN_8025be80(DAT_803dda10);
        FUN_8025c828(DAT_803dda10, DAT_803dda08, DAT_803dda0c, 0xff);
        FUN_8025c65c(DAT_803dda10, 0, 0);
        FUN_8025c1a4(DAT_803dda10, 0xf, 0xf, 0xf, 0);
        FUN_8025c224(DAT_803dda10, 7, 4, 6, 7);
        FUN_8025c2a8(DAT_803dda10, 0, 0, 0, 1, 0);
        FUN_8025c368(DAT_803dda10, 0, 0, 0, 1, 0);
    }
    DAT_803dd9eb = 1;
    DAT_803dd9f8 = DAT_803dd9f8 + 1;
    DAT_803dda08 = DAT_803dda08 + 1;
    DAT_803dda10 = DAT_803dda10 + 1;
    DAT_803dda0c = DAT_803dda0c + 1;
    DAT_803dd9ea = DAT_803dd9ea + '\x01';
    DAT_803dd9e9 = DAT_803dd9e9 + '\x01';
    FUN_80286888();
    return;
}

void FUN_80052778(char* param_1)
{
    int blendModeId;
    int blendArgs[4];

    FUN_8025be80(DAT_803dda10);
    FUN_80047d88(param_1, '\x01', '\x01', blendArgs, &blendModeId);
    FUN_8025c5f0(DAT_803dda10, blendModeId);
    GXSetBlendMode(DAT_803dda10, blendArgs[0]);
    FUN_8025c828(DAT_803dda10, 0xff, 0xff, 4);
    FUN_8025c65c(DAT_803dda10, 0, 0);
    if ((DAT_803dd9ea == '\0') || (DAT_803dd9b0 == '\0'))
    {
        FUN_8025c1a4(DAT_803dda10, 0xf, 0xf, 0xf, 0xe);
        FUN_8025c224(DAT_803dda10, 7, 7, 7, 6);
    }
    else
    {
        FUN_8025c1a4(DAT_803dda10, 0xf, 0, 0xe, 0xf);
        FUN_8025c224(DAT_803dda10, 7, 0, 6, 7);
    }
    FUN_8025c2a8(DAT_803dda10, 0, 0, 0, 1, 0);
    FUN_8025c368(DAT_803dda10, 0, 0, 0, 1, 0);
    DAT_803dd9b0 = 1;
    DAT_803dda10 = DAT_803dda10 + 1;
    DAT_803dd9ea = DAT_803dd9ea + '\x01';
    return;
}

void FUN_800528d0(void)
{
    FUN_80258944((u32)DAT_803dd9e9);
    FUN_8025ca04((u32)DAT_803dd9ea);
    FUN_8025be54((u32)DAT_803dd9e8);
    return;
}

void FUN_80052904(void)
{
    DAT_803dd9d8 = 0x1e;
    DAT_803dda04 = 0x1e;
    DAT_803dd9d4 = 0x40;
    DAT_803dda00 = 0x40;
    DAT_803dd9e4 = 0;
    DAT_803dda10 = 0;
    DAT_803dd9dc = 0;
    DAT_803dda08 = 0;
    DAT_803dd9e0 = 0;
    DAT_803dda0c = 0;
    DAT_803dd9d0 = 0;
    DAT_803dd9fc = 0;
    DAT_803dd9cc = 4;
    DAT_803dd9f8 = 4;
    DAT_803dd9f4 = 0;
    DAT_803dd9f0 = 0xc;
    DAT_803dd9ec = 0x1c;
    DAT_803dd9eb = 0;
    DAT_803dd9cb = 0;
    DAT_803dd9ea = 0;
    DAT_803dd9ca = 0;
    DAT_803dd9e9 = 0;
    DAT_803dd9c9 = 0;
    DAT_803dd9e8 = 0;
    DAT_803dd9c8 = 0;
    DAT_803dd9b0 = 0;
    return;
}

u32 FUN_80053078(u32 param_1)
{
    int idx;

    if ((param_1 & 0x80000000) != 0)
    {
        return param_1;
    }
    idx = param_1 - 1;
    if ((-1 < idx) && (idx < DAT_803dda3c))
    {
        return *(u32*)(DAT_803dda44 + idx * 0x10 + 4);
    }
    return 0;
}

void FUN_800530b4(void)
{
}

void FUN_800530b8(int param_1, u32* param_2)
{
    bool hasMip;
    double scalar;

    hasMip = 0 < (int)((u32) * (u8*)(param_1 + 0x1d) - (u32) * (u8*)(param_1 + 0x1c));
    FUN_8025aa74(param_2, param_1 + *(int*)(param_1 + 0x50) + 0x60, (u32) * (u16*)(param_1 + 10),
                 (u32) * (u16*)(param_1 + 0xc), 0, (u32) * (u8*)(param_1 + 0x17),
                 (u32) * (u8*)(param_1 + 0x18), hasMip);
    if (hasMip)
    {
        FUN_8025ace8((double)(float)((double)(u32) * (u8*)(param_1 + 0x1c)),
                     (double)(float)((double)(int)(*(u8*)(param_1 + 0x1d))), (double)lbl_803DF818, param_2,
                     (u32) * (u8*)(param_1 + 0x19), (u32) * (u8*)(param_1 + 0x1a), 0, '\0', 0);
    }
    else
    {
        scalar = (double)lbl_803DF81C;
        FUN_8025ace8(scalar, scalar, scalar, param_2, (u32) * (u8*)(param_1 + 0x19),
                     (u32) * (u8*)(param_1 + 0x1a), 0, '\0', 0);
    }
    return;
}

int FUN_8005337c(int param_1)
{
    int* entry;
    int idx;
    int remaining;

    idx = 0;
    entry = DAT_803dda44;
    remaining = DAT_803dda3c;
    if (0 < DAT_803dda3c)
    {
        do
        {
            if (param_1 == *entry)
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

void FUN_800533cc(int param_1, u32* param_2, int* param_3)
{
    u32 flags;
    int cnt;
    u32 reverse;
    int cnt2;

    flags = *param_2;
    reverse = flags & 0x80000;
    if ((flags & 0x20000) == 0)
    {
        if ((flags & 0x40000) == 0)
        {
            if (reverse == 0)
            {
                *param_3 = *param_3 + (u32) * (u16*)(param_1 + 0x14) * (u32)DAT_803dc070;
                while ((int)(u32) * (u16*)(param_1 + 0x10) <= *param_3)
                {
                    *param_3 = *param_3 - (u32) * (u16*)(param_1 + 0x10);
                }
            }
            else
            {
                *param_3 = *param_3 - (u32) * (u16*)(param_1 + 0x14) * (u32)DAT_803dc070;
                while (*param_3 < 0)
                {
                    *param_3 = *param_3 + (u32) * (u16*)(param_1 + 0x10);
                }
            }
        }
        else
        {
            if (reverse == 0)
            {
                *param_3 = *param_3 + (u32) * (u16*)(param_1 + 0x14) * (u32)DAT_803dc070;
            }
            else
            {
                *param_3 = *param_3 - (u32) * (u16*)(param_1 + 0x14) * (u32)DAT_803dc070;
            }
            do
            {
                cnt = *param_3;
                if (cnt < 0)
                {
                    *param_3 = -cnt;
                    *param_2 = *param_2 & 0xfff7ffff;
                }
                cnt2 = *param_3;
                reverse = (u32) * (u16*)(param_1 + 0x10);
                if ((int)reverse <= cnt2)
                {
                    *param_3 = (reverse * 2 + -1) - cnt2;
                    *param_2 = *param_2 | 0x80000;
                }
            }
            while ((int)reverse <= cnt2 || cnt < 0);
        }
    }
    else if ((flags & 0x40000) == 0)
    {
        reverse = randomGetRange(0, 1000);
        if (0x3d9 < (int)reverse)
        {
            *param_2 = *param_2 & 0xfff7ffff;
            *param_2 = *param_2 | 0x40000;
        }
    }
    else if (reverse == 0)
    {
        *param_3 = *param_3 + (u32) * (u16*)(param_1 + 0x14) * (u32)DAT_803dc070;
        if ((int)(u32) * (u16*)(param_1 + 0x10) <= *param_3)
        {
            *param_3 = ((u32) * (u16*)(param_1 + 0x10) * 2 + -1) - *param_3;
            if (*param_3 < 0)
            {
                *param_3 = 0;
                *param_2 = *param_2 & 0xfff3ffff;
            }
            else
            {
                *param_2 = *param_2 | 0x80000;
            }
        }
    }
    else
    {
        *param_3 = *param_3 - (u32) * (u16*)(param_1 + 0x14) * (u32)DAT_803dc070;
        if (*param_3 < 0)
        {
            *param_3 = 0;
            *param_2 = *param_2 & 0xfff3ffff;
        }
    }
    return;
}

void FUN_8005360c(u32 param_1, u32* param_2, u32* param_3, u32 param_4,
                  int param_5)
{
    u32* curNode;
    u32* scan;
    int i;
    int idx;
    u32 count;
    u32* resultNode;

    if (param_2 != (u32*)0x0)
    {
        idx = param_5 >> 0x10;
        if (*(u16*)(param_2 + 4) == 0)
        {
            count = 0;
        }
        else
        {
            count = (int)(u32) * (u16*)(param_2 + 4) >> 8;
        }
        curNode = param_2;
        resultNode = param_2;
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
            if ((param_4 & 0x40) != 0)
            {
                if ((param_4 & 0x80000) == 0)
                {
                    i = idx + 1;
                    if ((int)count <= i)
                    {
                        if ((param_4 & 0x40000) == 0)
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
                        if ((param_4 & 0x40000) == 0)
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
                for (scan = param_2; (idx < i && (scan != (u32*)0x0));
                     scan = (u32*)*scan)
                {
                    idx = idx + 1;
                }
                resultNode = param_2;
                if (scan != (u32*)0x0)
                {
                    resultNode = scan;
                }
            }
        }
        if (param_3 != (u32*)0x0)
        {
            resultNode = param_3;
        }
        FUN_8004812c((int)curNode, 0);
        FUN_8004812c((int)resultNode, 1);
    }
    return;
}

void FUN_80053754(void)
{
}

void FUN_80053758(u64 param_1, u64 param_2, u64 param_3, u64 param_4,
                  u64 param_5, u64 param_6, u64 param_7, u64 param_8)
{
}

void FUN_800537a0(u32 param_1, u32 param_2, int param_3, char param_4, u32 param_5,
                  u8 param_6, u8 param_7, u8 param_8, u8 param_9)
{
    int tex;
    u64 dims;

    dims = FUN_80286834();
    tex = FUN_8025a850((u32)((u64)dims >> 0x20), (u32)dims, param_3, param_4, param_5);
    tex = FUN_80017830(tex + 0x60, 6);
    if (tex != 0)
    {
        FUN_800033a8(tex, 0, 100);
        *(char*)&((Texture*)tex)->format = (char)param_3;
        *(short*)(tex + 10) = (short)((u64)dims >> 0x20);
        *(short*)(tex + 0xc) = (short)dims;
        *(u16*)(tex + 0x10) = 1;
        *(u16*)(tex + 0xe) = 0;
        *(u8*)(tex + 0x17) = param_6;
        *(u8*)(tex + 0x18) = param_7;
        *(u8*)(tex + 0x19) = param_8;
        *(u8*)(tex + 0x1a) = param_9;
        *(u32*)(tex + 0x50) = 0;
        FUN_800531e0(tex);
    }
    FUN_80286880();
    return;
}

u32
FUN_8005398c(u64 param_1, double param_2, double param_3, u64 param_4, u64 param_5,
             u64 param_6, u64 param_7, u64 param_8, u32 param_9,
             u32 param_10, u32 param_11, u32 param_12, u32 param_13,
             u32 param_14, u32 param_15, u32 param_16)
{
    u32 fileFlags;
    u32 result[5];

    result[0] = 0;
    fileFlags = FUN_80042838();
    if ((fileFlags & 0x100000) == 0)
    {
        FUN_8001763c(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, result, param_9,
                     param_11, param_12, param_13, param_14, param_15, param_16);
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
    DAT_803dda80 = 0xffffffff;
    *(u8*)(state + 0x10) = *(u8*)(state + 0x10) & 0xdf;
    return;
}

void FUN_80053ba4(void)
{
    DAT_803dda74 = 0;
    return;
}

void FUN_80053bb0(double param_1, double param_2, double param_3, u8 param_4, u8 param_5)
{
    DAT_803dda74 = 1;
    lbl_803DDAD0 = (float)param_1;
    lbl_803DDACC = (float)param_2;
    lbl_803DDAC8 = (float)param_3;
    DAT_803dda75 = param_4;
    DAT_803dda7b = param_5;
    return;
}

void FUN_80053c98(u64 param_1, double param_2, double param_3, u64 param_4,
                  u64 param_5, u64 param_6, u64 param_7, u64 param_8,
                  int param_9, char param_10, u32 param_11, u32 param_12,
                  u32 param_13, u32 param_14, u32 param_15, u32 param_16)
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

extern u8 gRcpDistortSlots[];

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
            s = *(void**)(gRcpDistortSlots + i * 0x1C);
            if (*(u16*)((char*)s + 0xE) != 0 && s == p1)
            {
                (*(u16*)((char*)*(void**)(gRcpDistortSlots + i * 0x1C) + 0xE))--;
                break;
            }
        }
    }
    p2 = (void*)def[1];
    if (p2 == NULL) return;
    for (j = 0; j < 6; j++)
    {
        if (*(u16*)((char*)*(void**)(gRcpDistortSlots + j * 0x1C) + 0xE) != 0 &&
            *(void**)(gRcpDistortSlots + j * 0x1C) == p2)
        {
            (*(u16*)((char*)*(void**)(gRcpDistortSlots + j * 0x1C) + 0xE))--;
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
extern int lbl_803DCD90;

void gxColorFn_800523d0(void)
{
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, 0xff, 0xff, 4);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    if (lbl_803DCD6A == 0 || lbl_803DCD30 == 0)
    {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 0xf, 0xf, 0xa);
        GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 5);
    }
    else
    {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 0, 0xa, 0xf);
        GXSetTevAlphaIn(lbl_803DCD90, 7, 0, 5, 7);
    }
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
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
    gxSetZMode_(0, 2, 0);
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
    GXSetTevOrder(lbl_803DCD90, 0xff, 0xff, 0xff);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    if (lbl_803DCD6A != 0 && lbl_803DCD30 != 0)
    {
        GXSetTevColorIn(lbl_803DCD90, 0, 0xe, 3, 0xf);
        GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 0);
    }
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
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
    GXSetTevOrder(lbl_803DCD90, 0xff, 0xff, 4);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    gxTextureFn_8004bf88(param, 0, 1, &sel_color, &sel_alpha);
    GXSetTevKAlphaSel(lbl_803DCD90, sel_alpha);
    if (lbl_803DCD6A == 0 || lbl_803DCD30 == 0)
    {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 0xf, 0xf, 0xa);
        GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 6);
    }
    else
    {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 0, 0xa, 0xf);
        GXSetTevAlphaIn(lbl_803DCD90, 7, 0, 6, 7);
    }
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
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
    GXSetTevOrder(lbl_803DCD90, 0xff, 0xff, 4);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    if (lbl_803DCD6A == 0 || lbl_803DCD30 == 0)
    {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 0xf, 0xf, 0xe);
        GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 6);
    }
    else
    {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 0, 0xe, 0xf);
        GXSetTevAlphaIn(lbl_803DCD90, 7, 0, 6, 7);
    }
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    lbl_803DCD30 = 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD6A++;
}

extern u32 GXGetTexBufferSize(u16 w, u16 h, u32 format, u8 mipmap, u8 max_lod);
extern void* memset(void*, int, u32);
extern void textureFn_80053d58(void* obj);
#pragma dont_inline on
void* textureAlloc(u16 w, u16 h, int fmt, u8 mip, u8 maxLod, u8 b8, u8 b9, u8 b10, u8 b11)
{
    u8* obj;
    u32 size = GXGetTexBufferSize(w, h, fmt, mip, maxLod) + 96;
    obj = (u8*)mmAlloc(size, 6, 0);
    if (obj == NULL) return NULL;
    memset(obj, 0, 100);
    *(u8*)(obj + 22) = fmt;
    *(u16*)(obj + 10) = w;
    *(u16*)(obj + 12) = h;
    *(u16*)(obj + 16) = 1;
    *(u16*)(obj + 14) = 0;
    *(u8*)(obj + 23) = b8;
    *(u8*)(obj + 24) = b9;
    *(u8*)(obj + 25) = b10;
    *(u8*)(obj + 26) = b11;
    *(int*)&((GameObject*)obj)->anim.modelInstance = 0;
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
    *(int*)(obj + 64) = 0;
    obj[72] = 0;
    texObj = (void*)(obj + 32);
    if ((int)obj[29] - (int)obj[28] > 0) mipmap = 1;
    GXInitTexObj(texObj, obj + 96,
                 *(u16*)(obj + 10), *(u16*)(obj + 12),
                 obj[22], obj[23], obj[24], mipmap);
    if (mipmap != 0)
    {
        GXInitTexObjLOD(texObj, obj[25], obj[26],
                        (f32)(u32)obj[28], (f32)(s32)obj[29],
                        lbl_803DEB98, 0, 0, 0);
    }
    else
    {
        GXInitTexObjLOD(texObj, obj[25], obj[26],
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
                    if (iter[72] != 0) findSomething(*(int*)(iter + 64));
                    if (iter[73] == 0) mm_free(iter);
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
#pragma peephole off
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
#pragma peephole off
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
        (*(u16*)((char*)s + 0xE))++;
        out[0] = *slot;
    }
    if (*(void**)(def + 0x14) == NULL)
        return;
    if (def[0x20] >= 6)
        slot = (void**)gRcpDistortSlots;
    else
        slot = (void**)(gRcpDistortSlots + (def[0x20] >> 1) * 0x1C);
    s = *slot;
    (*(u16*)((char*)s + 0xE))++;
    out[1] = *slot;
}

extern void selectTexture(int handle, int slot);

void textureFn_800541ac(int p1, int* tex, void* forceTex, int flags, int packed)
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
    char* romBase;
    char *p, *obj, *end, *objStart;
    int objIndex, i;
    int visible, v, flag;
    int byteIdx, bit;
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
                    ((s8*)*(s8**)((char*)bm2 + 0x10))[byteIdx] =
                        ((s8*)*(s8**)((char*)bm2 + 0x10))[byteIdx] & ~bit;
                    ((s8*)*(s8**)((char*)bm2 + 0x10))[byteIdx] =
                        ((s8*)*(s8**)((char*)bm2 + 0x10))[byteIdx] | bit;
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

extern TevSwapEntry gRcpTevSwapTable[];
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
extern u8 gRcpWarpDistortDisplayList[];
extern F32Pair LastReadFinished_803DEB50;
extern f32 lbl_803DEB54;
extern f32 lbl_803DEB64;

#pragma opt_loop_invariants off
void lightFn_80052974(f32 a, f32 b)
{
    f32 z;
    f32 scale;
    f32 half;
    f32 w;
    f32 x0;
    f32 y;
    f32 yy;
    f32 x1;
    f32 d;
    f32 r;
    f32 fa;
    f32 fb;
    u32 i;
    u32 j;

    if (gRcpWarpDistortListBuilt == 0)
    {
        GXSetMisc(GX_MT_XF_FLUSH, 0);
        DCInvalidateRange(gRcpWarpDistortDisplayList, 0x6640);
        GXBeginDisplayList(gRcpWarpDistortDisplayList, 0x6640);
        w = LastReadIssued_803DEB58.lo;
        half = lbl_803DEB5C;
        scale = lbl_803DEB54;
        for (i = 0; i < 0x10; i++)
        {
            GXBegin(GX_TRIANGLESTRIP, GX_VTXFMT4, 0x22);
            fa = scale * (f32)i;
            z = lbl_803DEB64;
            fb = scale * (f32)(i + 1);
            x0 = fa / w - half;
            x1 = fb / w - half;
            for (j = 0; j <= 0x10; j++)
            {
                y = (scale * (f32)j) / w - half;
                yy = y * y;
                d = x0 * x0 + yy;
                if (d < half)
                {
                    r = sqrtf(half - d);
                }
                else
                {
                    r = LastCommandWasRead_803DEB60;
                }
                *(volatile f32*)0xCC008000 = x0;
                *(volatile f32*)0xCC008000 = y;
                *(volatile f32*)0xCC008000 = z;
                *(volatile f32*)0xCC008000 = x0;
                *(volatile f32*)0xCC008000 = y;
                *(volatile f32*)0xCC008000 = r;
                d = x1 * x1 + yy;
                if (d < half)
                {
                    r = sqrtf(half - d);
                }
                else
                {
                    r = LastCommandWasRead_803DEB60;
                }
                *(volatile f32*)0xCC008000 = x1;
                *(volatile f32*)0xCC008000 = y;
                *(volatile f32*)0xCC008000 = z;
                *(volatile f32*)0xCC008000 = x1;
                *(volatile f32*)0xCC008000 = y;
                *(volatile f32*)0xCC008000 = r;
            }
        }
        gRcpWarpDistortListSize = GXEndDisplayList();
        gRcpWarpDistortListBuilt = 1;
        GXSetMisc(GX_MT_XF_FLUSH, 8);
    }
    GXCallDisplayList(gRcpWarpDistortDisplayList, gRcpWarpDistortListSize);
}
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

extern f32 powfCoreHighPrecision(f32 base, f32 exp);
extern f32 gRcpDistortScaleA;
extern f32 gRcpDistortPowExp;
extern u8 lbl_8030D028[];
extern u8 gRcpDistortSlotIndex;
extern void* gRcpDistortTexture;

void initFn_800534f8(void)
{
    int i;
    u8* p;
    u8* q;
    int j;
    u32 half;
    u8* slot;
    f32 scaleB;
    f32 scaleA;
    f32 v;
    f32 inv;

    i = 0;
    p = gRcpDistortSlots;
    for (; i < 6; i++)
    {
        *(void**)(p + i * 0x1c) = textureAlloc(0x20, 0x20, 6, 0, 0, 0, 0, 1, 1);
        p[i * 0x1c + 0x1a] = 0;
    }
    j = 0;
    gRcpDistortSlotIndex = j;
    q = lbl_8030D028;
    scaleA = gRcpDistortScaleA;
    scaleB = LastReadFinished_803DEB50.lo;
    for (; j < 6; j++)
    {
        v = *(f32*)(q + j * 8 + 4);
        slot = gRcpDistortSlots + gRcpDistortSlotIndex * 0x1c;
        slot[0xc] = 0xff;
        slot[0xd] = 0xff;
        slot[0xe] = 0xff;
        inv = scaleA / powfCoreHighPrecision(*(f32*)(q + j * 8), gRcpDistortPowExp);
        slot = gRcpDistortSlots + gRcpDistortSlotIndex * 0x1c;
        half = j & 1;
        *(f32*)(slot + half * 4 + 0x10) = inv;
        *(s8*)(slot + half + 0x18) = scaleB * v;
        slot[0x1b] = 1;
        if (half != 0)
        {
            gRcpDistortSlotIndex = gRcpDistortSlotIndex + 1;
        }
    }
    (gRcpDistortSlots + 0x1b)[gRcpDistortSlotIndex++ * 0x1c] = 0;
    (gRcpDistortSlots + 0x1b)[gRcpDistortSlotIndex++ * 0x1c] = 0;
    (gRcpDistortSlots + 0x1b)[gRcpDistortSlotIndex++ * 0x1c] = 0;
    gRcpDistortTexture = textureLoadAsset(0x5dc);
}

extern void* getCurrentDataFile(int id);
extern void loadAssetFileById(void* out, int id);
extern int* gRcpTexBankTable[3];
extern int gRcpTexBankCount[3];
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
    {
        while (*p != -1)
        {
            p++;
            n++;
        }
        gRcpTexBankCount[0] = n - 1;
    }
    n = 0;
    p = getCurrentDataFile(0x21);
    gRcpTexBankTable[1] = p;
    if (gRcpTexBankTable != NULL)
    {
        while (*p != -1)
        {
            p++;
            n++;
        }
        gRcpTexBankCount[1] = n - 1;
    }
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
extern u8* gMapBlockLayerTables[5];
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
        for (k = 0; k < 5; k++)
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
    GXColor8 c2;
    GXColor8 c;
    int count;
    u8* e;
    int i;
    u8* base;
    int sel;
    int k;
    int n;
    int model;
    u8* tex;
    int* lp;

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
    base = gRcpDistortSlots;
    e = base;
    for (; i < 6; i++)
    {
        tex = *(u8**)e;
        if (((Texture*)tex)->refCount != 0 && e[0x1b] == 1 && gRcpDistortGroup == e[0x1a])
        {
            c.r = (e[0xc] * e[0x18]) >> 8;
            c.g = 0;
            c.b = (e[0xe] * e[0x19]) >> 8;
            c.a = 0xff;
            GXSetChanMatColor(4, c);
            GXSetChanMatColor(5, c);
            textureFn_80052bb4(*(int*)(e + 4), (f32*)(e + 0x10));
            resetLotsOfRenderVars();
            textureFn_8004ff20(gRcpDistortTexture, mtx, &c2, 0);
            textureFn_800528bc();
            lightFn_80052974((f32)(i * 0x20), LastCommandWasRead_803DEB60);
            GXCopyTex(*(u8**)e + 0x60, 0);
            tex = *(u8**)e;
            if (((Texture*)tex)->preloaded != 0)
            {
                GXPreLoadEntireTexture(tex + 0x20, ((Texture*)tex)->tmemAddr);
            }
        }
        e += 0x1c;
    }
    resetLotsOfRenderVars();
    textureFn_800524ec(&gRcpDistortMatColor);
    textureFn_800528bc();
    GXSetChanMatColor(0, *(GXColor8*)&gRcpDistortMatColor);
    sel = 5;
    e = gRcpDistortSlots + 0x8c;
    for (k = 5; k >= 0; k--)
    {
        if (*(u16*)(*(u8**)e + 0xe) != 0 && e[0x1b] == 0 && gRcpDistortGroup == e[0x1a])
        {
            sel = k;
            break;
        }
        e -= 0x1c;
    }
    i = 0;
    for (; i < 6; i++)
    {
        if (*(u16*)(*(u8**)base + 0xe) != 0 && base[0x1b] == 0 && gRcpDistortGroup == base[0x1a])
        {
            model = *(int*)(base + 4);
            modelTextureFn_80089970(2 - (i - 3));
            modelLightStruct_selectObjectLights(model, lights, 8, &count, 4);
            modelLightChannels_reset(1);
            modelLightChannel_configure(0, 0, 0);
            lp = lights;
            for (n = 0; n < count; n++)
            {
                modelLightStruct_loadChannelLight(0, (void*)*lp, model);
                lp++;
            }
            modelLightChannels_applyGXControls();
            lightGetColor(0, &c2.r, &c2.g, &c2.b);
            GXSetChanAmbColor(GX_COLOR0, c2);
            lightFn_80052974((f32)(i * 0x20), LastCommandWasRead_803DEB60);
            GXCopyTex(*(u8**)base + 0x60, (i == sel) ? 1 : 0);
            tex = *(u8**)base;
            if (((Texture*)tex)->preloaded != 0)
            {
                GXPreLoadEntireTexture(tex + 0x20, ((Texture*)tex)->tmemAddr);
            }
        }
        base += 0x1c;
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
    char* strs;
    u8* tex;
    u8* na;
    int done;
    int pass;
    int i;
    int off;
    u32 size;
    int d;

    strs = (char*)(int)sRcpTexRestructStrings;
    done = 0;
    pass = 0;
    texFlagFn_80023cbc(2);
    OSReport(strs + 0x1164);
    printHeapStats(1);
    OSReport(strs + 0x1194);
    testAndSet_onlyUseHeaps1and2(1);
    i = 0;
    off = 0;
    for (; i < gLoadedTextureCount; off += 16, i++)
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
            else
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
        off = 0;
        for (; i < gLoadedTextureCount; i++, off += 16)
        {
            tex = ((LoadedTextureEntry*)((u8*)gLoadedTextures + off))->texture;
            if (tex != NULL && ((LoadedTextureEntry*)((u8*)gLoadedTextures + off))->flag != 0 &&
                ((Texture*)tex)->cached == 0 &&
                (int)((LoadedTextureEntry*)((u8*)gLoadedTextures + off))->size != -1)
            {
                if (mmGetRegionForPtr(tex) == 0)
                {
                    if (*(void**)tex == NULL)
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

void* textureLoad(int texId, u8 flag)
{
    int orig;
    int* p;
    LoadedTextureEntry* entry;
    u8* walk;
    u8* tex;
    u8* first;
    u8* prev;
    u8* buf;
    int restore;
    int disabled;
    int n;
    u16 m;
    int bank;
    int file;
    int id16;
    int word;
    int mips;
    int k;
    int sz2;
    u32 size;
    int packed;
    int base19;
    int slot;
    int sizeOut;
    int frameOut;

    restore = 1;
    disabled = 0;
    if (texId < 0)
    {
        n = -texId;
        if ((n & 0x8000) && (n & 0x7fff) == 0x82e)
        {
            OSReport(&sDebugIntLineFormat);
        }
    }
    n = 0;
    for (; n < gLoadedTextureCount; n++)
    {
        if (gLoadedTextures[n].key == texId)
        {
            tex = gLoadedTextures[n].texture;
            ((Texture*)tex)->refCount += 1;
            if (flag != 0 && gLoadedTextures[n].flag != 0)
            {
                return (void*)(n + 1);
            }
            return tex;
        }
    }
    if (getLoadedFileFlags(0) != 0)
    {
        restore = OSDisableInterrupts();
        disabled = 1;
    }
    orig = texId;
    if (texId < 0)
    {
        texId = -texId;
    }
    else
    {
        if (texId >= 0xbb8)
        {
            m = gRcpTexIdRemap[texId];
            if (m != 0)
            {
                texId = m + 1;
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
    else if (orig >= 0xbb8)
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
    p = getCurrentDataFile(0x24);
    gRcpTexBankTable[0] = p;
    if (gRcpTexBankTable != NULL)
    {
        while (*p != -1)
        {
            p++;
            n++;
        }
        gRcpTexBankCount[0] = n - 1;
    }
    n = 0;
    p = getCurrentDataFile(0x21);
    gRcpTexBankTable[1] = p;
    if (gRcpTexBankTable != NULL)
    {
        while (*p != -1)
        {
            p++;
            n++;
        }
        gRcpTexBankCount[1] = n - 1;
    }
    word = gRcpTexBankTable[bank][id16];
    mips = (word >> 24) & 0x3f;
    if (mips == 1)
    {
        if (bank == 0)
        {
            tex0GetFrame(word, id16, &sizeOut, &frameOut, mips, 0, 0);
        }
        else if (bank == 2)
        {
            texPreGetMipmap(word, id16, &sizeOut, &frameOut, mips, 0, 0);
        }
        else
        {
            tex1GetFrame(word, id16, &sizeOut, &frameOut, mips, 0, 0);
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
        tex0GetFrame(word, id16, &sizeOut, &frameOut, mips, gRcpTexHeaderBuffer, 2);
    }
    else if (bank == 2)
    {
        texPreGetMipmap(word, id16, &sizeOut, &frameOut, mips, gRcpTexHeaderBuffer, 2);
    }
    else
    {
        tex1GetFrame(word, id16, &sizeOut, &frameOut, mips, gRcpTexHeaderBuffer, 2);
    }
    first = NULL;
    prev = NULL;
    k = 0;
    packed = mips << 8;
    base19 = (word & 0xffffff) << 1;
    for (; k < mips; k++)
    {
        if (mips > 1)
        {
            if (bank == 0)
            {
                tex0GetFrame(word, id16, &sizeOut, &frameOut, k, gRcpTexHeaderBuffer, 1);
            }
            else if (bank == 2)
            {
                texPreGetMipmap(word, id16, &sizeOut, &frameOut, k, gRcpTexHeaderBuffer, 1);
            }
            else
            {
                tex1GetFrame(word, id16, &sizeOut, &frameOut, k, gRcpTexHeaderBuffer, 1);
            }
        }
        size = sizeOut;
        if (frameOut == -1)
        {
            sz2 = sizeOut;
        }
        else
        {
            sz2 = frameOut;
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
            if (k != 0)
            {
                *(u16*)(first + 0x10) = packed;
                k = mips;
                continue;
            }
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
        if (frameOut == -1)
        {
            buf = (u8*)loadAndDecompressDataFile(file, 0, base19 + ((int*)gRcpTexHeaderBuffer)[k], sz2, 0,
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
            loadAndDecompressDataFile(file, (int)buf, base19 + ((int*)gRcpTexHeaderBuffer)[k], sz2, 0, id16,
                                      0);
        }
        if (frameOut != -1)
        {
            DCStoreRange(buf, size);
        }
        *(void**)buf = NULL;
        if (prev != NULL)
        {
            *(u8**)prev = buf;
        }
        prev = buf;
        if (k == 0)
        {
            first = buf;
            *(u16*)(buf + 0x10) = packed;
        }
        else
        {
            *(u16*)(buf + 0x10) = 1;
        }
    }
    walk = first;
    *(u32*)(first + 0x4c) = size;
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
    gLoadedTextures[slot].key = orig;
    gLoadedTextures[slot].texture = first;
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
    return first;
}
