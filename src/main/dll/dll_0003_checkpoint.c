#include "main/audio/sfx_ids.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/dim_partfx.h"

extern u32 randomGetRange(int min, int max);

extern undefined4 DAT_8039d0b8;
extern undefined4 DAT_8039d0bc;
extern undefined4 DAT_803de090;
extern f32 lbl_803DC4B0;
extern f32 lbl_803DC4B4;
extern f32 lbl_803E0E38;
extern f32 lbl_803E0E3C;
extern f32 lbl_803E0E40;
extern f32 lbl_803E0E44;
extern f32 lbl_803E0E48;
extern f32 lbl_803E0E4C;
extern f32 lbl_803E0E50;
extern f32 lbl_803E0E54;
extern f32 lbl_803E0E58;
extern f32 lbl_803E0E5C;
extern f32 lbl_803E0E60;
extern f32 lbl_803E0E64;
extern f32 lbl_803E0E68;
extern f32 lbl_803E0E6C;
extern f32 lbl_803E0E70;
extern f32 lbl_803E0E74;
extern f32 lbl_803E0E78;
extern f32 lbl_803E0E7C;
extern f32 lbl_803E0E80;
extern f32 lbl_803E0E84;
extern f32 lbl_803E0E88;
extern f32 lbl_803E0E8C;

undefined4
FUN_800c8110(int param_1, undefined4 param_2, undefined2* param_3, uint param_4, u8 param_5,
             int param_6)
{
    undefined4 uVar1;
    uint uVar2;
    int local_98[3];
    undefined2 local_8c;
    undefined2 local_8a;
    undefined2 local_88;
    undefined4 local_84;
    float local_80;
    float local_7c;
    float local_78;
    float local_74;
    float local_70;
    float local_6c;
    float local_68;
    float local_64;
    float local_60;
    float local_5c;
    undefined2 local_58;
    undefined2 local_56;
    uint local_54;
    undefined4 local_50;
    undefined4 local_4c;
    uint local_48;
    uint local_44;
    undefined2 local_40;
    undefined2 local_3e;
    undefined2 local_3c;
    u8 local_3a;
    u8 local_38;
    u8 local_37;
    u8 local_36;
    undefined4 local_30;
    uint uStack_2c;
    undefined4 local_28;
    uint uStack_24;
    undefined4 local_20;
    uint uStack_1c;
    undefined4 local_18;
    uint uStack_14;

    lbl_803DC4B0 = lbl_803DC4B0 + lbl_803E0E38;
    if (lbl_803E0E40 < lbl_803DC4B0)
    {
        lbl_803DC4B0 = lbl_803E0E3C;
    }
    lbl_803DC4B4 = lbl_803DC4B4 + lbl_803E0E44;
    if (lbl_803E0E40 < lbl_803DC4B4)
    {
        lbl_803DC4B4 = lbl_803E0E48;
    }
    if (param_1 == 0)
    {
        uVar1 = 0xffffffff;
    }
    else
    {
        if ((param_4 & 0x200000) != 0)
        {
            if (param_3 == (undefined2*)0x0)
            {
                return 0xffffffff;
            }
            local_80 = ((PartFxSpawnParams*)param_3)->posX;
            local_7c = ((PartFxSpawnParams*)param_3)->posY;
            local_78 = ((PartFxSpawnParams*)param_3)->posZ;
            local_84 = *(undefined4*)&((PartFxSpawnParams*)param_3)->scale;
            local_88 = ((PartFxSpawnParams*)param_3)->unk4;
            local_8a = ((PartFxSpawnParams*)param_3)->unk2;
            local_8c = *param_3;
            local_36 = param_5;
        }
        local_54 = 0;
        local_50 = 0;
        local_3a = (undefined)param_2;
        local_68 = lbl_803E0E4C;
        local_64 = lbl_803E0E4C;
        local_60 = lbl_803E0E4C;
        local_74 = lbl_803E0E4C;
        local_70 = lbl_803E0E4C;
        local_6c = lbl_803E0E4C;
        local_5c = lbl_803E0E4C;
        local_98[2] = 0;
        local_98[1] = 0xffffffff;
        local_38 = 0xff;
        local_37 = 0;
        local_56 = 0;
        local_40 = 0xffff;
        local_3e = 0xffff;
        local_3c = 0xffff;
        local_4c = 0xffff;
        local_48 = 0xffff;
        local_44 = 0xffff;
        local_58 = 0;
        local_98[0] = param_1;
        switch (param_2)
        {
        case 0x73a:
            uStack_2c = randomGetRange(8, 10);
            local_70 = lbl_803E0E50 * (f32)(s32)
            uStack_2c;
            uVar2 = randomGetRange(0, 0x28);
            if (uVar2 == 0)
            {
                uStack_2c = randomGetRange(0x15, 0x29);
                local_5c = lbl_803E0E38 *
                    (f32)(s32)
                uStack_2c;
                local_98[2] = 0x1cc;
            }
            else
            {
                uStack_2c = randomGetRange(8, 0x14);
                local_5c = lbl_803E0E38 *
                    (f32)(s32)
                uStack_2c;
                local_98[2] = randomGetRange(0x5a, 0x78);
            }
            local_54 = 0x80180200;
            local_50 = 0x1000020;
            local_56 = 0xc0b;
            local_38 = 0x7f;
            local_3c = 0x3fff;
            local_3e = 0x3fff;
            local_40 = 0x3fff;
            local_44 = 0xffff;
            local_48 = 0xffff;
            local_4c = 0xffff;
            local_64 = lbl_803E0E54;
            break;
        case 0x73b:
            uStack_2c = randomGetRange(0xffffffec, 0x14);
            local_74 = lbl_803E0E50 * (f32)(s32)
            uStack_2c;
            uStack_24 = randomGetRange(8, 0x14);
            local_70 = lbl_803E0E50 * (f32)(s32)
            uStack_24;
            uStack_1c = randomGetRange(0xffffffec, 0x14);
            local_6c = lbl_803E0E50 * (f32)(s32)
            uStack_1c;
            local_5c = lbl_803E0E58;
            local_98[2] = 0x32;
            local_54 = 0x3000200;
            local_50 = 0x200020;
            local_56 = 0x33;
            local_38 = 0xff;
            local_40 = 0xffff;
            local_3e = 0xffff;
            local_3c = 0xffff;
            local_4c = 0xffff;
            local_48 = randomGetRange(0, 0x8000);
            local_64 = lbl_803E0E5C;
            local_44 = local_48;
            break;
        default:
            return 0xffffffff;
        case 0x73d:
            uStack_1c = randomGetRange(0xfffffff6, 10);
            local_68 = lbl_803E0E3C * (f32)(s32)
            uStack_1c;
            uStack_24 = randomGetRange(0xfffffff6, 100);
            local_64 = lbl_803E0E50 * (f32)(s32)
            uStack_24;
            uStack_2c = randomGetRange(0xfffffff6, 10);
            local_60 = lbl_803E0E3C * (f32)(s32)
            uStack_2c;
            uStack_14 = randomGetRange(7, 9);
            local_5c = lbl_803E0E60 *
                lbl_803E0E64 * (f32)(s32)
            uStack_14;
            local_98[2] = 0x3c;
            local_54 = 0x80100;
            local_37 = 0x10;
            local_56 = 0xde;
            break;
        case 0x73e:
            uStack_14 = randomGetRange(0xfffffff6, 10);
            local_68 = lbl_803E0E3C * (f32)(s32)
            uStack_14;
            uStack_1c = randomGetRange(0xfffffff6, 100);
            local_64 = lbl_803E0E50 * (f32)(s32)
            uStack_1c;
            uStack_24 = randomGetRange(0xfffffff6, 10);
            local_60 = lbl_803E0E3C * (f32)(s32)
            uStack_24;
            uStack_2c = randomGetRange(7, 9);
            local_5c = lbl_803E0E60 *
                lbl_803E0E64 * (f32)(s32)
            uStack_2c;
            local_98[2] = 0x3c;
            local_54 = 0x80100;
            local_37 = 0x10;
            local_56 = 0xdf;
            break;
        case 0x73f:
            if (param_6 == 0)
            {
                uStack_14 = randomGetRange(0xfffffff6, 10);
                local_68 = lbl_803E0E3C *
                    (f32)(s32)
                uStack_14;
                uStack_1c = randomGetRange(0xfffffff6, 100);
                local_64 = lbl_803E0E50 *
                    (f32)(s32)
                uStack_1c;
                uStack_24 = randomGetRange(0xfffffff6, 10);
                uStack_24 = uStack_24 ^ 0x80000000;
                local_60 = lbl_803E0E3C *
                    (f32)(s32)
                uStack_24;
            }
            else
            {
                uStack_14 = randomGetRange(0xfffffff6, 10);
                local_68 = lbl_803E0E3C *
                    (f32)(s32)
                uStack_14 +
                    lbl_803E0E68;
                uStack_1c = randomGetRange(0xfffffff6, 100);
                local_64 = lbl_803E0E50 *
                    (f32)(s32)
                uStack_1c +
                    lbl_803E0E6C;
                uStack_24 = randomGetRange(0xfffffff6, 10);
                uStack_24 = uStack_24 ^ 0x80000000;
                local_60 = lbl_803E0E3C *
                    (f32)(s32)
                uStack_24 +
                    lbl_803E0E70;
            }
            local_28 = 0x43300000;
            uStack_14 = randomGetRange(7, 9);
            local_5c = lbl_803E0E74 *
                lbl_803E0E64 * (f32)(s32)
            uStack_14;
            local_98[2] = 0x3c;
            local_54 = 0x80100;
            local_37 = 0x10;
            local_56 = 0xde;
            break;
        case 0x740:
            if (param_6 == 0)
            {
                uStack_14 = randomGetRange(0xfffffff6, 10);
                local_68 = lbl_803E0E3C *
                    (f32)(s32)
                uStack_14;
                uStack_1c = randomGetRange(0xfffffff6, 100);
                local_64 = lbl_803E0E50 *
                    (f32)(s32)
                uStack_1c;
                uStack_24 = randomGetRange(0xfffffff6, 10);
                uStack_24 = uStack_24 ^ 0x80000000;
                local_60 = lbl_803E0E3C *
                    (f32)(s32)
                uStack_24;
            }
            else
            {
                uStack_14 = randomGetRange(0xfffffff6, 10);
                local_68 = lbl_803E0E3C *
                    (f32)(s32)
                uStack_14 +
                    lbl_803E0E68;
                uStack_1c = randomGetRange(0xfffffff6, 100);
                local_64 = lbl_803E0E50 *
                    (f32)(s32)
                uStack_1c +
                    lbl_803E0E6C;
                uStack_24 = randomGetRange(0xfffffff6, 10);
                uStack_24 = uStack_24 ^ 0x80000000;
                local_60 = lbl_803E0E3C *
                    (f32)(s32)
                uStack_24 +
                    lbl_803E0E70;
            }
            local_28 = 0x43300000;
            uStack_14 = randomGetRange(7, 9);
            local_5c = lbl_803E0E74 *
                lbl_803E0E64 * (f32)(s32)
            uStack_14;
            local_98[2] = 0x3c;
            local_54 = 0x80100;
            local_37 = 0x10;
            local_56 = 0xdf;
            break;
        case 0x741:
            if (param_3 != (undefined2*)0x0)
            {
                local_64 = ((PartFxSpawnParams*)param_3)->posY;
            }
            local_5c = lbl_803E0E78;
            local_98[2] = randomGetRange(0, 0x1e);
            local_98[2] = local_98[2] + 0x50;
            local_38 = 0x60;
            local_54 = 0x80110;
            local_56 = 0x7b;
            local_37 = 0x20;
            break;
        case 0x742:
            local_6c = lbl_803E0E7C;
            uStack_14 = randomGetRange(0xffffffec, 0x14);
            local_74 = lbl_803E0E80 * (f32)(s32)
            uStack_14;
            uStack_1c = randomGetRange(0xffffffec, 0x14);
            local_70 = lbl_803E0E80 * (f32)(s32)
            uStack_1c;
            local_5c = lbl_803E0E84;
            local_98[2] = randomGetRange(0x46, 0x50);
            local_38 = 0xff;
            local_54 = 0x82000104;
            local_50 = 0x400;
            local_56 = 0x3f4;
            break;
        case 0x743:
            local_6c = lbl_803E0E7C;
            uStack_14 = randomGetRange(0xffffffec, 0x14);
            local_74 = lbl_803E0E80 * (f32)(s32)
            uStack_14;
            uStack_1c = randomGetRange(0xffffffec, 0x14);
            local_70 = lbl_803E0E80 * (f32)(s32)
            uStack_1c;
            local_5c = lbl_803E0E84;
            local_98[2] = randomGetRange(0x46, 0x50);
            local_38 = 0xff;
            local_54 = 0x82000104;
            local_50 = 0x400;
            local_56 = 0x500;
            break;
        case 0x744:
            uVar2 = randomGetRange(0, 4);
            if (uVar2 == 4)
            {
                local_5c = lbl_803E0E88;
                local_38 = 0x9b;
                local_54 = 0x480000;
                local_98[2] = randomGetRange(0x1e, 0x28);
            }
            else
            {
                local_5c = lbl_803E0E8C;
                local_38 = 0x7d;
                local_54 = 0x180000;
                local_98[2] = 0x50;
            }
            local_50 = 0x2000000;
            local_56 = 0x88;
        }
        local_54 = local_54 | param_4;
        if (((local_54 & 1) != 0) && ((local_54 & 2) != 0))
        {
            local_54 = local_54 ^ 2;
        }
        if ((local_54 & 1) != 0)
        {
            if ((param_4 & 0x200000) == 0)
            {
                if (local_98[0] != 0)
                {
                    local_68 = local_68 + *(float*)(local_98[0] + 0x18);
                    local_64 = local_64 + *(float*)(local_98[0] + 0x1c);
                    local_60 = local_60 + *(float*)(local_98[0] + 0x20);
                }
            }
            else
            {
                local_68 = local_68 + local_80;
                local_64 = local_64 + local_7c;
                local_60 = local_60 + local_78;
            }
        }
        uVar1 = (*gExpgfxInterface)->spawnEffect(local_98, 0xffffffff, param_2, 0);
    }
    return uVar1;
}

undefined4 FUN_800c9030(uint param_1, int* param_2)
{
    int iVar1;
    int iVar2;
    int iVar3;

    *param_2 = -1;
    if ((int)param_1 < 0)
    {
        return 0;
    }
    iVar1 = DAT_803de090 + -1;
    iVar2 = 0;
    while (true)
    {
        while (true)
        {
            if (iVar1 < iVar2)
            {
                *param_2 = -1;
                return 0;
            }
            iVar3 = iVar1 + iVar2 >> 1;
            if (param_1 <= (uint)(&DAT_8039d0b8)[iVar3 * 2]) break;
            iVar2 = iVar3 + 1;
        }
        if ((uint)(&DAT_8039d0b8)[iVar3 * 2] <= param_1) break;
        iVar1 = iVar3 + -1;
    }
    *param_2 = iVar3;
    return (&DAT_8039d0bc)[iVar3 * 2];
}

extern s16 lbl_803DD414;
extern s16 lbl_803DD416;

typedef struct PartFxKV
{
    u32 key;
    u32 value;
} PartFxKV;

extern f32 lbl_803E04E8;
extern f32 lbl_803E0500;

extern f32 timeDelta;
extern f32 mathSinf(f32 x);

extern f32 sqrtf(f32);

typedef struct PartFxNode
{
    u8 _pad0[0xc];
    f32 _0xc;
    s32 _0x10;
    u8 _pad14[4];
    s32 _0x18;
    s32 _0x1c;
    s32 _0x20;
} PartFxNode;

#pragma dont_inline on
u32 Checkpoint_find(s32 key, s32* idx_out)
{
    extern PartFxKV lbl_8039C458[]; /* #57 */
    extern s32 lbl_803DD410; /* #57 */
    s32 high;
    s32 low;
    s32 mid;
    *idx_out = -1;
    if (key < 0) return 0;
    high = lbl_803DD410 - 1;
    low = 0;
    while (high >= low)
    {
        mid = (high + low) >> 1;
        if ((u32)key > lbl_8039C458[mid].key)
        {
            low = mid + 1;
        }
        else if ((u32)key < lbl_8039C458[mid].key)
        {
            high = mid - 1;
        }
        else
        {
            *idx_out = mid;
            return lbl_8039C458[mid].value;
        }
    }
    *idx_out = -1;
    return 0;
}

extern f32 lbl_803E04D8;
extern f32 lbl_803E04DC;
extern f32 lbl_803E04E0;
extern f32 lbl_803E04E4;
extern f32 mathCosf(f32 x);

#pragma dont_inline off
s32 fn_800D55BC(u8* p, s32 idx, f32* out1, f32* out2, f32* out3, u8 mode, f32 fa, f32 fb)
{
    s32 ret;
    s32 local_idx;
    u8* q;
    f32 cosA;
    f32 sinA;
    f32 cosB;
    f32 sinB;
    f32 sclA;
    f32 sclB;
    s32 i;
    s32 j;
    f32* v3;

    ret = 1;
    if (p == NULL)
    {
        return 0;
    }
    q = (u8*)Checkpoint_find(((s32*)(p + 0x20))[idx], &local_idx);
    if (q == NULL)
    {
        q = (u8*)Checkpoint_find(((s32*)(p + 0x20))[1 - idx], &local_idx);
        ret = 2;
    }
    if (q == NULL)
    {
        return 0;
    }

    cosA = -mathSinf(lbl_803E04D8 * (f32)(*(u8*)(p + 0x29) << 8) / lbl_803E04DC);
    sinA = -mathCosf(lbl_803E04D8 * (f32)(*(u8*)(p + 0x29) << 8) / lbl_803E04DC);
    cosB = -mathSinf(lbl_803E04D8 * (f32)(*(u8*)(q + 0x29) << 8) / lbl_803E04DC);
    sinB = -mathCosf(lbl_803E04D8 * (f32)(*(u8*)(q + 0x29) << 8) / lbl_803E04DC);
    sclA = lbl_803E04E0 * (f32)(u32) * (u8*)(p + 0x2a);
    sclB = lbl_803E04E0 * (f32)(u32) * (u8*)(q + 0x2a);

    if (mode == 1)
    {
        f32 prodA;
        f32 prodB;
        f32 prodC;
        f32 prodD;
        j = 0;
        i = 0;
        v3 = out3;
        prodA = sclA * sinA;
        prodB = sclB * sinB;
        prodC = sclA * -cosA;
        prodD = sclB * -cosB;
        do
        {
            u8* pp;
            u8* qq;
            pp = p + i;
            out1[0] = (f32) * (s8*)(pp + 0x2d) * prodA + *(f32*)(p + 8);
            qq = q + i;
            out1[1] = (f32) * (s8*)(qq + 0x2d) * prodB + *(f32*)(q + 8);
            out1[2] = 2.0f * ((f32)(u32) * (u8*)(p + 0x3d) *
                mathSinf(3.1415927f * (f32)(*(u8*)(p + 0x3e) << 8) / 32768.0f));
            out1[3] = 2.0f * ((f32)(u32) * (u8*)(q + 0x3d) *
                mathSinf(3.1415927f * (f32)(*(u8*)(q + 0x3e) << 8) / 32768.0f));
            out2[0] = sclA * (f32) * (s8*)(pp + 0x31) + *(f32*)(p + 0xc);
            out2[1] = sclB * (f32) * (s8*)(qq + 0x31) + *(f32*)(q + 0xc);
            out2[2] = 0.0f;
            out2[3] = 0.0f;
            v3[0] = (f32) * (s8*)(pp + 0x2d) * prodC + *(f32*)(p + 0x10);
            v3[1] = (f32) * (s8*)(qq + 0x2d) * prodD + *(f32*)(q + 0x10);
            v3[2] = 2.0f * ((f32)(u32) * (u8*)(p + 0x3d) *
                mathCosf(3.1415927f * (f32)(*(u8*)(p + 0x3e) << 8) / 32768.0f));
            v3[3] = 2.0f * ((f32)(u32) * (u8*)(q + 0x3d) *
                mathCosf(3.1415927f * (f32)(*(u8*)(q + 0x3e) << 8) / 32768.0f));
            i += 1;
            out1 += 4;
            out2 += 4;
            v3 += 4;
            j += 4;
        }
        while (j < 0x10);
    }
    else if (mode == 0)
    {
        out1[0] = fa * (sclA * sinA) + *(f32*)(p + 8);
        out1[1] = fa * (sclB * sinB) + *(f32*)(q + 8);
        out1[2] = lbl_803E04E4 * ((f32)(u32) * (u8*)(p + 0x3d) *
            mathSinf(lbl_803E04D8 * (f32)(*(u8*)(p + 0x3e) << 8) / lbl_803E04DC));
        out1[3] = lbl_803E04E4 * ((f32)(u32) * (u8*)(q + 0x3d) *
            mathSinf(lbl_803E04D8 * (f32)(*(u8*)(q + 0x3e) << 8) / lbl_803E04DC));
        out2[0] = sclA * fb + *(f32*)(p + 0xc);
        out2[1] = sclB * fb + *(f32*)(q + 0xc);
        {
            f32 e8 = lbl_803E04E8;
            out2[2] = e8;
            out2[3] = e8;
        }
        out3[0] = fa * (sclA * -cosA) + *(f32*)(p + 0x10);
        out3[1] = fa * (sclB * -cosB) + *(f32*)(q + 0x10);
        out3[2] = lbl_803E04E4 * ((f32)(u32) * (u8*)(p + 0x3d) *
            mathCosf(lbl_803E04D8 * (f32)(*(u8*)(p + 0x3e) << 8) / lbl_803E04DC));
        out3[3] = lbl_803E04E4 * ((f32)(u32) * (u8*)(q + 0x3d) *
            mathCosf(lbl_803E04D8 * (f32)(*(u8*)(q + 0x3e) << 8) / lbl_803E04DC));
    }
    else
    {
        u8* pp;
        u8* qq;
        pp = p + (mode - 2);
        out1[0] = (f32) * (s8*)(pp + 0x2d) * (sclA * sinA) + *(f32*)(p + 8);
        qq = q + (mode - 2);
        out1[1] = (f32) * (s8*)(qq + 0x2d) * (sclB * sinB) + *(f32*)(q + 8);
        out1[2] = lbl_803E04E4 * ((f32)(u32) * (u8*)(p + 0x3d) *
            mathSinf(lbl_803E04D8 * (f32)(*(u8*)(p + 0x3e) << 8) / lbl_803E04DC));
        out1[3] = lbl_803E04E4 * ((f32)(u32) * (u8*)(q + 0x3d) *
            mathSinf(lbl_803E04D8 * (f32)(*(u8*)(q + 0x3e) << 8) / lbl_803E04DC));
        out2[0] = sclA * (f32) * (s8*)(pp + 0x31) + *(f32*)(p + 0xc);
        out2[1] = sclB * (f32) * (s8*)(qq + 0x31) + *(f32*)(q + 0xc);
        {
            f32 e8 = lbl_803E04E8;
            out2[2] = e8;
            out2[3] = e8;
        }
        out3[0] = (f32) * (s8*)(pp + 0x2d) * (sclA * -cosA) + *(f32*)(p + 0x10);
        out3[1] = (f32) * (s8*)(qq + 0x2d) * (sclB * -cosB) + *(f32*)(q + 0x10);
        out3[2] = lbl_803E04E4 * ((f32)(u32) * (u8*)(p + 0x3d) *
            mathCosf(lbl_803E04D8 * (f32)(*(u8*)(p + 0x3e) << 8) / lbl_803E04DC));
        out3[3] = lbl_803E04E4 * ((f32)(u32) * (u8*)(q + 0x3d) *
            mathCosf(lbl_803E04D8 * (f32)(*(u8*)(q + 0x3e) << 8) / lbl_803E04DC));
    }
    return ret;
}

u32 Checkpoint_func0E(s32* p)
{
    extern u32 lbl_803DD418; /* #57 */
    *p = lbl_803DD414;
    return lbl_803DD418;
}

void fn_800D6584(void)
{
    extern u32 lbl_803DD418; /* #57 */
    extern u32 lbl_803DD41C; /* #57 */
    u32 tmp = lbl_803DD418;
    lbl_803DD418 = lbl_803DD41C;
    lbl_803DD41C = tmp;
    lbl_803DD414 = lbl_803DD416;
    lbl_803DD416 = 0;
}

/* Rank object r3 against array at lbl_803DD418 by (int@0x1c, float@0xc) descending. */
typedef struct PartFxItem
{
    u8 _pad0[0xc];
    f32 _0xc;
    u8 _pad10[0xc];
    s32 _0x1c;
} PartFxItem;

s32 Checkpoint_func0F(PartFxItem* p)
{
    extern u32 lbl_803DD418; /* #57 */
    PartFxItem* q;
    s32 rank = 1;
    PartFxItem** arr = (PartFxItem**)lbl_803DD418;
    s32 i;
    for (i = 0; i < lbl_803DD414; i++)
    {
        q = arr[i];
        if (q != p)
        {
            if (q->_0x1c > p->_0x1c)
            {
                rank++;
            }
            else if (q->_0x1c == p->_0x1c)
            {
                if (q->_0xc > p->_0xc)
                {
                    rank++;
                }
            }
        }
    }
    return rank;
}

PartFxItem* Checkpoint_func10(s32 target_rank)
{
    extern u32 lbl_803DD418; /* #57 */
    s32 i = 0;
    PartFxItem** outer = (PartFxItem**)lbl_803DD418;
    PartFxItem** base = outer;
    s32 n = lbl_803DD414;
    for (; i < n; i++)
    {
        PartFxItem* cur = *outer;
        s32 rank = 1;
        PartFxItem** inner = base;
        s32 j;
        for (j = 0; j < n; j++)
        {
            PartFxItem* other = *inner;
            if (other != cur)
            {
                if (other->_0x1c > cur->_0x1c)
                {
                    rank++;
                }
                else if (other->_0x1c == cur->_0x1c)
                {
                    if (other->_0xc > cur->_0xc)
                    {
                        rank++;
                    }
                }
            }
            inner++;
        }
        if (rank == target_rank)
        {
            return cur;
        }
        outer++;
    }
    return 0;
}

void Checkpoint_func0A(s32 key, f32* out_vec, u8* flag_byte)
{
    s32 local_idx;
    PartFxNode* n;
    s32 alt_found;
    n = (PartFxNode*)Checkpoint_find(key, &local_idx);
    if (n == 0) return;
    out_vec[0] = (f32)(s32)
    randomGetRange(-0x63, 0x63) / lbl_803E0500;
    out_vec[1] = (f32)(s32)
    randomGetRange(-0x63, 0x63) / lbl_803E0500;
    out_vec[2] = (f32)(s32)
    randomGetRange(0, 0x63) / lbl_803E0500;
    alt_found = 0;
    {
        s32 v = n->_0x20;
        if (v != 0)
        {
            PartFxNode* m = (PartFxNode*)Checkpoint_find(v, &local_idx);
            if (m->_0x20 > -1)
            {
                alt_found = 1;
            }
        }
    }
    if ((s8) * flag_byte == 0)
    {
        if (alt_found != 0)
        {
            *(s32*)(out_vec + 4) = n->_0x20;
        }
        else
        {
            s32 v = n->_0x18;
            if (v > -1)
            {
                *(s32*)(out_vec + 4) = v;
                *flag_byte = 1;
            }
        }
    }
    else
    {
        s32 v = n->_0x18;
        if (v != 0)
        {
            *(s32*)(out_vec + 4) = v;
        }
        else if (alt_found != 0)
        {
            *(s32*)(out_vec + 4) = n->_0x20;
            *flag_byte = 0;
        }
    }
}

void Checkpoint_func0C(PartFxNode* o)
{
    s32 local_idx;
    PartFxNode* ret;
    s32 nxt;
    ret = (PartFxNode*)Checkpoint_find(o->_0x10, &local_idx);
    if (ret == 0)
    {
        o->_0x18 = 0;
        o->_0xc = lbl_803E04E8;
    }
    else
    {
        while ((nxt = ret->_0x18) > -1)
        {
            ret = (PartFxNode*)Checkpoint_find(nxt, &local_idx);
            o->_0x1c = o->_0x1c + 1;
        }
        o->_0x18 = o->_0x10;
        o->_0xc = lbl_803E04E8;
    }
}

/* Append v to array pointed to by lbl_803DD41C, capped at 10 entries.
 * NOTE: stuck at ~78% ? instruction scheduling differs. */
void Checkpoint_func0D(u32 v)
{
    extern u32 lbl_803DD41C; /* #57 */
    if (lbl_803DD416 >= 10) return;
    ((u32*)lbl_803DD41C)[lbl_803DD416++] = v;
}

void Effect16_func05(void);

/*
 * Field names inherited from ExpgfxSpawnConfig (include/main/expgfx_internal.h),
 * the consumer-side definition of this 0x64-byte spawn request consumed by
 * gExpgfxInterface->spawnEffect (expgfx_addremove). Widths kept as written here
 * (colorWord0..2 are the u16 spelling of the consumer's ExpgfxSpawnColorPair;
 * effectIdByte/modelIdByte land in bytes the consumer currently ignores).
 */

int Checkpoint_func09_ret_1(void) { return 0x1; }

extern f32 lbl_803E0504;
extern f32 lbl_803E0508;
extern f32 Curve_EvalHermite(f32* values, f32 t, f32* outTangent);

s32 Checkpoint_func08(u8* out, u8* o, f32 dist, s32 p3, u8 flag)
{
    extern u16 getAngle(f32 a, f32 b); /* #57 */
    f32 v1[4];
    f32 v2[4];
    f32 v3[4];
    f32 outX;
    f32 outY;
    f32 outZ;
    s32 local_idx;
    s32 mode;
    s32 alt;
    u8* n;
    s32 i;
    s8 clamp;
    s32 ang1;
    s32 ang2;
    f32 kMax;
    f32 kMin;
    f32 t;
    f32 seg;
    f32 x;
    f32 y;
    f32 z;
    f32 len;

    i = 0;
    mode = p3 + 2;
    kMin = lbl_803E04E8;
    kMax = lbl_803E0504;
    do
    {
        if (*(s32*)(o + 0x10) < 0)
        {
            return 1;
        }
        n = (u8*)Checkpoint_find(*(s32*)(o + 0x10), &local_idx);
        if (n == NULL)
        {
            return 1;
        }
        if (*(s32*)(n + 0x20) < 0)
        {
            *(s32*)(o + 0x10) = -1;
            return 1;
        }
        alt = 0;
        if (*(s32*)(n + 0x24) > -1 && *(u8*)(o + 0x30) != 0)
        {
            alt = 1;
        }
        if (fn_800D55BC(n, alt, v1, v2, v3, mode, lbl_803E04E8, *(f32*)&lbl_803E04E8) == 0)
        {
            return 1;
        }
        len = sqrtf((v3[0] - v3[1]) * (v3[0] - v3[1]) +
            ((v1[0] - v1[1]) * (v1[0] - v1[1]) + (v2[0] - v2[1]) * (v2[0] - v2[1])));
        t = *(f32*)(o + 8) + dist / len;
        clamp = 0;
        if (t < kMin)
        {
            t = kMin;
            clamp = -1;
        }
        if (t > kMax)
        {
            t = kMax;
            clamp = 1;
        }
        x = Curve_EvalHermite(v1, t, &outX);
        y = Curve_EvalHermite(v2, t, &outY);
        z = Curve_EvalHermite(v3, t, &outZ);
        ang1 = getAngle(outX, outZ) + 0x8000;
        if (flag != 0)
        {
            f32 xd;
            f32 zd;
            ang2 = getAngle(sqrtf(outX * outX + outZ * outZ), outY) - 0x4000;
            xd = x - *(f32*)(out + 0xc);
            zd = z - *(f32*)(out + 0x14);
            seg = sqrtf(xd * xd + zd * zd);
        }
        else
        {
            f32 xd;
            f32 zd;
            xd = x - *(f32*)(out + 0xc);
            zd = z - *(f32*)(out + 0x14);
            seg = sqrtf(xd * xd + zd * zd);
        }
        if (dist < kMin)
        {
            seg = -seg;
        }
        if (clamp == -1 && seg < dist)
        {
            *(s32*)(o + 0x10) = *(s32*)(n + alt * 4 + 0x18);
            *(f32*)(o + 8) = lbl_803E0508;
            if (alt != 0 && *(s32*)(o + 0x10) < 0)
            {
                *(s32*)(o + 0x10) = *(s32*)(n + 0x18);
            }
        }
        else if (clamp == 1 && seg < dist)
        {
            *(s32*)(o + 0x10) = *(s32*)(n + alt * 4 + 0x20);
            *(f32*)(o + 8) = lbl_803E04E8;
            if (alt != 0 && *(s32*)(o + 0x10) < 0)
            {
                *(s32*)(o + 0x10) = *(s32*)(n + 0x20);
            }
        }
        else
        {
            *(f32*)(o + 8) = t;
        }
        dist -= seg;
        *(f32*)(out + 0xc) = x;
        if (flag != 0)
        {
            *(f32*)(out + 0x10) = y;
        }
        *(f32*)(out + 0x14) = z;
        i += 1;
    }
    while (i < 3);
    *(s16*)(out + 0) = (s16)ang1;
    if (flag != 0)
    {
        *(s16*)(out + 2) = (s16)ang2;
    }
    return 0;
}

void Checkpoint_onGameLoop(void)
{
    extern u32 lbl_803DD418; /* #57 */
    extern u32 lbl_803DD41C; /* #57 */
    u32 tmp = lbl_803DD418;
    lbl_803DD418 = lbl_803DD41C;
    lbl_803DD41C = tmp;
    lbl_803DD414 = lbl_803DD416;
    lbl_803DD416 = 0;
}

#pragma dont_inline reset
#pragma dont_inline reset

#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/baddie_state.h"

extern f32 sqrtf(f32 x);
extern f32 lbl_803E050C;
extern f32 lbl_803E0510;
extern f32 lbl_803E0514;
extern f32 lbl_803E0518;

#pragma opt_common_subs off
int Checkpoint_func07(int* obj, int* state)
{
    extern int getAngle(f32 dx, f32 dz); /* #57 */
    extern int* Checkpoint_find(int id, int* slot); /* #57 */
    int slotC;
    int slot8;
    char* cp;
    char* cp2;
    short ang;
    f32 cosv, sinv, cos2, sin2;
    f32 dist, dist2, nx, nz, offs, dz;
    f32 offs2, distA, distB, dx, dy, len, q, proj, proj2, t0, sum, frac, zero;

    if (*(int*)&((BaddieState*)state)->posY < 0)
    {
        *(int*)&((BaddieState*)state)->posZ = 0;
        *(f32*)((char*)state + 0xc) = lbl_803E04E8;
        if (*(int*)((char*)state + 0x10) < 0)
        {
            return 0;
        }
        *(int*)&((BaddieState*)state)->posY = *(int*)((char*)state + 0x10);
    }
    cp = (char*)Checkpoint_find(*(int*)&((BaddieState*)state)->posY, &slot8);
    if (cp == NULL)
    {
        *(int*)&((BaddieState*)state)->posY = -1;
        return 0;
    }
    cosv = mathSinf((lbl_803E04D8 * (f32)(*(u8*)(cp + 0x29) << 8)) / lbl_803E04DC);
    sinv = mathCosf((lbl_803E04D8 * (f32)(*(u8*)(cp + 0x29) << 8)) / lbl_803E04DC);
    offs = -(*(f32*)(cp + 8) * cosv + *(f32*)(cp + 0x10) * sinv);
    dist = offs + (cosv * ((GameObject*)obj)->anim.localPosX + sinv * ((GameObject*)obj)->anim.localPosZ);
    if (*(int*)(cp + 0x18) > -1 && dist >= lbl_803E04E8)
    {
        *(int*)&((BaddieState*)state)->posY = *(int*)(cp + 0x18);
        *(f32*)((char*)state + 0xc) = lbl_803E050C;
        *(int*)&((BaddieState*)state)->posZ = *(int*)&((BaddieState*)state)->posZ - 1;
        return *(u8*)(cp + 0x29);
    }
    if (*(int*)(cp + 0x20) < 0)
    {
        return *(u8*)(cp + 0x29);
    }
    cp2 = (char*)Checkpoint_find(*(int*)(cp + 0x20), &slotC);
    ang = getAngle(*(f32*)(cp2 + 8) - *(f32*)(cp + 8), *(f32*)(cp2 + 0x10) - *(f32*)(cp + 0x10));
    cos2 = mathSinf((lbl_803E04D8 * (f32)(*(u8*)(cp2 + 0x29) << 8)) / lbl_803E04DC);
    sin2 = mathCosf((lbl_803E04D8 * (f32)(*(u8*)(cp2 + 0x29) << 8)) / lbl_803E04DC);
    offs2 = -(*(f32*)(cp2 + 8) * cos2 + *(f32*)(cp2 + 0x10) * sin2);
    dist2 = offs2 + (cos2 * ((GameObject*)obj)->anim.localPosX + sin2 * ((GameObject*)obj)->anim.localPosZ);
    zero = lbl_803E04E8;
    if (dist2 < zero)
    {
        *(int*)&((BaddieState*)state)->posY = *(int*)(cp + 0x20);
        *(f32*)((char*)state + 0xc) = zero;
        *(int*)&((BaddieState*)state)->posZ = *(int*)&((BaddieState*)state)->posZ + 1;
        return ang;
    }
    distA = offs + (cosv * *(f32*)(cp2 + 8) + sinv * *(f32*)(cp2 + 0x10));
    distB = offs2 + (cos2 * *(f32*)(cp + 8) + sin2 * *(f32*)(cp + 0x10));
    if (((distA < zero && dist < zero) || (distA >= lbl_803E04E8 && dist >= lbl_803E04E8)) &&
        ((distB <= lbl_803E04E8 && dist2 <= lbl_803E04E8) || (distB > lbl_803E04E8 && dist2 > lbl_803E04E8)))
    {
        dx = *(f32*)(cp + 8) - *(f32*)(cp2 + 8);
        dy = *(f32*)(cp + 0xc) - *(f32*)(cp2 + 0xc);
        dz = *(f32*)(cp + 0x10) - *(f32*)(cp2 + 0x10);
        len = sqrtf(dz * dz + (dx * dx + dy * dy));
        if (len > lbl_803E04E8)
        {
            q = lbl_803E0504 / len;
            nx = dx * q;
            nz = dz * q;
        }
        proj = cosv * nx + sinv * nz;
        if (proj > lbl_803E0510 && proj < lbl_803E0514)
        {
            return ang;
        }
        t0 = -dist / proj;
        proj2 = cos2 * nx + sin2 * nz;
        if (proj2 > lbl_803E0510 && proj2 < lbl_803E0514)
        {
            return ang;
        }
        sum = t0 + dist2 / proj2;
        frac = lbl_803E04E8;
        if (lbl_803E04E8 != sum)
        {
            frac = t0 / sum;
        }
        *(f32*)((char*)state + 0xc) = frac;
        if (*(f32*)((char*)state + 0xc) < lbl_803E04E8)
        {
            *(f32*)((char*)state + 0xc) = lbl_803E04E8;
        }
        if (*(f32*)((char*)state + 0xc) >= lbl_803E0518)
        {
            *(f32*)((char*)state + 0xc) = lbl_803E0518;
        }
    }
    return ang;
}
#pragma opt_common_subs reset

#pragma scheduling on
#pragma peephole on
void Checkpoint_release(void)
{
}

void Checkpoint_reset(void) { extern u32 lbl_803DD410; /* #57 */ lbl_803DD410 = 0x0; }

extern u32 lbl_8039CA98[];

#pragma opt_common_subs off
#pragma opt_common_subs reset

#pragma opt_common_subs off
#pragma opt_common_subs reset

#pragma opt_common_subs off
#pragma opt_common_subs reset

#pragma opt_common_subs off
#pragma opt_common_subs reset

#pragma scheduling off
void Checkpoint_initialise(void)
{
    extern void* lbl_803DD418; /* #57 */
    extern void* lbl_803DD41C; /* #57 */
    extern u32 lbl_803DD410; /* #57 */
    lbl_803DD410 = 0;
    lbl_803DD41C = lbl_8039CA98;
    lbl_803DD418 = (void*)((u8*)lbl_8039CA98 + 0x28);
}

/* Checkpoint_Add: sorted insertion of (entry->_14 as key, entry as pointer) into lbl_8039C458 table. */
typedef struct CheckpointSlot
{
    u32 key;
    void* entry;
} CheckpointSlot;

#pragma opt_common_subs off
#pragma peephole off
void Checkpoint_Add(int* entry)
{
    extern CheckpointSlot lbl_8039C458[]; /* #57 */
    extern u32 lbl_803DD410; /* #57 */
    int i = 0;
    CheckpointSlot* p = lbl_8039C458;
    int count = lbl_803DD410;
    while (i < count && (u32)entry[5] > p[i].key)
    {
        i++;
    }
    {
        CheckpointSlot* end = &lbl_8039C458[count];
        while (count > i)
        {
            end->entry = (end - 1)->entry;
            end->key = (end - 1)->key;
            end--;
            count--;
        }
    }
    lbl_803DD410 = lbl_803DD410 + 1;
    lbl_8039C458[i].entry = entry;
    lbl_8039C458[i].key = entry[5];
}
#pragma opt_common_subs reset

#pragma opt_common_subs off
void Checkpoint_remove(int* obj)
{
    extern CheckpointSlot lbl_8039C458[]; /* #57 */
    extern u32 lbl_803DD410; /* #57 */
    int count;
    int i = 0;
    CheckpointSlot* p = lbl_8039C458;
    CheckpointSlot* e;

    count = lbl_803DD410;

    while (i < count && (u32) * (int*)&((GameObject*)obj)->anim.localPosZ != p[i].key)
    {
        i++;
    }
    if (i >= count) return;
    count = lbl_803DD410 - 1;
    lbl_803DD410 = count;
    e = &lbl_8039C458[i];
    while (i < count)
    {
        e->entry = (e + 1)->entry;
        e->key = (e + 1)->key;
        e++;
        i++;
    }
}
#pragma opt_common_subs reset
#pragma opt_common_subs off
#pragma opt_common_subs reset

#pragma opt_common_subs off
#pragma opt_common_subs reset
#pragma opt_common_subs off
#pragma opt_common_subs reset

#pragma opt_common_subs off
#pragma opt_common_subs reset

extern f64 lbl_803E0520;
extern f32 lbl_803E051C;
extern f32 lbl_803E0528;
extern f32 lbl_803E052C;
extern f32 lbl_803E0530;
extern f32 lbl_803E0534;
extern f32 lbl_803E0538;

void Checkpoint_func06(int* obj, int* state, int filter)
{
    extern CheckpointSlot lbl_8039C458[]; /* #57 */
    extern u32 lbl_803DD410; /* #57 */
    extern int* Checkpoint_find(int id, int* slot); /* #57 */
    int stack[64];
    char visited[200];
    int cur;
    int slot;
    int k, count, i, j;
    char* cp;
    char* p;
    char* n;
    char* e;
    f32 cos1, sin1, cos2, sin2;
    f32 dist1, dist2, nx, nz, offs1, dz;
    f32 offs2, distA, distB, dx, dy, len, q, t0, sum, frac, b1, width;
    f32 px, py, pz, outX, outY;
    f32 ddx, ddy, ddz;

    count = 0;
    for (i = 0; i < (int)lbl_803DD410; i++)
    {
        visited[i] = 0;
    }
    cp = (char*)Checkpoint_find(*(int*)((char*)state + 0x10), &cur);
    if (cp != NULL)
    {
        stack[count++] = cur;
    }
    else
    {
        for (i = 0; i < (int)lbl_803DD410; i++)
        {
            e = (char*)lbl_8039C458[i].entry;
            if (visited[i] == 0 && (filter == -1 || *(s8*)(e + 0x28) == filter))
            {
                ddx = *(f32*)(e + 8) - ((GameObject*)obj)->anim.localPosX;
                ddy = *(f32*)(e + 0xc) - ((GameObject*)obj)->anim.localPosY;
                ddz = *(f32*)(e + 0x10) - ((GameObject*)obj)->anim.localPosZ;
                if (ddz * ddz + (ddx * ddx + ddy * ddy) < lbl_803E051C)
                {
                    stack[count++] = i;
                    for (j = i; j < (int)lbl_803DD410; j++)
                    {
                        if (filter == *(s8*)((char*)lbl_8039C458[j].entry + 0x28))
                        {
                            visited[j] = 1;
                        }
                    }
                }
            }
        }
    }
    for (i = 0; i < (int)lbl_803DD410; i++)
    {
        visited[i] = 0;
    }
    for (;;)
    {
        if (count > 0)
        {
            count--;
            cur = stack[count];
            cp = (char*)lbl_8039C458[cur].entry;
        }
        else
        {
            *(int*)((char*)state + 0x10) = -1;
            return;
        }
        if (cp == NULL)
        {
            return;
        }
        p = cp;
        for (k = 0; k < 2; k++)
        {
            n = (char*)Checkpoint_find(*(int*)(p + 0x20), &slot);
            if (n != NULL)
            {
                cos1 = mathSinf((lbl_803E04D8 * (f32)(*(u8*)(cp + 0x29) << 8)) / lbl_803E04DC);
                sin1 = mathCosf((lbl_803E04D8 * (f32)(*(u8*)(cp + 0x29) << 8)) / lbl_803E04DC);
                offs1 = -(*(f32*)(cp + 8) * cos1 + *(f32*)(cp + 0x10) * sin1);
                cos2 = mathSinf((lbl_803E04D8 * (f32)(*(u8*)(n + 0x29) << 8)) / lbl_803E04DC);
                sin2 = mathCosf((lbl_803E04D8 * (f32)(*(u8*)(n + 0x29) << 8)) / lbl_803E04DC);
                offs2 = -(*(f32*)(n + 8) * cos2 + *(f32*)(n + 0x10) * sin2);
                dist1 = offs1 + (cos1 * ((GameObject*)obj)->anim.localPosX + sin1 * ((GameObject*)obj)->anim.localPosZ);
                dist2 = offs2 + (cos2 * ((GameObject*)obj)->anim.localPosX + sin2 * ((GameObject*)obj)->anim.localPosZ);
                distA = offs1 + (cos1 * *(f32*)(n + 8) + sin1 * *(f32*)(n + 0x10));
                distB = offs2 + (cos2 * *(f32*)(cp + 8) + sin2 * *(f32*)(cp + 0x10));
                if (((distA <= lbl_803E04E8 && dist1 <= lbl_803E04E8) || (distA > lbl_803E04E8 && dist1 > lbl_803E04E8))
                    &&
                    ((distB <= lbl_803E04E8 && dist2 <= lbl_803E04E8) || (distB > lbl_803E04E8 && dist2 >
                        lbl_803E04E8)))
                {
                    dx = *(f32*)(cp + 8) - *(f32*)(n + 8);
                    dy = *(f32*)(cp + 0xc) - *(f32*)(n + 0xc);
                    dz = *(f32*)(cp + 0x10) - *(f32*)(n + 0x10);
                    len = sqrtf(dz * dz + (dx * dx + dy * dy));
                    if (len > lbl_803E0520)
                    {
                        q = lbl_803E0504 / len;
                        nx = dx * q;
                        nz = dz * q;
                    }
                    q = cos1 * nx + sin1 * nz;
                    t0 = -dist1 / q;
                    sum = t0 + dist2 / (cos2 * nx + sin2 * nz);
                    if (sum > lbl_803E0528 || sum < lbl_803E052C)
                    {
                        frac = t0 / sum;
                    }
                    else
                    {
                        frac = lbl_803E04E8;
                    }
                    if (frac < lbl_803E04E8)
                    {
                        frac = lbl_803E04E8;
                    }
                    if (frac >= lbl_803E0518)
                    {
                        frac = lbl_803E0518;
                    }
                    b1 = (f32) * (u8*)(cp + 0x2a);
                    width = frac * ((f32) * (u8*)(n + 0x2a) - b1) + b1;
                    px = -(dx * frac - *(f32*)(cp + 8));
                    py = -(dy * frac - *(f32*)(cp + 0xc));
                    pz = -(dz * frac - *(f32*)(cp + 0x10));
                    outY = (((GameObject*)obj)->anim.localPosY - py) / width;
                    outX = (-(px * nz - pz * nx) + (((GameObject*)obj)->anim.localPosX * nz - ((GameObject*)obj)->anim.
                        localPosZ * nx)) / width;
                    if (outX < lbl_803E0530 || outX > lbl_803E0534 || outY < lbl_803E0538 || outY > lbl_803E0534)
                    {
                    }
                    else
                    {
                        *(int*)((char*)state + 0x10) = *(int*)(cp + 0x14);
                        *(int*)&((BaddieState*)state)->posX = *(int*)(cp + 0x14);
                        *(f32*)((char*)state + 0) = outX;
                        *(f32*)((char*)state + 4) = outY;
                        *(f32*)((char*)state + 8) = frac;
                        *(s16*)((char*)state + 0x20) = *(s8*)(cp + 0x28);
                        return;
                    }
                }
            }
            p += 4;
        }
        if (visited[cur] == 0)
        {
            p = cp + 4;
            for (k = 1; k >= 0; k--)
            {
                n = (char*)Checkpoint_find(*(int*)(p + 0x18), &slot);
                if (n != NULL && visited[slot] == 0 && count < 0x3c)
                {
                    stack[count++] = slot;
                }
                n = (char*)Checkpoint_find(*(int*)(p + 0x20), &slot);
                if (n != NULL && visited[slot] == 0 && count < 0x3c)
                {
                    stack[count++] = slot;
                }
                p -= 4;
            }
            visited[cur] = 1;
        }
    }
}
