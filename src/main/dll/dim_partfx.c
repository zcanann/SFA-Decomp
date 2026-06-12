#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
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

/*
 * --INFO--
 *
 * Function: Effect16_func04
 * EN v1.0 Address: 0x800C8008
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800C8294
 * EN v1.1 Size: 4100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
/* Effect16_func04 is defined further below (full recovered body). */


/*
 * --INFO--
 *
 * Function: FUN_800c8110
 * EN v1.0 Address: 0x800C8110
 * EN v1.0 Size: 904b
 * EN v1.1 Address: 0x800CABBC
 * EN v1.1 Size: 3116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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
            local_80 = ((PartFxSpawnParams*)param_3)->unkC;
            local_7c = ((PartFxSpawnParams*)param_3)->unk10;
            local_78 = ((PartFxSpawnParams*)param_3)->unk14;
            local_84 = *(undefined4*)&((PartFxSpawnParams*)param_3)->unk8;
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
                local_64 = ((PartFxSpawnParams*)param_3)->unk10;
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


/*
 * --INFO--
 *
 * Function: FUN_800c9030
 * EN v1.0 Address: 0x800C9030
 * EN v1.0 Size: 128b
 * EN v1.1 Address: 0x800D57BC
 * EN v1.1 Size: 140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
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


/* sda21 globals used by leaf accessors below. */
extern s16 lbl_803DD414;
extern s16 lbl_803DD416;

typedef struct PartFxKV
{
    u32 key;
    u32 value;
} PartFxKV;

extern f32 lbl_803E04E8;
extern f32 lbl_803E0500;

/* Globals for tick functions Effect16_func05 / Effect17_func05 / Effect18_func05 / Effect19_func05 / Effect20_func05. */
extern f32 timeDelta;
extern u8 framesThisStep;
extern f32 mathSinf(f32 x);

extern f32 lbl_803DB848;
extern f32 lbl_803DB84C;
extern f32 lbl_803E00A8;
extern f32 lbl_803E00AC;
extern f32 lbl_803E00B0;
extern f32 lbl_803E00B8;
extern s32 lbl_803DD3C0;
extern s32 lbl_803DD3C4;
extern f32 lbl_803DD3C8;
extern f32 lbl_803DD3CC;
extern f32 lbl_803E0108;
extern f32 lbl_803E010C;

extern f32 lbl_803DB858;
extern f32 lbl_803DB85C;
extern f32 lbl_803E01B8;
extern f32 lbl_803E01BC;
extern f32 lbl_803E01C0;
extern f32 lbl_803E01C8;
extern s32 lbl_803DD3D0;
extern s32 lbl_803DD3D4;
extern f32 lbl_803DD3D8;
extern f32 lbl_803DD3DC;
extern f32 lbl_803E0218;
extern f32 lbl_803E021C;

extern f32 lbl_803DB868;
extern f32 lbl_803DB86C;
extern f32 lbl_803E0220;
extern f32 lbl_803E0224;
extern f32 lbl_803E0228;
extern f32 lbl_803E0230;
extern s32 lbl_803DD3E0;
extern s32 lbl_803DD3E4;
extern f32 lbl_803DD3E8;
extern f32 lbl_803DD3EC;
extern f32 lbl_803E02D0;
extern f32 lbl_803E02D4;

extern f32 lbl_803DB878;
extern f32 lbl_803DB87C;
extern f32 lbl_803E02D8;
extern f32 lbl_803E02DC;
extern f32 lbl_803E02E8;
extern s32 lbl_803DD3F0;
extern s32 lbl_803DD3F4;
extern f32 lbl_803DD3F8;
extern f32 lbl_803DD3FC;
extern f32 lbl_803E0308;
extern f32 lbl_803E030C;

extern f32 lbl_803DB870;
extern f32 lbl_803DB874;
extern f32 lbl_803E02E4;
extern f32 lbl_803E02EC;
extern f32 lbl_803E02F0;
extern f32 lbl_803E02F4;
extern f32 lbl_803E02F8;
extern f32 lbl_803E02FC;

extern f32 lbl_803E0180;
extern f32 lbl_803E0184;
extern f32 lbl_803E0188;
extern f32 lbl_803E018C;
extern f32 lbl_803E0190;
extern f32 lbl_803E0194;
extern f32 lbl_803E0198;
extern f32 lbl_803E019C;
extern f32 lbl_803E01A0;
extern f32 lbl_803E01A4;
extern f32 lbl_803E01A8;
extern f32 lbl_803E01AC;
extern WaterfxInterface** gWaterfxInterface;
extern void Sfx_PlayFromObject(int obj, int sfxId);

typedef struct WaterfxCfg
{
    s16 x;
    s16 y;
    s16 z;
    u8 pad6[2];
    f32 f8;
    f32 fc;
    f32 f10;
    f32 f14;
} WaterfxCfg;

extern WaterfxCfg lbl_8039C440;

extern f32 lbl_803DB850;
extern f32 lbl_803DB854;
extern f32 lbl_803E01C0;
extern f32 lbl_803E01C4;
extern f32 lbl_803E01C8;
extern f32 lbl_803E01CC;
extern f32 lbl_803E01D0;
extern f32 lbl_803E01D4;
extern f32 lbl_803E01D8;
extern f32 lbl_803E01DC;
extern f32 lbl_803E01E0;
extern f32 lbl_803E01E4;
extern f32 lbl_803E01E8;
extern f32 lbl_803E01EC;
extern f32 lbl_803E01F0;
extern f32 lbl_803E01F4;
extern f32 lbl_803E01F8;
extern f32 lbl_803E01FC;
extern f32 lbl_803E0200;
extern f32 lbl_803E0204;
extern f32 lbl_803E0208;
extern f32 lbl_803E020C;

extern f32 lbl_803E0110;
extern f32 lbl_803E0114;
extern f32 lbl_803E0118;
extern f32 lbl_803E011C;
extern f32 lbl_803E0120;
extern f32 lbl_803E0124;
extern f32 lbl_803E0128;
extern f32 lbl_803E012C;
extern f32 lbl_803E0130;
extern f32 lbl_803E0134;
extern f32 lbl_803E0138;
extern f32 lbl_803E013C;
extern f32 lbl_803E0140;
extern f32 lbl_803E0144;
extern f32 lbl_803E0148;
extern f32 lbl_803E014C;
extern f32 lbl_803E0150;
extern f32 lbl_803E0154;
extern f32 lbl_803E0158;
extern f32 lbl_803E015C;
extern f32 lbl_803E0160;
extern f32 lbl_803E0164;
extern f32 lbl_803E0168;
extern f32 lbl_803E016C;
extern f32 lbl_803E0170;
extern f32 lbl_803E0174;
extern WaterfxCfg lbl_8039C428;

extern f32 lbl_803DB840;
extern f32 lbl_803DB844;
extern f32 lbl_803E00B4;
extern f32 lbl_803E00BC;
extern f32 lbl_803E00C0;
extern f32 lbl_803E00C4;
extern f32 lbl_803E00C8;
extern f32 lbl_803E00CC;
extern f32 lbl_803E00D0;
extern f32 lbl_803E00D4;
extern f32 lbl_803E00D8;
extern f32 lbl_803E00DC;
extern f32 lbl_803E00E0;
extern f32 lbl_803E00E4;
extern f32 lbl_803E00E8;
extern f32 lbl_803E00EC;
extern f32 lbl_803E00F0;
extern f32 lbl_803E00F4;
extern f32 lbl_803E00F8;
extern WaterfxCfg lbl_8039C410;

extern f32 lbl_803DB888;
extern f32 lbl_803DB88C;
extern f32 lbl_803E0310;
extern f32 lbl_803E0314;
extern f32 lbl_803E0318;
extern f32 lbl_803E0320;
extern s32 lbl_803DD400;
extern s32 lbl_803DD404;
extern f32 lbl_803DD408;
extern f32 lbl_803DD40C;
extern f32 lbl_803E0344;
extern f32 lbl_803E0348;

extern f32 lbl_803DB860;
extern f32 lbl_803DB864;
extern f32 lbl_803E0228;
extern f32 lbl_803E022C;
extern f32 lbl_803E0230;
extern f32 lbl_803E0234;
extern f32 lbl_803E0238;
extern f32 lbl_803E023C;
extern f32 lbl_803E0240;
extern f32 lbl_803E0244;
extern f32 lbl_803E0248;
extern f32 lbl_803E024C;
extern f32 lbl_803E0250;
extern f32 lbl_803E0254;
extern f32 lbl_803E0258;
extern f32 lbl_803E025C;
extern f32 lbl_803E0260;
extern f32 lbl_803E0264;
extern f32 lbl_803E0268;
extern f32 lbl_803E026C;
extern f32 lbl_803E0270;
extern f32 lbl_803E0274;
extern f32 lbl_803E0278;
extern f32 lbl_803E027C;
extern f32 lbl_803E0280;
extern f32 lbl_803E0284;
extern f32 lbl_803E0288;
extern f32 lbl_803E028C;
extern f32 lbl_803E0290;
extern f32 lbl_803E0294;
extern f32 lbl_803E0298;
extern f32 lbl_803E029C;
extern f32 lbl_803E02A0;
extern f32 lbl_803E02A4;
extern f32 lbl_803E02A8;
extern f32 lbl_803E02AC;
extern f32 lbl_803E02B0;
extern f32 lbl_803E02B4;
extern f32 lbl_803E02B8;
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

/* Binary search for key in lbl_8039C458 (count = lbl_803DD410). */
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

typedef struct CheckpointPair
{
    u8 pad[0x20];
    s32 keys[2];
} CheckpointPair;

/* Build particle quad positions from a checkpoint pair. */
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

/* Set *p to lbl_803DD414 (sign-extended) and return lbl_803DD418. */
u32 Checkpoint_func0E(s32* p)
{
    extern u32 lbl_803DD418; /* #57 */
    *p = lbl_803DD414;
    return lbl_803DD418;
}

/* Swap lbl_803DD418 with lbl_803DD41C; copy 416 into 414 then clear 416. */
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

/* NOTE: 96.8% ? register choice differs (r5 vs r7 for rank). */
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

/* Find item in lbl_803DD418 array whose rank equals target_rank. */
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

/* Init random offsets / chain advance with lookup. */
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

/* Walk a chain via Checkpoint_find lookups starting from o->_0x10. */
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

/* Tick: counter1, counter2 + rate*timeDelta; clamp; periodic sin. */
void Effect16_func05(void)
{
    f32 sum;
    f32 step;
    sum = lbl_803DB848 + (step = lbl_803E00A8 * timeDelta);
    lbl_803DB848 = sum;
    if (sum > 1.0f) lbl_803DB848 = lbl_803E00AC;
    sum = lbl_803DB84C + step;
    lbl_803DB84C = sum;
    if (sum > 1.0f) lbl_803DB84C = lbl_803E00B8;
    lbl_803DD3C0 = lbl_803DD3C0 + (s32)framesThisStep * 0x64;
    if (lbl_803DD3C0 > 0x7fff) lbl_803DD3C0 = 0;
    lbl_803DD3CC = mathSinf(lbl_803E0108 * (f32)(s16)lbl_803DD3C0 / lbl_803E010C);
    lbl_803DD3C4 = lbl_803DD3C4 + (s32)framesThisStep * 0x32;
    if (lbl_803DD3C4 > 0x7fff) lbl_803DD3C4 = 0;
    lbl_803DD3C8 = mathSinf(lbl_803E0108 * (f32)(s16)lbl_803DD3C4 / lbl_803E010C);
}

void Effect17_func05(void)
{
    f32 sum;
    f32 step;
    sum = lbl_803DB858 + (step = lbl_803E01B8 * timeDelta);
    lbl_803DB858 = sum;
    if (sum > 1.0f) lbl_803DB858 = lbl_803E01BC;
    sum = lbl_803DB85C + step;
    lbl_803DB85C = sum;
    if (sum > 1.0f) lbl_803DB85C = lbl_803E01C8;
    lbl_803DD3D0 = lbl_803DD3D0 + (s32)framesThisStep * 0x64;
    if (lbl_803DD3D0 > 0x7fff) lbl_803DD3D0 = 0;
    lbl_803DD3DC = mathSinf(lbl_803E0218 * (f32)(s16)lbl_803DD3D0 / lbl_803E021C);
    lbl_803DD3D4 = lbl_803DD3D4 + (s32)framesThisStep * 0x32;
    if (lbl_803DD3D4 > 0x7fff) lbl_803DD3D4 = 0;
    lbl_803DD3D8 = mathSinf(lbl_803E0218 * (f32)(s16)lbl_803DD3D4 / lbl_803E021C);
}

void Effect18_func05(void)
{
    f32 sum;
    f32 step;
    sum = lbl_803DB868 + (step = lbl_803E0220 * timeDelta);
    lbl_803DB868 = sum;
    if (sum > 1.0f) lbl_803DB868 = lbl_803E0224;
    sum = lbl_803DB86C + step;
    lbl_803DB86C = sum;
    if (sum > 1.0f) lbl_803DB86C = lbl_803E0230;
    lbl_803DD3E0 = lbl_803DD3E0 + (s32)framesThisStep * 0x64;
    if (lbl_803DD3E0 > 0x7fff) lbl_803DD3E0 = 0;
    lbl_803DD3EC = mathSinf(lbl_803E02D0 * (f32)(s16)lbl_803DD3E0 / lbl_803E02D4);
    lbl_803DD3E4 = lbl_803DD3E4 + (s32)framesThisStep * 0x32;
    if (lbl_803DD3E4 > 0x7fff) lbl_803DD3E4 = 0;
    lbl_803DD3E8 = mathSinf(lbl_803E02D0 * (f32)(s16)lbl_803DD3E4 / lbl_803E02D4);
}

/*
 * Field names inherited from ExpgfxSpawnConfig (include/main/expgfx_internal.h),
 * the consumer-side definition of this 0x64-byte spawn request consumed by
 * gExpgfxInterface->spawnEffect (expgfx_addremove). Widths kept as written here
 * (colorWord0..2 are the u16 spelling of the consumer's ExpgfxSpawnColorPair;
 * effectIdByte/modelIdByte land in bytes the consumer currently ignores).
 */
typedef struct PartFxSpawn
{
    void* attachedSource;
    int quadVertex3Pad06;
    int lifetimeFrames;
    s16 sourceVecX;
    s16 sourceVecY;
    s16 sourceVecZ;
    u8 pad12[2];
    f32 sourcePosX;
    f32 sourcePosY;
    f32 sourcePosZ;
    f32 sourcePosW;
    f32 velocityX;
    f32 velocityY;
    f32 velocityZ;
    f32 startPosX;
    f32 startPosY;
    f32 startPosZ;
    f32 scale;
    s16 textureSetupFlags;
    s16 textureId;
    u32 behaviorFlags;
    u32 renderFlags;
    u32 overrideColor0;
    u32 overrideColor1;
    u32 overrideColor2;
    u16 colorWord0;
    u16 colorWord1;
    u16 colorWord2;
    u8 effectIdByte;
    u8 pad5f[1];
    u8 initialAlpha;
    u8 linkGroup;
    u8 modelIdByte;
} PartFxSpawn;

int Effect19_func04(void* sourceObj, int effectId, s16* spawnParams, u32 spawnFlags,
                    u8 modelId, f32* extraArgs)
{
    int spawnResult;
    PartFxSpawn cfg;

    lbl_803DB870 = lbl_803DB870 + lbl_803E02D8;
    if (lbl_803DB870 > 1.0f) lbl_803DB870 = lbl_803E02DC;
    lbl_803DB874 = lbl_803DB874 + lbl_803E02E4;
    if (lbl_803DB874 > 1.0f) lbl_803DB874 = lbl_803E02E8;
    if (sourceObj == 0)
    {
        spawnResult = -1;
    }
    else
    {
        if ((spawnFlags & 0x200000) != 0)
        {
            if (spawnParams == 0) return -1;
            cfg.sourcePosY = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.sourcePosZ = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.sourcePosW = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.sourcePosX = ((PartFxSpawnParams*)spawnParams)->unk8;
            cfg.sourceVecZ = ((PartFxSpawnParams*)spawnParams)->unk4;
            cfg.sourceVecY = ((PartFxSpawnParams*)spawnParams)->unk2;
            cfg.sourceVecX = *spawnParams;
            cfg.modelIdByte = modelId;
        }
        cfg.behaviorFlags = 0;
        cfg.renderFlags = 0;
        cfg.effectIdByte = (u8)effectId;
        cfg.attachedSource = sourceObj;
        cfg.startPosX = lbl_803E02EC;
        cfg.startPosY = lbl_803E02EC;
        cfg.startPosZ = lbl_803E02EC;
        cfg.velocityX = lbl_803E02EC;
        cfg.velocityY = lbl_803E02EC;
        cfg.velocityZ = lbl_803E02EC;
        cfg.scale = lbl_803E02EC;
        cfg.lifetimeFrames = 0;
        cfg.quadVertex3Pad06 = -1;
        cfg.initialAlpha = 0xff;
        cfg.linkGroup = 0;
        cfg.textureId = 0;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0xffff;
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = 0xffff;
        cfg.overrideColor1 = 0xffff;
        cfg.overrideColor2 = 0xffff;
        cfg.textureSetupFlags = 0;
        switch (effectId)
        {
        case 0x76c:
            cfg.velocityX = lbl_803E02F0 * (f32)(s32)
            randomGetRange(0x1e, 0x64);
            if (((PartFxSpawnParams*)spawnParams)->unkC > lbl_803E02EC) cfg.velocityX = -cfg.velocityX;
            cfg.velocityY = lbl_803E02D8 * (f32)(s32)
            randomGetRange(0, 0x64) + lbl_803E02DC;
            cfg.startPosZ = lbl_803E02DC *
                (f32)(s32)
            randomGetRange((s32)extraArgs[0], (s32)extraArgs[1]);
            cfg.startPosX = lbl_803E02F4;
            if (((PartFxSpawnParams*)spawnParams)->unkC > lbl_803E02EC) cfg.startPosX = lbl_803E02F8;
            cfg.scale = lbl_803E02FC * (f32)(s32)
            randomGetRange(-0x64, 0x64) + extraArgs[2];
            cfg.lifetimeFrames = 0x23;
            cfg.behaviorFlags = 0x80108;
            cfg.textureId = 0x60;
            cfg.initialAlpha = 0xc4;
            break;
        default:
            return -1;
        }
        cfg.behaviorFlags = cfg.behaviorFlags | spawnFlags;
        if (((cfg.behaviorFlags & 1) != 0) && ((cfg.behaviorFlags & 2) != 0)) cfg.behaviorFlags ^= 2LL;
        if ((cfg.behaviorFlags & 1) != 0)
        {
            if ((spawnFlags & 0x200000) != 0)
            {
                cfg.startPosX = cfg.startPosX + cfg.sourcePosY;
                cfg.startPosY = cfg.startPosY + cfg.sourcePosZ;
                cfg.startPosZ = cfg.startPosZ + cfg.sourcePosW;
            }
            else if (cfg.attachedSource != 0)
            {
                cfg.startPosX = cfg.startPosX + *(f32*)((char*)cfg.attachedSource + 0x18);
                cfg.startPosY = cfg.startPosY + *(f32*)((char*)cfg.attachedSource + 0x1c);
                cfg.startPosZ = cfg.startPosZ + *(f32*)((char*)cfg.attachedSource + 0x20);
            }
        }
        spawnResult = (*gExpgfxInterface)->spawnEffect(&cfg, -1, effectId, 0);
    }
    return spawnResult;
}

int Effect13_func04(void* sourceObj, int effectId, s16* spawnParams, u32 spawnFlags, u8 modelId)
{
    int spawnResult;
    PartFxSpawn cfg;

    if (sourceObj == 0) return -1;
    if ((spawnFlags & 0x200000) != 0)
    {
        if (spawnParams == 0) return -1;
        cfg.sourcePosY = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.sourcePosZ = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.sourcePosW = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.sourcePosX = ((PartFxSpawnParams*)spawnParams)->unk8;
        cfg.sourceVecZ = ((PartFxSpawnParams*)spawnParams)->unk4;
        cfg.sourceVecY = ((PartFxSpawnParams*)spawnParams)->unk2;
        cfg.sourceVecX = *spawnParams;
        cfg.modelIdByte = modelId;
    }
    cfg.behaviorFlags = 0;
    cfg.renderFlags = 0;
    cfg.effectIdByte = (u8)effectId;
    cfg.attachedSource = sourceObj;
    cfg.startPosX = lbl_803E0180;
    cfg.startPosY = lbl_803E0180;
    cfg.startPosZ = lbl_803E0180;
    cfg.velocityX = lbl_803E0180;
    cfg.velocityY = lbl_803E0180;
    cfg.velocityZ = lbl_803E0180;
    cfg.scale = lbl_803E0180;
    cfg.lifetimeFrames = 0;
    cfg.quadVertex3Pad06 = -1;
    cfg.initialAlpha = 0xff;
    cfg.linkGroup = 0;
    cfg.textureId = 0;
    cfg.colorWord0 = 0xffff;
    cfg.colorWord1 = 0xffff;
    cfg.colorWord2 = 0xffff;
    cfg.overrideColor0 = 0xffff;
    cfg.overrideColor1 = 0xffff;
    cfg.overrideColor2 = 0xffff;
    switch (effectId)
    {
    case 0x44c:
        cfg.velocityX = lbl_803E0184 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityY = lbl_803E0188 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.velocityZ = lbl_803E0184 * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.scale = lbl_803E018C;
        cfg.lifetimeFrames = 0x6e;
        cfg.behaviorFlags = 0x8a100208;
        cfg.renderFlags = 0x20;
        cfg.textureId = 0x5f;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0xffff;
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = 0x400;
        cfg.overrideColor1 = 0xea60;
        cfg.overrideColor2 = 0x1000;
        break;
    case 0x44d:
        cfg.velocityX = lbl_803E018C * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.velocityZ = lbl_803E018C * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.scale = lbl_803E0190;
        cfg.lifetimeFrames = 0x258;
        cfg.initialAlpha = 0x7f;
        cfg.behaviorFlags = 0x0a100100;
        cfg.renderFlags = 0x20;
        cfg.textureId = 0x62;
        cfg.colorWord0 = 0x400;
        cfg.colorWord1 = 0xea60;
        cfg.colorWord2 = 0x1000;
        cfg.overrideColor0 = 0;
        cfg.overrideColor1 = 0xc350;
        cfg.overrideColor2 = 0;
        break;
    case 0x44e:
        cfg.startPosY = lbl_803E0194;
        cfg.scale = lbl_803E0198;
        cfg.lifetimeFrames = 0xc8;
        cfg.behaviorFlags = 0x11000004;
        cfg.textureId = 0x151;
        cfg.quadVertex3Pad06 = 0x44f;
        break;
    case 0x44f:
        if (spawnParams == 0)
        {
            lbl_8039C440.fc = lbl_803E0180;
            lbl_8039C440.f10 = lbl_803E0180;
            lbl_8039C440.f14 = lbl_803E0180;
            lbl_8039C440.f8 = lbl_803E019C;
            lbl_8039C440.x = 0;
            lbl_8039C440.y = 0;
            lbl_8039C440.z = 0;
            spawnParams = (s16*)&lbl_8039C440;
        }
        (*gWaterfxInterface)->spawnSplashBurst(NULL, ((PartFxSpawnParams*)spawnParams)->unkC,
                                               ((PartFxSpawnParams*)spawnParams)->unk10,
                                               ((PartFxSpawnParams*)spawnParams)->unk14, lbl_803E01A0);
        Sfx_PlayFromObject((int)sourceObj, SFXsc_snort02);
        cfg.lifetimeFrames = 1;
        cfg.scale = lbl_803E01A4;
        cfg.behaviorFlags = 0x0a000001;
        cfg.textureId = 0x56;
        break;
    case 0x450:
        cfg.startPosY = lbl_803E01A8;
        cfg.scale = lbl_803E0198;
        cfg.lifetimeFrames = 0xc8;
        cfg.behaviorFlags = 0x11000004;
        cfg.textureId = 0x151;
        cfg.quadVertex3Pad06 = 0x451;
        break;
    case 0x451:
        Sfx_PlayFromObject((int)sourceObj, SFXsc_snort02);
        cfg.lifetimeFrames = 0x64;
        cfg.scale = lbl_803E01AC * (f32)(s32)
        cfg.lifetimeFrames;
        cfg.behaviorFlags = 0x0a100201;
        cfg.textureId = 0x56;
        break;
    default:
        return -1;
    }
    cfg.behaviorFlags = cfg.behaviorFlags | spawnFlags;
    if (((cfg.behaviorFlags & 1) != 0) && ((cfg.behaviorFlags & 2) != 0)) cfg.behaviorFlags ^= 2LL;
    if ((cfg.behaviorFlags & 1) != 0)
    {
        if ((spawnFlags & 0x200000) != 0)
        {
            cfg.startPosX = cfg.startPosX + cfg.sourcePosY;
            cfg.startPosY = cfg.startPosY + cfg.sourcePosZ;
            cfg.startPosZ = cfg.startPosZ + cfg.sourcePosW;
        }
        else
        {
            if (cfg.attachedSource != 0)
            {
                cfg.startPosX = cfg.startPosX + *(f32*)((char*)cfg.attachedSource + 0x18);
                cfg.startPosY = cfg.startPosY + *(f32*)((char*)cfg.attachedSource + 0x1c);
                cfg.startPosZ = cfg.startPosZ + *(f32*)((char*)cfg.attachedSource + 0x20);
            }
        }
    }
    spawnResult = (*gExpgfxInterface)->spawnEffect(&cfg, -1, effectId, 0);
    return spawnResult;
}

int Effect17_func04(void* sourceObj, int effectId, s16* spawnParams, u32 spawnFlags,
                    u8 modelId, s16* extraArgs)
{
    int spawnResult;
    PartFxSpawn cfg;

    lbl_803DB850 = lbl_803DB850 + lbl_803E01B8;
    if (lbl_803DB850 > 1.0f) lbl_803DB850 = lbl_803E01BC;
    lbl_803DB854 = lbl_803DB854 + lbl_803E01C4;
    if (lbl_803DB854 > 1.0f) lbl_803DB854 = lbl_803E01C8;
    if (sourceObj == 0) return -1;
    if ((spawnFlags & 0x200000) != 0)
    {
        if (spawnParams == 0) return -1;
        cfg.sourcePosY = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.sourcePosZ = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.sourcePosW = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.sourcePosX = ((PartFxSpawnParams*)spawnParams)->unk8;
        cfg.sourceVecZ = ((PartFxSpawnParams*)spawnParams)->unk4;
        cfg.sourceVecY = ((PartFxSpawnParams*)spawnParams)->unk2;
        cfg.sourceVecX = *spawnParams;
        cfg.modelIdByte = modelId;
    }
    cfg.behaviorFlags = 0;
    cfg.renderFlags = 0;
    cfg.effectIdByte = (u8)effectId;
    cfg.attachedSource = sourceObj;
    cfg.startPosX = lbl_803E01CC;
    cfg.startPosY = lbl_803E01CC;
    cfg.startPosZ = lbl_803E01CC;
    cfg.velocityX = lbl_803E01CC;
    cfg.velocityY = lbl_803E01CC;
    cfg.velocityZ = lbl_803E01CC;
    cfg.scale = lbl_803E01CC;
    cfg.lifetimeFrames = 0;
    cfg.quadVertex3Pad06 = -1;
    cfg.initialAlpha = 0xff;
    cfg.linkGroup = 0;
    cfg.textureId = 0;
    cfg.colorWord0 = 0xffff;
    cfg.colorWord1 = 0xffff;
    cfg.colorWord2 = 0xffff;
    cfg.overrideColor0 = 0xffff;
    cfg.overrideColor1 = 0xffff;
    cfg.overrideColor2 = 0xffff;
    cfg.textureSetupFlags = 0;
    switch (effectId)
    {
    case 0x73a:
        cfg.velocityY = lbl_803E01D0 * (f32)(s32)
        randomGetRange(8, 0xa);
        if ((int)randomGetRange(0, 0x28) != 0)
        {
            cfg.scale = lbl_803E01B8 * (f32)(s32)
            randomGetRange(8, 0x14);
            cfg.lifetimeFrames = randomGetRange(0x5a, 0x78);
        }
        else
        {
            cfg.scale = lbl_803E01B8 * (f32)(s32)
            randomGetRange(0x15, 0x29);
            cfg.lifetimeFrames = 0x1cc;
        }
        cfg.behaviorFlags = 0x80180200;
        cfg.renderFlags = 0x1000020;
        cfg.textureId = 0xc0b;
        cfg.initialAlpha = 0x7f;
        cfg.colorWord2 = 0x3fff;
        cfg.colorWord1 = 0x3fff;
        cfg.colorWord0 = 0x3fff;
        cfg.overrideColor2 = 0xffff;
        cfg.overrideColor1 = 0xffff;
        cfg.overrideColor0 = 0xffff;
        cfg.startPosY = lbl_803E01D4;
        break;
    case 0x73b:
        cfg.velocityX = lbl_803E01D0 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803E01D0 * (f32)(s32)
        randomGetRange(8, 0x14);
        cfg.velocityZ = lbl_803E01D0 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.scale = lbl_803E01D8;
        cfg.lifetimeFrames = 0x32;
        cfg.behaviorFlags = 0x3000200;
        cfg.renderFlags = 0x200020;
        cfg.textureId = 0x33;
        cfg.initialAlpha = 0xff;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0xffff;
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = 0xffff;
        cfg.overrideColor2 = randomGetRange(0, 0x8000);
        cfg.overrideColor1 = cfg.overrideColor2;
        cfg.startPosY = lbl_803E01DC;
        break;
    case 0x73d:
        cfg.startPosX = lbl_803E01BC * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.startPosY = lbl_803E01D0 * (f32)(s32)
        randomGetRange(-0xa, 0x64);
        cfg.startPosZ = lbl_803E01BC * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.scale = lbl_803E01E0 * (lbl_803E01E4 * (f32)(s32)
        randomGetRange(7, 9)
        )
        ;
        cfg.lifetimeFrames = 0x3c;
        cfg.behaviorFlags = 0x80100;
        cfg.linkGroup = 0x10;
        cfg.textureId = 0xde;
        break;
    case 0x73e:
        cfg.startPosX = lbl_803E01BC * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.startPosY = lbl_803E01D0 * (f32)(s32)
        randomGetRange(-0xa, 0x64);
        cfg.startPosZ = lbl_803E01BC * (f32)(s32)
        randomGetRange(-0xa, 0xa);
        cfg.scale = lbl_803E01E0 * (lbl_803E01E4 * (f32)(s32)
        randomGetRange(7, 9)
        )
        ;
        cfg.lifetimeFrames = 0x3c;
        cfg.behaviorFlags = 0x80100;
        cfg.linkGroup = 0x10;
        cfg.textureId = 0xdf;
        break;
    case 0x73f:
        if (extraArgs != 0)
        {
            cfg.startPosX = lbl_803E01BC * (f32)(s32)
            randomGetRange(-0xa, 0xa) + lbl_803E01E8;
            cfg.startPosY = lbl_803E01D0 * (f32)(s32)
            randomGetRange(-0xa, 0x64) + lbl_803E01EC;
            cfg.startPosZ = lbl_803E01BC * (f32)(s32)
            randomGetRange(-0xa, 0xa) + lbl_803E01F0;
        }
        else
        {
            cfg.startPosX = lbl_803E01BC * (f32)(s32)
            randomGetRange(-0xa, 0xa);
            cfg.startPosY = lbl_803E01D0 * (f32)(s32)
            randomGetRange(-0xa, 0x64);
            cfg.startPosZ = lbl_803E01BC * (f32)(s32)
            randomGetRange(-0xa, 0xa);
        }
        cfg.scale = lbl_803E01F4 * (lbl_803E01E4 * (f32)(s32)
        randomGetRange(7, 9)
        )
        ;
        cfg.lifetimeFrames = 0x3c;
        cfg.behaviorFlags = 0x80100;
        cfg.linkGroup = 0x10;
        cfg.textureId = 0xde;
        break;
    case 0x740:
        if (extraArgs != 0)
        {
            cfg.startPosX = lbl_803E01BC * (f32)(s32)
            randomGetRange(-0xa, 0xa) + lbl_803E01E8;
            cfg.startPosY = lbl_803E01D0 * (f32)(s32)
            randomGetRange(-0xa, 0x64) + lbl_803E01EC;
            cfg.startPosZ = lbl_803E01BC * (f32)(s32)
            randomGetRange(-0xa, 0xa) + lbl_803E01F0;
        }
        else
        {
            cfg.startPosX = lbl_803E01BC * (f32)(s32)
            randomGetRange(-0xa, 0xa);
            cfg.startPosY = lbl_803E01D0 * (f32)(s32)
            randomGetRange(-0xa, 0x64);
            cfg.startPosZ = lbl_803E01BC * (f32)(s32)
            randomGetRange(-0xa, 0xa);
        }
        cfg.scale = lbl_803E01F4 * (lbl_803E01E4 * (f32)(s32)
        randomGetRange(7, 9)
        )
        ;
        cfg.lifetimeFrames = 0x3c;
        cfg.behaviorFlags = 0x80100;
        cfg.linkGroup = 0x10;
        cfg.textureId = 0xdf;
        break;
    case 0x741:
        if (spawnParams != 0) cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.scale = lbl_803E01F8;
        cfg.lifetimeFrames = randomGetRange(0, 0x1e) + 0x50;
        cfg.initialAlpha = 0x60;
        cfg.behaviorFlags = 0x80110;
        cfg.textureId = 0x7b;
        cfg.linkGroup = 0x20;
        break;
    case 0x742:
        cfg.velocityZ = lbl_803E01FC;
        cfg.velocityX = lbl_803E0200 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803E0200 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.scale = lbl_803E0204;
        cfg.lifetimeFrames = randomGetRange(0x46, 0x50);
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x82000104;
        cfg.renderFlags = 0x400;
        cfg.textureId = 0x3f4;
        break;
    case 0x743:
        cfg.velocityZ = lbl_803E01FC;
        cfg.velocityX = lbl_803E0200 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803E0200 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.scale = lbl_803E0204;
        cfg.lifetimeFrames = randomGetRange(0x46, 0x50);
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x82000104;
        cfg.renderFlags = 0x400;
        cfg.textureId = 0x500;
        break;
    case 0x744:
        if ((int)randomGetRange(0, 4) == 4)
        {
            cfg.scale = lbl_803E0208;
            cfg.initialAlpha = 0x9b;
            cfg.behaviorFlags = 0x480000;
            cfg.lifetimeFrames = randomGetRange(0x1e, 0x28);
        }
        else
        {
            cfg.scale = lbl_803E020C;
            cfg.initialAlpha = 0x7d;
            cfg.behaviorFlags = 0x180000;
            cfg.lifetimeFrames = 0x50;
        }
        cfg.renderFlags = 0x2000000;
        cfg.textureId = 0x88;
        break;
    default:
        return -1;
    }
    cfg.behaviorFlags = cfg.behaviorFlags | spawnFlags;
    if (((cfg.behaviorFlags & 1) != 0) && ((cfg.behaviorFlags & 2) != 0)) cfg.behaviorFlags ^= 2LL;
    if ((cfg.behaviorFlags & 1) != 0)
    {
        if ((spawnFlags & 0x200000) != 0)
        {
            cfg.startPosX = cfg.startPosX + cfg.sourcePosY;
            cfg.startPosY = cfg.startPosY + cfg.sourcePosZ;
            cfg.startPosZ = cfg.startPosZ + cfg.sourcePosW;
        }
        else
        {
            if (cfg.attachedSource != 0)
            {
                cfg.startPosX = cfg.startPosX + *(f32*)((char*)cfg.attachedSource + 0x18);
                cfg.startPosY = cfg.startPosY + *(f32*)((char*)cfg.attachedSource + 0x1c);
                cfg.startPosZ = cfg.startPosZ + *(f32*)((char*)cfg.attachedSource + 0x20);
            }
        }
    }
    spawnResult = (*gExpgfxInterface)->spawnEffect(&cfg, -1, effectId, 0);
    return spawnResult;
}

int Effect16_func04(void* sourceObj, int effectId, s16* spawnParams, u32 spawnFlags,
                    u8 modelId, s16* extraArgs)
{
    int spawnResult;
    PartFxSpawn cfg;

    lbl_803DB840 = lbl_803DB840 + lbl_803E00A8;
    if (lbl_803DB840 > 1.0f) lbl_803DB840 = lbl_803E00AC;
    lbl_803DB844 = lbl_803DB844 + lbl_803E00B4;
    if (lbl_803DB844 > 1.0f) lbl_803DB844 = lbl_803E00B8;
    if (sourceObj == 0) return -1;
    if ((spawnFlags & 0x200000) != 0)
    {
        if (spawnParams == 0) return -1;
        cfg.sourcePosY = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.sourcePosZ = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.sourcePosW = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.sourcePosX = ((PartFxSpawnParams*)spawnParams)->unk8;
        cfg.sourceVecZ = ((PartFxSpawnParams*)spawnParams)->unk4;
        cfg.sourceVecY = ((PartFxSpawnParams*)spawnParams)->unk2;
        cfg.sourceVecX = *spawnParams;
        cfg.modelIdByte = modelId;
    }
    cfg.behaviorFlags = 0;
    cfg.renderFlags = 0;
    cfg.effectIdByte = (u8)effectId;
    cfg.attachedSource = sourceObj;
    cfg.startPosX = lbl_803E00BC;
    cfg.startPosY = lbl_803E00BC;
    cfg.startPosZ = lbl_803E00BC;
    cfg.velocityX = lbl_803E00BC;
    cfg.velocityY = lbl_803E00BC;
    cfg.velocityZ = lbl_803E00BC;
    cfg.scale = lbl_803E00BC;
    cfg.lifetimeFrames = 0;
    cfg.quadVertex3Pad06 = -1;
    cfg.initialAlpha = 0xff;
    cfg.linkGroup = 0;
    cfg.textureId = 0;
    cfg.colorWord0 = 0xffff;
    cfg.colorWord1 = 0xffff;
    cfg.colorWord2 = 0xffff;
    cfg.overrideColor0 = 0xffff;
    cfg.overrideColor1 = 0xffff;
    cfg.overrideColor2 = 0xffff;
    switch (effectId)
    {
    case 0x6d7:
        if (spawnParams == 0)
        {
            lbl_8039C410.fc = lbl_803E00BC;
            lbl_8039C410.f10 = lbl_803E00BC;
            lbl_8039C410.f14 = lbl_803E00BC;
            lbl_8039C410.f8 = lbl_803E00B0;
            lbl_8039C410.x = 0;
            lbl_8039C410.y = 0;
            lbl_8039C410.z = 0;
            spawnParams = (s16*)&lbl_8039C410;
        }
        cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.scale = lbl_803E00A8 * (f32)(s32)
        randomGetRange(0xa, 0x1e);
        cfg.lifetimeFrames = randomGetRange(0x118, 0x12c);
        cfg.behaviorFlags = 0x80180214;
        cfg.textureId = 0x5c;
        break;
    case 0x6d8:
        if (spawnParams == 0)
        {
            lbl_8039C410.fc = lbl_803E00BC;
            lbl_8039C410.f10 = lbl_803E00BC;
            lbl_8039C410.f14 = lbl_803E00BC;
            lbl_8039C410.f8 = lbl_803E00B0;
            lbl_8039C410.x = 0;
            lbl_8039C410.y = 0;
            lbl_8039C410.z = 0;
            spawnParams = (s16*)&lbl_8039C410;
        }
        cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.scale = lbl_803E00A8 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.lifetimeFrames = randomGetRange(0x118, 0x12c);
        cfg.behaviorFlags = 0x80180214;
        cfg.textureId = 0xc79;
        break;
    case 0x6d9:
        cfg.velocityX = lbl_803E00C0 * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.velocityY = lbl_803E00C0 * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.velocityZ = lbl_803E00C0 * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.scale = lbl_803E00C4 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.lifetimeFrames = 0x64;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80114;
        cfg.renderFlags = 0x10008;
        cfg.textureId = 0x157;
        break;
    case 0x6da:
        cfg.scale = lbl_803E00C8;
        cfg.lifetimeFrames = 0x14;
        cfg.behaviorFlags = 0x80480210;
        cfg.textureId = 0xc79;
        cfg.initialAlpha = 0x9d;
        break;
    case 0x6db:
        if (extraArgs != 0)
        {
            cfg.velocityX = lbl_803E00CC * (f32)(s32)
            randomGetRange(-0x96, 0x96);
            cfg.velocityZ = lbl_803E00CC * (f32)(s32)
            randomGetRange(-0x96, 0x96);
            cfg.velocityY = lbl_803E00CC * (f32)(s32)
            randomGetRange(0x64, 0x190);
            cfg.scale = lbl_803E00D0 * (f32)(s32)
            randomGetRange(0xf, 0x14);
            cfg.lifetimeFrames = 0x32;
            cfg.colorWord0 = 0xffff;
            cfg.colorWord1 = 0xffff;
            cfg.colorWord2 = 0xffff;
            cfg.overrideColor0 = 0xffff;
            cfg.overrideColor1 = 0;
            cfg.overrideColor2 = 0;
            cfg.behaviorFlags = 0x3000200;
            cfg.renderFlags = 0x200022;
        }
        else
        {
            cfg.scale = lbl_803E00D4 * (f32)(s32)
            randomGetRange(0xf, 0x14);
            cfg.lifetimeFrames = 1;
            cfg.behaviorFlags = 0x80000;
        }
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0xc79;
        break;
    case 0x6dc:
        cfg.velocityY = lbl_803E00D8 * (f32)(s32)
        randomGetRange(8, 0xa);
        cfg.scale = lbl_803E00A8 * (f32)(s32)
        randomGetRange(0x12, 0x1c);
        cfg.lifetimeFrames = randomGetRange(0x32, 0x64);
        cfg.behaviorFlags = 0x80180200;
        cfg.textureId = 0xc0b;
        cfg.initialAlpha = 0xff;
        break;
    case 0x6dd:
        cfg.scale = lbl_803E00AC;
        cfg.lifetimeFrames = 0xa;
        cfg.initialAlpha = 0xc3;
        cfg.linkGroup = 0x10;
        cfg.behaviorFlags = 0x580110;
        cfg.textureId = 0xc79;
        break;
    case 0x6de:
        cfg.velocityX = lbl_803E00DC * lbl_803DB840 * (f32)(s32)
        randomGetRange(-0xf, 0xf);
        cfg.velocityZ = lbl_803E00DC * lbl_803DB840 * (f32)(s32)
        randomGetRange(-0xf, 0xf);
        cfg.velocityY = lbl_803E00DC * lbl_803DB840 * (f32)(s32)
        randomGetRange(-0xf, 0xf);
        cfg.initialAlpha = 0x7d;
        cfg.scale = lbl_803E00E0 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.behaviorFlags = 0x3000000;
        cfg.renderFlags = 0x300000;
        cfg.lifetimeFrames = 0x14;
        cfg.textureId = 0xc79;
        break;
    case 0x6df:
        cfg.velocityX = lbl_803E00CC * (f32)(s32)
        randomGetRange(-0xf, 0xf);
        cfg.velocityZ = lbl_803E00CC * (f32)(s32)
        randomGetRange(-0xf, 0xf);
        cfg.velocityY = lbl_803E00CC * (f32)(s32)
        randomGetRange(-0xf, 0xf);
        cfg.initialAlpha = 0xff;
        cfg.scale = lbl_803E00E4 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.behaviorFlags = 0x80200;
        cfg.renderFlags = 0x100000;
        cfg.lifetimeFrames = 0x64;
        cfg.textureId = 0x125;
        break;
    case 0x6e0:
        cfg.velocityX = lbl_803E00E8 * (f32)(s32)
        randomGetRange(-0xf, 0xf);
        cfg.velocityZ = lbl_803E00E8 * (f32)(s32)
        randomGetRange(-0xf, 0xf);
        cfg.velocityY = lbl_803E00E8 * (f32)(s32)
        randomGetRange(-0xf, 0xf);
        cfg.initialAlpha = 0xff;
        cfg.scale = lbl_803E00E0 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.behaviorFlags = 0x2000200;
        cfg.renderFlags = 0x300000;
        cfg.lifetimeFrames = 0x1e;
        cfg.textureId = 0x33;
        break;
    case 0x6e1:
        cfg.lifetimeFrames = 0x46;
        cfg.scale = lbl_803E00EC;
        cfg.colorWord0 = 0xff00;
        cfg.colorWord1 = 0xff00;
        cfg.colorWord2 = 0xff00;
        cfg.overrideColor0 = 0xff00;
        cfg.overrideColor1 = 0;
        cfg.overrideColor2 = 0xff00;
        cfg.behaviorFlags = 0x100100;
        cfg.renderFlags = 0x20;
        cfg.initialAlpha = 0x7f;
        cfg.textureId = 0x72;
        break;
    case 0x6f2:
        if (spawnParams == 0)
        {
            lbl_8039C410.fc = lbl_803E00BC;
            lbl_8039C410.f10 = lbl_803E00BC;
            lbl_8039C410.f14 = lbl_803E00BC;
            lbl_8039C410.f8 = lbl_803E00B0;
            lbl_8039C410.x = 0;
            lbl_8039C410.y = 0;
            lbl_8039C410.z = 0;
            spawnParams = (s16*)&lbl_8039C410;
        }
        cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.velocityX = lbl_803E00C0 * (f32)(s32)
        randomGetRange(-7, 3);
        cfg.velocityY = lbl_803E00C0 * (f32)(s32)
        randomGetRange(5, 0xf);
        cfg.velocityZ = lbl_803E00C0 * (f32)(s32)
        randomGetRange(-7, 3);
        cfg.scale = lbl_803E00F0 * (f32)(s32)
        randomGetRange(0x32, 0x3c);
        cfg.lifetimeFrames = randomGetRange(0x3c, 0x5a);
        cfg.behaviorFlags = 0x580004;
        cfg.renderFlags = 0x400000;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0xc0d;
        break;
    case 0x6f3:
        if (spawnParams == 0)
        {
            lbl_8039C410.fc = lbl_803E00BC;
            lbl_8039C410.f10 = lbl_803E00BC;
            lbl_8039C410.f14 = lbl_803E00BC;
            lbl_8039C410.f8 = lbl_803E00B0;
            lbl_8039C410.x = 0;
            lbl_8039C410.y = 0;
            lbl_8039C410.z = 0;
            spawnParams = (s16*)&lbl_8039C410;
        }
        cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.scale = lbl_803E00F4 * (f32)(s32)
        randomGetRange(0x32, 0x64);
        cfg.lifetimeFrames = 0x64;
        cfg.behaviorFlags = 0xc0804;
        cfg.renderFlags = 0x8800001;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x58f;
        break;
    case 0x6f4:
        if (spawnParams == 0)
        {
            lbl_8039C410.fc = lbl_803E00BC;
            lbl_8039C410.f10 = lbl_803E00BC;
            lbl_8039C410.f14 = lbl_803E00BC;
            lbl_8039C410.f8 = lbl_803E00B0;
            lbl_8039C410.x = 0;
            lbl_8039C410.y = 0;
            lbl_8039C410.z = 0;
            spawnParams = (s16*)&lbl_8039C410;
        }
        cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.scale = lbl_803E00F8 * (f32)(s32)
        randomGetRange(0x32, 0x64);
        cfg.lifetimeFrames = 0x64;
        cfg.behaviorFlags = 0xc0804;
        cfg.renderFlags = 0x4800001;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x590;
        break;
    case 0x6f5:
        if (spawnParams == 0)
        {
            lbl_8039C410.fc = lbl_803E00BC;
            lbl_8039C410.f10 = lbl_803E00BC;
            lbl_8039C410.f14 = lbl_803E00BC;
            lbl_8039C410.f8 = lbl_803E00B0;
            lbl_8039C410.x = 0;
            lbl_8039C410.y = 0;
            lbl_8039C410.z = 0;
            spawnParams = (s16*)&lbl_8039C410;
        }
        cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.scale = lbl_803E00F4 * (f32)(s32)
        randomGetRange(0x32, 0x64);
        cfg.lifetimeFrames = 0x64;
        cfg.behaviorFlags = 0xc0804;
        cfg.renderFlags = 0x8800001;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x403;
        break;
    case 0x6f6:
        if (spawnParams == 0)
        {
            lbl_8039C410.fc = lbl_803E00BC;
            lbl_8039C410.f10 = lbl_803E00BC;
            lbl_8039C410.f14 = lbl_803E00BC;
            lbl_8039C410.f8 = lbl_803E00B0;
            lbl_8039C410.x = 0;
            lbl_8039C410.y = 0;
            lbl_8039C410.z = 0;
            spawnParams = (s16*)&lbl_8039C410;
        }
        cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.scale = lbl_803E00F8 * (f32)(s32)
        randomGetRange(0x32, 0x64);
        cfg.lifetimeFrames = 0x64;
        cfg.behaviorFlags = 0xc0804;
        cfg.renderFlags = 0x4800001;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x404;
        break;
    case 0x6f7:
        if (spawnParams == 0)
        {
            lbl_8039C410.fc = lbl_803E00BC;
            lbl_8039C410.f10 = lbl_803E00BC;
            lbl_8039C410.f14 = lbl_803E00BC;
            lbl_8039C410.f8 = lbl_803E00B0;
            lbl_8039C410.x = 0;
            lbl_8039C410.y = 0;
            lbl_8039C410.z = 0;
            spawnParams = (s16*)&lbl_8039C410;
        }
        cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.scale = lbl_803E00F4 * (f32)(s32)
        randomGetRange(0x32, 0x64);
        cfg.lifetimeFrames = 0x64;
        cfg.behaviorFlags = 0xc0804;
        cfg.renderFlags = 0x8800001;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x405;
        break;
    case 0x6f8:
        if (spawnParams == 0)
        {
            lbl_8039C410.fc = lbl_803E00BC;
            lbl_8039C410.f10 = lbl_803E00BC;
            lbl_8039C410.f14 = lbl_803E00BC;
            lbl_8039C410.f8 = lbl_803E00B0;
            lbl_8039C410.x = 0;
            lbl_8039C410.y = 0;
            lbl_8039C410.z = 0;
            spawnParams = (s16*)&lbl_8039C410;
        }
        cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.scale = lbl_803E00F8 * (f32)(s32)
        randomGetRange(0x32, 0x64);
        cfg.lifetimeFrames = 0x64;
        cfg.behaviorFlags = 0xc0804;
        cfg.renderFlags = 0x8800001;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x406;
        break;
    default:
        return -1;
    }
    cfg.behaviorFlags = cfg.behaviorFlags | spawnFlags;
    if (((cfg.behaviorFlags & 1) != 0) && ((cfg.behaviorFlags & 2) != 0)) cfg.behaviorFlags ^= 2LL;
    if ((cfg.behaviorFlags & 1) != 0)
    {
        if ((spawnFlags & 0x200000) != 0)
        {
            cfg.startPosX = cfg.startPosX + cfg.sourcePosY;
            cfg.startPosY = cfg.startPosY + cfg.sourcePosZ;
            cfg.startPosZ = cfg.startPosZ + cfg.sourcePosW;
        }
        else
        {
            if (cfg.attachedSource != 0)
            {
                cfg.startPosX = cfg.startPosX + *(f32*)((char*)cfg.attachedSource + 0x18);
                cfg.startPosY = cfg.startPosY + *(f32*)((char*)cfg.attachedSource + 0x1c);
                cfg.startPosZ = cfg.startPosZ + *(f32*)((char*)cfg.attachedSource + 0x20);
            }
        }
    }
    spawnResult = (*gExpgfxInterface)->spawnEffect(&cfg, -1, effectId, 0);
    return spawnResult;
}

int Effect15_func04(void* sourceObj, int effectId, s16* spawnParams, u32 spawnFlags,
                    u8 modelId, f32* extraArgs)
{
    int spawnResult;
    PartFxSpawn cfg;

    if (sourceObj == 0) return -1;
    if ((spawnFlags & 0x200000) != 0)
    {
        if (spawnParams == 0) return -1;
        cfg.sourcePosY = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.sourcePosZ = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.sourcePosW = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.sourcePosX = ((PartFxSpawnParams*)spawnParams)->unk8;
        cfg.sourceVecZ = ((PartFxSpawnParams*)spawnParams)->unk4;
        cfg.sourceVecY = ((PartFxSpawnParams*)spawnParams)->unk2;
        cfg.sourceVecX = *spawnParams;
        cfg.modelIdByte = modelId;
    }
    cfg.behaviorFlags = 0;
    cfg.renderFlags = 0;
    cfg.effectIdByte = (u8)effectId;
    cfg.attachedSource = sourceObj;
    cfg.startPosX = lbl_803E0110;
    cfg.startPosY = lbl_803E0110;
    cfg.startPosZ = lbl_803E0110;
    cfg.velocityX = lbl_803E0110;
    cfg.velocityY = lbl_803E0110;
    cfg.velocityZ = lbl_803E0110;
    cfg.scale = lbl_803E0110;
    cfg.lifetimeFrames = 0;
    cfg.quadVertex3Pad06 = -1;
    cfg.initialAlpha = 0xff;
    cfg.linkGroup = 0;
    cfg.textureId = 0;
    cfg.colorWord0 = 0xffff;
    cfg.colorWord1 = 0xffff;
    cfg.colorWord2 = 0xffff;
    cfg.overrideColor0 = 0xffff;
    cfg.overrideColor1 = 0xffff;
    cfg.overrideColor2 = 0xffff;
    switch (effectId)
    {
    case 0x3e8:
        cfg.scale = lbl_803E0114 * (f32)(s32)
        randomGetRange(0x5a, 0x64);
        cfg.velocityX = lbl_803E0118 * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.velocityY = lbl_803E0110;
        cfg.velocityZ = lbl_803E0118 * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.lifetimeFrames = 0x28;
        cfg.behaviorFlags |= 0x80218LL;
        cfg.renderFlags = 0x20;
        switch (randomGetRange(0, 2))
        {
        case 0:
            cfg.textureId = 0x156;
            break;
        case 1:
            cfg.textureId = 0x157;
            break;
        case 2:
            cfg.textureId = 0xc0e;
            break;
        default:
            cfg.textureId = 0x156;
            break;
        }
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0xd6d8;
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = 0xffff;
        cfg.overrideColor1 = 0x7530;
        cfg.overrideColor2 = 0xffff;
        cfg.initialAlpha = 0xff;
        break;
    case 0x3e9:
        if (spawnParams == 0)
        {
            lbl_8039C428.fc = lbl_803E0110;
            lbl_8039C428.f10 = lbl_803E0110;
            lbl_8039C428.f14 = lbl_803E0110;
            lbl_8039C428.f8 = lbl_803E011C;
            lbl_8039C428.x = 0;
            lbl_8039C428.y = 0;
            lbl_8039C428.z = 0;
            spawnParams = (s16*)&lbl_8039C428;
        }
        cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.scale = lbl_803E0120;
        cfg.behaviorFlags |= 0x180110LL;
        cfg.renderFlags = 0x20;
        cfg.lifetimeFrames = 0x12;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x159;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0xffff;
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = 0xffff;
        cfg.overrideColor1 = 0xc350;
        cfg.overrideColor2 = 0xffff;
        break;
    case 0x3ea:
        if (spawnParams == 0)
        {
            lbl_8039C428.fc = lbl_803E0110;
            lbl_8039C428.f10 = lbl_803E0110;
            lbl_8039C428.f14 = lbl_803E0110;
            lbl_8039C428.f8 = lbl_803E011C;
            lbl_8039C428.x = 0;
            lbl_8039C428.y = 0;
            lbl_8039C428.z = 0;
            spawnParams = (s16*)&lbl_8039C428;
        }
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x64, 0x64) / lbl_803E0124;
        cfg.startPosY = (f32)(s32)(-(s32)randomGetRange(0x64, 0x96)) / lbl_803E0128;
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x64, 0x64) / lbl_803E0124;
        cfg.behaviorFlags |= 0x80208LL;
        cfg.renderFlags = 0x10000;
        cfg.velocityX = lbl_803E012C * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.velocityZ = lbl_803E012C * (f32)(s32)
        randomGetRange(-0x64, 0x64);
        cfg.initialAlpha = 0xff;
        cfg.lifetimeFrames = 0x3c;
        cfg.textureId = 0x7b;
        cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 *
            (lbl_803E0130 * (lbl_803E0134 * (f32)(s32)
        randomGetRange(0x32, 0x64)
        )
        )
        +
            lbl_803E012C;
        break;
    case 0x3eb:
        cfg.velocityX = lbl_803E0138 * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.velocityY = lbl_803E013C * (f32)(s32)
        randomGetRange(-5, 5);
        cfg.velocityZ = lbl_803E0138 * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.startPosX = lbl_803E0110;
        cfg.startPosY = (f32)(s32)
        randomGetRange(-6, 2);
        cfg.startPosZ = lbl_803E0110;
        cfg.scale = lbl_803E013C;
        cfg.lifetimeFrames = 0x32;
        cfg.behaviorFlags = 0x80080208;
        cfg.textureId = 0x60;
        cfg.colorWord0 = 0x7f00;
        cfg.colorWord1 = 0x6400;
        cfg.colorWord2 = 0;
        cfg.overrideColor0 = 0x5a00;
        cfg.overrideColor1 = 0;
        cfg.overrideColor2 = 0;
        cfg.renderFlags = 0x20;
        cfg.initialAlpha = 0x7f;
        break;
    case 0x3ec:
        return -1;
    case 0x3ed:
        cfg.velocityX = lbl_803E013C * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.velocityY = lbl_803E0120 * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.velocityZ = lbl_803E013C * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.scale = lbl_803E0140 * (f32)(s32)
        randomGetRange(0xa, 0x14);
        cfg.lifetimeFrames = 0x32;
        cfg.behaviorFlags = 0x80210;
        cfg.renderFlags = 0x8000800;
        cfg.textureId = 0x79;
        break;
    case 0x3ee:
        cfg.startPosX = cfg.startPosX + (f32)(s32)
        randomGetRange(-0xa, 0xa) / lbl_803E0144;
        cfg.startPosY = cfg.startPosY + (f32)(s32)
        randomGetRange(-0x1e, 0) / lbl_803E0148;
        cfg.startPosZ = cfg.startPosZ + (f32)(s32)
        randomGetRange(-0xa, 0xa) / lbl_803E0144;
        cfg.velocityX = lbl_803E012C * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803E014C * (f32)(s32)(-(s32)randomGetRange(0x28, 0x64));
        cfg.velocityZ = lbl_803E012C * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.scale = lbl_803E012C * (f32)(s32)
        randomGetRange(0xf, 0x16);
        cfg.lifetimeFrames = 0x258;
        cfg.behaviorFlags = 0x180100;
        cfg.textureId = 0xc10;
        cfg.initialAlpha = (u8)randomGetRange(0x96, 0xfa);
        break;
    case 0x3ef:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x4b0, 0x4b0) / lbl_803E0128;
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x4b0, 0x4b0) / lbl_803E0128;
        cfg.velocityY = lbl_803E014C * (f32)(s32)
        randomGetRange(0x1e, 0x46);
        cfg.scale = lbl_803E0154 * (f32)(s32)
        randomGetRange(0, 0x14) + lbl_803E0150;
        cfg.lifetimeFrames = 0xc8;
        cfg.behaviorFlags = 0x80100;
        cfg.textureId = 0x33;
        cfg.initialAlpha = 0xb4;
        cfg.renderFlags = 0x8100800;
        break;
    case 0x3f0:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x3e8, 0x3e8) / lbl_803E0128;
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x3e8, 0x3e8) / lbl_803E0128;
        cfg.velocityY = lbl_803E0158 * (f32)(s32)
        randomGetRange(0x1e, 0x46);
        cfg.scale = lbl_803E0154 * (f32)(s32)
        randomGetRange(0, 0x14) + lbl_803E015C;
        cfg.lifetimeFrames = 0xfa;
        cfg.behaviorFlags = 0x80100;
        cfg.textureId = 0x33;
        cfg.renderFlags = 0x8000800;
        cfg.initialAlpha = 0xb4;
        break;
    case 0x3f1:
        cfg.startPosX = lbl_803E0110;
        cfg.startPosY = lbl_803E0110;
        cfg.startPosZ = lbl_803E0110;
        cfg.behaviorFlags = 0x80800;
        cfg.textureId = 0x76;
        cfg.initialAlpha = 0xd2;
        cfg.scale = lbl_803E0160;
        cfg.lifetimeFrames = 0x64;
        break;
    case 0x3f2:
        if (extraArgs == 0) return 0;
        if (spawnParams == 0)
        {
            lbl_8039C428.fc = lbl_803E0110;
            lbl_8039C428.f10 = lbl_803E0110;
            lbl_8039C428.f14 = lbl_803E0110;
            lbl_8039C428.f8 = lbl_803E011C;
            lbl_8039C428.x = 0;
            lbl_8039C428.y = 0;
            lbl_8039C428.z = 0;
            spawnParams = (s16*)&lbl_8039C428;
        }
        if (spawnParams != 0)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        }
        if (extraArgs != 0)
        {
            cfg.velocityX = extraArgs[0];
            cfg.velocityY = lbl_803E0164 * (f32)(s32)
            randomGetRange(0, 0x14);
            cfg.velocityZ = extraArgs[1];
        }
        cfg.scale = lbl_803E0168 *
            (lbl_803E0170 * (f32)(s32)
        randomGetRange(0, 0xa) + lbl_803E016C
        )
        ;
        cfg.lifetimeFrames = randomGetRange(0xbe, 0xfa);
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x81088000;
        cfg.textureId = 0x23c;
        break;
    case 0x3f3:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x32, 0x32) / lbl_803E0128;
        cfg.startPosY = (f32)(s32)
        randomGetRange(-0x32, 0x32) / lbl_803E0128;
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x32, 0x32) / lbl_803E0128;
        cfg.velocityX = lbl_803E0118 * (f32)(s32)
        randomGetRange(0x1e, 0x3c);
        if ((int)randomGetRange(0, 1) != 0) cfg.velocityX = -cfg.velocityX;
        cfg.velocityY = lbl_803E0118 * (f32)(s32)
        randomGetRange(0x1e, 0x3c);
        if ((int)randomGetRange(0, 1) != 0) cfg.velocityY = -cfg.velocityY;
        cfg.velocityZ = lbl_803E0118 * (f32)(s32)
        randomGetRange(0x1e, 0x3c);
        if ((int)randomGetRange(0, 1) != 0) cfg.velocityZ = -cfg.velocityZ;
        cfg.scale = lbl_803E0154 * (f32)(s32)
        randomGetRange(0, 0xa) + lbl_803E012C;
        cfg.lifetimeFrames = 0x46;
        cfg.behaviorFlags = 0x80208;
        cfg.textureId = 0x76;
        cfg.initialAlpha = 0xb4;
        cfg.renderFlags = 0x100000;
        break;
    case 0x3f4:
    case 0x3f5:
    case 0x3f6:
        if (spawnParams != 0)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.startPosX = cfg.startPosX - *(f32*)((char*)cfg.attachedSource + 0x18);
            cfg.startPosY = cfg.startPosY - *(f32*)((char*)cfg.attachedSource + 0x1c);
            cfg.startPosZ = cfg.startPosZ - *(f32*)((char*)cfg.attachedSource + 0x20);
        }
        if ((int)randomGetRange(0, 0x28) == 0) cfg.scale = lbl_803E0130;
        else cfg.scale = lbl_803E015C;
        cfg.lifetimeFrames = 0x14;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80210;
        switch (effectId - 0x3f4)
        {
        case 0:
            cfg.textureId = 0x156;
            break;
        case 1:
            cfg.textureId = 0x157;
            break;
        case 2:
            cfg.textureId = 0xc0e;
            break;
        default:
            cfg.textureId = 0x156;
            break;
        }
        break;
    case 0x3f7:
    case 0x3f8:
    case 0x3f9:
        if (spawnParams != 0)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.startPosX = cfg.startPosX - *(f32*)((char*)cfg.attachedSource + 0x18);
            cfg.startPosY = cfg.startPosY - *(f32*)((char*)cfg.attachedSource + 0x1c);
            cfg.startPosZ = cfg.startPosZ - *(f32*)((char*)cfg.attachedSource + 0x20);
            cfg.velocityZ = lbl_803E0174;
        }
        cfg.scale = lbl_803E015C;
        cfg.lifetimeFrames = 0x64;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x480210;
        cfg.renderFlags = 0x100000;
        switch (effectId - 0x3f7)
        {
        case 0:
            cfg.textureId = 0x4fb;
            break;
        case 1:
            cfg.textureId = 0x4fc;
            break;
        case 2:
            cfg.textureId = 0x4fd;
            break;
        default:
            cfg.textureId = 0x4fb;
            break;
        }
        break;
    case 0x3fa:
        if (spawnParams != 0)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.startPosX = cfg.startPosX - *(f32*)((char*)cfg.attachedSource + 0x18);
            cfg.startPosY = cfg.startPosY - *(f32*)((char*)cfg.attachedSource + 0x1c);
            cfg.startPosZ = cfg.startPosZ - *(f32*)((char*)cfg.attachedSource + 0x20);
            cfg.velocityZ = lbl_803E0134;
        }
        cfg.scale = lbl_803E015C;
        cfg.lifetimeFrames = 0x64;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x480210;
        cfg.renderFlags = 0x100000;
        cfg.textureId = 0x4fb;
        break;
    case 0x3fb:
        if (spawnParams != 0)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.startPosX = cfg.startPosX - *(f32*)((char*)cfg.attachedSource + 0x18);
            cfg.startPosY = cfg.startPosY - *(f32*)((char*)cfg.attachedSource + 0x1c);
            cfg.startPosZ = cfg.startPosZ - *(f32*)((char*)cfg.attachedSource + 0x20);
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8;
        }
        cfg.lifetimeFrames = 5;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80800;
        cfg.renderFlags = 0x1000000;
        cfg.textureId = 0x5ea;
        break;
    case 0x3fc:
        if (spawnParams != 0)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.startPosX = cfg.startPosX - *(f32*)((char*)cfg.attachedSource + 0x18);
            cfg.startPosY = cfg.startPosY - *(f32*)((char*)cfg.attachedSource + 0x1c);
            cfg.startPosZ = cfg.startPosZ - *(f32*)((char*)cfg.attachedSource + 0x20);
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8;
        }
        cfg.lifetimeFrames = 5;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80800;
        cfg.renderFlags = 0x1000000;
        cfg.textureId = 0x5eb;
        break;
    default:
        return -1;
    }
    cfg.behaviorFlags = cfg.behaviorFlags | spawnFlags;
    if (((cfg.behaviorFlags & 1) != 0) && ((cfg.behaviorFlags & 2) != 0)) cfg.behaviorFlags ^= 2LL;
    if ((cfg.behaviorFlags & 1) != 0)
    {
        if ((spawnFlags & 0x200000) != 0)
        {
            cfg.startPosX = cfg.startPosX + cfg.sourcePosY;
            cfg.startPosY = cfg.startPosY + cfg.sourcePosZ;
            cfg.startPosZ = cfg.startPosZ + cfg.sourcePosW;
        }
        else
        {
            if (cfg.attachedSource != 0)
            {
                cfg.startPosX = cfg.startPosX + *(f32*)((char*)cfg.attachedSource + 0x18);
                cfg.startPosY = cfg.startPosY + *(f32*)((char*)cfg.attachedSource + 0x1c);
                cfg.startPosZ = cfg.startPosZ + *(f32*)((char*)cfg.attachedSource + 0x20);
            }
        }
    }
    spawnResult = (*gExpgfxInterface)->spawnEffect(&cfg, -1, effectId, 0);
    return spawnResult;
}

int Effect18_func04(void* sourceObj, int effectId, s16* spawnParams, u32 spawnFlags,
                    u8 modelId, void* extraArgs)
{
    int spawnResult;
    f32 thr;
    PartFxSpawn cfg;

    lbl_803DB860 = lbl_803DB860 + lbl_803E0220;
    if (lbl_803DB860 > 1.0f) lbl_803DB860 = lbl_803E0224;
    lbl_803DB864 = lbl_803DB864 + lbl_803E022C;
    if (lbl_803DB864 > 1.0f) lbl_803DB864 = lbl_803E0230;
    if (sourceObj == 0) return -1;
    if ((spawnFlags & 0x200000) != 0)
    {
        if (spawnParams == 0) return -1;
        cfg.sourcePosY = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.sourcePosZ = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.sourcePosW = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.sourcePosX = ((PartFxSpawnParams*)spawnParams)->unk8;
        cfg.sourceVecZ = ((PartFxSpawnParams*)spawnParams)->unk4;
        cfg.sourceVecY = ((PartFxSpawnParams*)spawnParams)->unk2;
        cfg.sourceVecX = *spawnParams;
        cfg.modelIdByte = modelId;
    }
    cfg.behaviorFlags = 0;
    cfg.renderFlags = 0;
    cfg.effectIdByte = (u8)effectId;
    cfg.attachedSource = sourceObj;
    cfg.startPosX = lbl_803E0234;
    cfg.startPosY = lbl_803E0234;
    cfg.startPosZ = lbl_803E0234;
    cfg.velocityX = lbl_803E0234;
    cfg.velocityY = lbl_803E0234;
    cfg.velocityZ = lbl_803E0234;
    cfg.scale = lbl_803E0234;
    cfg.lifetimeFrames = 0;
    cfg.quadVertex3Pad06 = -1;
    cfg.initialAlpha = 0xff;
    cfg.linkGroup = 0;
    cfg.textureId = 0;
    cfg.colorWord0 = 0xffff;
    cfg.colorWord1 = 0xffff;
    cfg.colorWord2 = 0xffff;
    cfg.overrideColor0 = 0xffff;
    cfg.overrideColor1 = 0xffff;
    cfg.overrideColor2 = 0xffff;
    switch (effectId)
    {
    case 0x708:
        cfg.velocityX = lbl_803E0238 * (f32)(s32)
        randomGetRange(0xa, 0x19);
        cfg.scale = lbl_803E0224;
        cfg.lifetimeFrames = randomGetRange(0x15e, 0x190);
        cfg.behaviorFlags = 0xa100100;
        cfg.renderFlags = 0x1000000;
        cfg.textureId = 0x62;
        break;
    case 0x709:
        cfg.velocityY = lbl_803E023C * (f32)(s32)
        randomGetRange(0xa, 0x14);
        if ((int)randomGetRange(0, 1) != 0) cfg.velocityY = -cfg.velocityY;
        cfg.scale = lbl_803E0220;
        cfg.lifetimeFrames = 0x78;
        cfg.initialAlpha = (u8)randomGetRange(0x7f, 0xff);
        cfg.behaviorFlags = 0x80480000;
        cfg.renderFlags = 0x440000;
        cfg.textureId = (s16)randomGetRange(0x525, 0x528);
        break;
    case 0x70a:
        cfg.velocityX = lbl_803E0240 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803E0240 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityZ = lbl_803E0240 * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.scale = lbl_803E0244;
        cfg.lifetimeFrames = 0x32;
        cfg.behaviorFlags = 0x480100;
        cfg.textureId = (s16)randomGetRange(0x525, 0x528);
        break;
    case 0x70b:
        cfg.lifetimeFrames = 0x64;
        cfg.scale = lbl_803E0248;
        cfg.behaviorFlags = 0x180200;
        cfg.textureId = 0x208;
        cfg.renderFlags = 0x5000000;
        break;
    case 0x70c:
        cfg.lifetimeFrames = randomGetRange(0x19, 0x4b);
        cfg.velocityX = lbl_803E023C * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityY = lbl_803E024C * (f32)(s32)
        cfg.lifetimeFrames;
        cfg.velocityZ = lbl_803E023C * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.scale = lbl_803E0250 * (f32)(s32)
        randomGetRange(0x32, 0x64);
        cfg.behaviorFlags = 0x1082000;
        cfg.textureId = (s16)randomGetRange(0x208, 0x20a);
        cfg.renderFlags = 0x1400000;
        break;
    case 0x70f:
        cfg.lifetimeFrames = randomGetRange(0xf, 0x2d);
        cfg.startPosX = (f32)(s32)
        randomGetRange(-5, 5);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-5, 5);
        cfg.velocityX = lbl_803E023C * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.velocityY = lbl_803E024C * (f32)(s32)
        cfg.lifetimeFrames;
        cfg.velocityZ = lbl_803E023C * (f32)(s32)
        randomGetRange(-0x28, 0x28);
        cfg.scale = lbl_803E0254 * (f32)(s32)
        randomGetRange(0x32, 0x46);
        cfg.initialAlpha = 0xa0;
        cfg.behaviorFlags = 0x1082000;
        cfg.renderFlags = 0x5400000;
        cfg.textureId = (s16)randomGetRange(0x208, 0x20a);
        break;
    case 0x710:
        if (extraArgs != 0) thr = *(f32*)extraArgs;
        else thr = lbl_803E0228;
        cfg.lifetimeFrames = randomGetRange(0xf, 0x4b);
        cfg.startPosY = lbl_803E0258 * thr;
        cfg.startPosZ = lbl_803E025C * thr;
        cfg.velocityX = lbl_803E023C * (f32)(s32)
        randomGetRange(-0x1e, 0x1e);
        cfg.velocityY = lbl_803E024C * (f32)(s32)
        cfg.lifetimeFrames;
        cfg.velocityZ = lbl_803E0260 * (f32)(s32)
        randomGetRange(0x14, 0x46);
        cfg.scale = lbl_803E0264 * (f32)(s32)
        randomGetRange(0x28, 0x3c);
        cfg.initialAlpha = (u8)randomGetRange(0x3c, 0xa0);
        cfg.behaviorFlags = 0x81080200;
        cfg.renderFlags = 0x4000800;
        cfg.textureId = 0xc0f;
        break;
    case 0x711:
        if (extraArgs != 0) thr = *(f32*)extraArgs;
        else thr = lbl_803E0228;
        cfg.lifetimeFrames = randomGetRange(0x23, 0x4b);
        cfg.startPosY = lbl_803E0268 * thr;
        cfg.startPosZ = lbl_803E025C * thr;
        cfg.velocityX = lbl_803E023C * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.velocityY = lbl_803E026C * (f32)(s32)
        cfg.lifetimeFrames;
        cfg.velocityZ = lbl_803E0260 * (f32)(s32)
        randomGetRange(0x14, 0x3c);
        cfg.scale = lbl_803E0264 * (f32)(s32)
        randomGetRange(0x28, 0x3c);
        cfg.initialAlpha = (u8)randomGetRange(0x64, 0xc8);
        cfg.behaviorFlags = 0x81080200;
        cfg.renderFlags = 0x4000800;
        cfg.textureId = 0xc0f;
        break;
    case 0x712:
        cfg.lifetimeFrames = randomGetRange(0x32, 0x64);
        cfg.velocityX = lbl_803E023C * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803E0270 * (f32)(s32)
        cfg.lifetimeFrames;
        cfg.velocityZ = lbl_803E023C * (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.scale = lbl_803E0274;
        if ((int)randomGetRange(0, 2) != 0) cfg.behaviorFlags = 0xa100008;
        else cfg.behaviorFlags = 0x180008;
        cfg.renderFlags = 0x1400000;
        cfg.textureId = 0x5f;
        break;
    case 0x713:
        break;
    case 0x714:
        cfg.initialAlpha = (u8)randomGetRange(0x1e, 0x28);
        if (extraArgs != 0)
        {
            cfg.initialAlpha = (f32)(u32)
            cfg.initialAlpha *
                ((f32)(s32) * (int*)extraArgs / lbl_803E0278);
        }
        cfg.velocityZ = lbl_803E027C * (f32)(s32)
        randomGetRange(0x12, 0x14);
        cfg.scale = lbl_803E0280 * (f32)(s32)
        randomGetRange(0x28, 0x3c);
        cfg.lifetimeFrames = randomGetRange(8, 0x14);
        cfg.behaviorFlags = 0x80204;
        cfg.renderFlags = 0x4002800;
        cfg.textureId = 0xc0f;
        break;
    case 0x715:
        if (extraArgs != 0)
        {
            cfg.velocityX = lbl_803E0284 * (f32)(s32)
            randomGetRange(-0x19, 0x19);
            cfg.velocityY = lbl_803E0284 * (f32)(s32)
            randomGetRange(5, 0x32);
            cfg.velocityZ = lbl_803E0284 * (f32)(s32)
            randomGetRange(-0x19, 0x19);
            cfg.scale = lbl_803E0288;
            cfg.lifetimeFrames = randomGetRange(0x28, 0x78);
            cfg.behaviorFlags = 0x80480000;
            cfg.renderFlags = 0x400800;
        }
        else
        {
            cfg.scale = lbl_803E028C * (f32)(s32)
            randomGetRange(0x32, 0x64);
            cfg.lifetimeFrames = 0x78;
            cfg.behaviorFlags = 0x80580200;
            cfg.renderFlags = 0x800;
        }
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0xc0f;
        break;
    case 0x716:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.startPosY = (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.velocityY = lbl_803E0238 * (f32)(s32)
        randomGetRange(0x5a, 0x64);
        cfg.linkGroup = 0xf;
        cfg.scale = lbl_803E0220 * (f32)(s32)
        randomGetRange(0x5a, 0x64);
        cfg.behaviorFlags = 0x800c0100;
        cfg.renderFlags = 0x4000800;
        cfg.initialAlpha = (u8)randomGetRange(0x96, 0xc8);
        cfg.lifetimeFrames = randomGetRange(0x32, 0x46);
        cfg.textureId = 0x185;
        break;
    case 0x717:
        if (extraArgs != 0) thr = *(f32*)extraArgs;
        else thr = lbl_803E0228;
        cfg.startPosX = thr * (lbl_803E0224 * (f32)(s32)
        randomGetRange(-0x96, 0x96)
        )
        ;
        cfg.startPosY = thr * (lbl_803E0224 * (f32)(s32)
        randomGetRange(0x64, 0x12c)
        )
        ;
        cfg.startPosZ = thr * (lbl_803E0224 * (f32)(s32)
        randomGetRange(-0x96, -0x32)
        )
        ;
        cfg.scale = lbl_803E0244;
        cfg.lifetimeFrames = randomGetRange(0x32, 0x96);
        cfg.behaviorFlags = 0x80480100;
        cfg.textureId = (s16)randomGetRange(0x527, 0x528);
        break;
    case 0x718:
        {
            f32 v = lbl_803E027C * (f32)(s32)randomGetRange(8, 0xa);
            cfg.velocityY = v;
            if (extraArgs != 0)
            {
                cfg.velocityY = v * (lbl_803E0228 + *(f32*)extraArgs / lbl_803E0290);
            }
            cfg.scale = lbl_803E0240 * (f32)(s32)
            randomGetRange(6, 0xc);
            cfg.lifetimeFrames = randomGetRange(0x3c, 0x64);
            cfg.behaviorFlags = 0x80180000;
            cfg.renderFlags = 0x5440800;
            cfg.textureId = 0xc0b;
            cfg.initialAlpha = 0x40;
            break;
        }
    case 0x71a:
        cfg.startPosZ = lbl_803E0294;
        cfg.scale = lbl_803E0298 * (f32)(s32)
        randomGetRange(0x4b, 0x64);
        cfg.lifetimeFrames = 1;
        cfg.behaviorFlags = 0x80010;
        cfg.renderFlags = 0x800;
        cfg.textureId = 0xc7e;
        cfg.initialAlpha = 0x7f;
        break;
    case 0x71b:
        cfg.scale = lbl_803E029C;
        cfg.lifetimeFrames = 0x64;
        cfg.behaviorFlags = 0x180000;
        cfg.renderFlags = 0x400800;
        cfg.textureId = 0x73;
        cfg.initialAlpha = 0xff;
        break;
    case 0x71c:
        cfg.lifetimeFrames = randomGetRange(0x28, 0x78);
        cfg.velocityX = lbl_803E027C * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.velocityY = lbl_803E02A0 * (f32)(s32)
        cfg.lifetimeFrames;
        cfg.velocityZ = lbl_803E027C * (f32)(s32)
        randomGetRange(-0x32, 0x32);
        cfg.scale = lbl_803E0284;
        cfg.behaviorFlags = 0x3000000;
        cfg.renderFlags = 0x600820;
        cfg.textureId = 0x20d;
        cfg.initialAlpha = 0xff;
        cfg.colorWord2 = 0xffff;
        cfg.colorWord1 = 0xffff;
        cfg.overrideColor0 = cfg.colorWord0 = 0xffff;
        cfg.overrideColor2 = 0;
        cfg.overrideColor1 = 0;
        break;
    case 0x71d:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.startPosY = (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x14, 0x14);
        cfg.linkGroup = 0xf;
        cfg.scale = lbl_803E0220 * (f32)(s32)
        randomGetRange(0x78, 0xc8);
        cfg.behaviorFlags = 0x80180100;
        cfg.renderFlags = 0x4000800;
        cfg.initialAlpha = (u8)randomGetRange(0x32, 0x64);
        cfg.lifetimeFrames = randomGetRange(0x64, 0x8c);
        cfg.textureId = 0x185;
        break;
    case 0x71e:
        cfg.startPosX = (f32)(s32)
        randomGetRange(-0x23, 0x23);
        cfg.startPosY = (f32)(s32)
        randomGetRange(0, 0x1e);
        cfg.startPosZ = (f32)(s32)
        randomGetRange(-0x23, 0x23);
        cfg.velocityY = lbl_803E027C * (f32)(s32)
        randomGetRange(8, 0xa);
        cfg.scale = lbl_803E0240 * (f32)(s32)
        randomGetRange(6, 0xc);
        cfg.lifetimeFrames = randomGetRange(0x64, 0x96);
        cfg.behaviorFlags = 0x80180000;
        cfg.renderFlags = 0x1440000;
        cfg.textureId = 0x564;
        cfg.initialAlpha = 0x7f;
        break;
    case 0x71f:
        cfg.velocityY = lbl_803E027C * (f32)(s32)
        randomGetRange(8, 0xa);
        cfg.scale = lbl_803E0288 * (f32)(s32)
        randomGetRange(6, 0xc);
        cfg.lifetimeFrames = randomGetRange(0x3c, 0x50);
        cfg.behaviorFlags = 0x80180000;
        cfg.renderFlags = 0x5440800;
        cfg.textureId = 0x564;
        cfg.initialAlpha = 0x40;
        break;
    case 0x720:
        cfg.velocityY = lbl_803E02A4 * (f32)(s32)
        randomGetRange(8, 0xa);
        cfg.scale = lbl_803E0288 * (f32)(s32)
        randomGetRange(6, 0xc);
        cfg.lifetimeFrames = randomGetRange(0x3c, 0x50);
        cfg.behaviorFlags = 0x80180200;
        cfg.renderFlags = 0x5000800;
        cfg.textureId = 0x564;
        cfg.initialAlpha = 0x40;
        break;
    case 0x721:
        cfg.scale = lbl_803E02A8 * (f32)(s32)
        randomGetRange(6, 0xc);
        cfg.lifetimeFrames = randomGetRange(0xfa, 0x15e);
        cfg.behaviorFlags = 0x80480008;
        cfg.renderFlags = 0x400000;
        cfg.textureId = 0xc0d;
        break;
    case 0x722:
        cfg.startPosY = lbl_803E02AC;
        cfg.lifetimeFrames = randomGetRange(0x1e, 0x3c);
        cfg.velocityX = lbl_803E02A4 * (f32)(s32)
        randomGetRange(-0x3c, 0x3c);
        cfg.velocityY = lbl_803E02B0 * sqrtf(cfg.velocityX * cfg.velocityX + cfg.velocityZ * cfg.velocityZ);
        cfg.velocityZ = lbl_803E02A4 * (f32)(s32)
        randomGetRange(-0x3c, 0x3c);
        cfg.scale = lbl_803E02A4;
        cfg.behaviorFlags = 0x80000;
        cfg.renderFlags = 0x5400800;
        cfg.textureId = 0x564;
        cfg.initialAlpha = (u8)((int)randomGetRange(0x46, 0xbe) >> 1);
        break;
    case 0x723:
        {
            int base, span;
            cfg.lifetimeFrames = randomGetRange(0x23, 0x2d);
            if (extraArgs != 0) base = *(int*)extraArgs + 5;
            else base = 5;
            cfg.velocityY = (f32)(s32)
            base / lbl_803E02B4 *
                (lbl_803E02B8 * (f32)(s32)
            randomGetRange(8, 0xc)
            )
            ;
            span = 0x41 - base;
            cfg.velocityX = lbl_803E024C * (f32)(s32)
            randomGetRange(-span, span);
            cfg.velocityZ = lbl_803E024C * (f32)(s32)
            randomGetRange(-span, span);
            cfg.scale = lbl_803E0240 * (f32)(s32)
            randomGetRange(6, 0xc);
            cfg.initialAlpha = (u8)((int)randomGetRange(0x40, 0x7f) >> 1);
            cfg.behaviorFlags = 0x80080000;
            cfg.renderFlags = 0x5400800;
            cfg.textureId = 0x564;
            break;
        }
    case 0x724:
        cfg.velocityY = lbl_803E027C * (f32)(s32)
        randomGetRange(8, 0xa);
        cfg.scale = lbl_803E0240 * (f32)(s32)
        randomGetRange(6, 0xc);
        cfg.lifetimeFrames = randomGetRange(0x1e, 0x3c);
        cfg.behaviorFlags = 0x80080000;
        cfg.renderFlags = 0x5440800;
        cfg.textureId = 0xc0b;
        cfg.initialAlpha = 0x40;
        break;
    default:
        return -1;
    }
    cfg.behaviorFlags = cfg.behaviorFlags | spawnFlags;
    if (((cfg.behaviorFlags & 1) != 0) && ((cfg.behaviorFlags & 2) != 0)) cfg.behaviorFlags ^= 2LL;
    if ((cfg.behaviorFlags & 1) != 0)
    {
        if ((spawnFlags & 0x200000) != 0)
        {
            cfg.startPosX = cfg.startPosX + cfg.sourcePosY;
            cfg.startPosY = cfg.startPosY + cfg.sourcePosZ;
            cfg.startPosZ = cfg.startPosZ + cfg.sourcePosW;
        }
        else
        {
            if (cfg.attachedSource != 0)
            {
                cfg.startPosX = cfg.startPosX + *(f32*)((char*)cfg.attachedSource + 0x18);
                cfg.startPosY = cfg.startPosY + *(f32*)((char*)cfg.attachedSource + 0x1c);
                cfg.startPosZ = cfg.startPosZ + *(f32*)((char*)cfg.attachedSource + 0x20);
            }
        }
    }
    spawnResult = (*gExpgfxInterface)->spawnEffect(&cfg, -1, effectId, 0);
    return spawnResult;
}

void Effect19_func05(void)
{
    f32 sum;
    f32 step;
    sum = lbl_803DB878 + (step = lbl_803E02D8 * timeDelta);
    lbl_803DB878 = sum;
    if (sum > 1.0f) lbl_803DB878 = lbl_803E02DC;
    sum = lbl_803DB87C + step;
    lbl_803DB87C = sum;
    if (sum > 1.0f) lbl_803DB87C = lbl_803E02E8;
    lbl_803DD3F0 = lbl_803DD3F0 + (s32)framesThisStep * 0x64;
    if (lbl_803DD3F0 > 0x7fff) lbl_803DD3F0 = 0;
    lbl_803DD3FC = mathSinf(lbl_803E0308 * (f32)(s16)lbl_803DD3F0 / lbl_803E030C);
    lbl_803DD3F4 = lbl_803DD3F4 + (s32)framesThisStep * 0x32;
    if (lbl_803DD3F4 > 0x7fff) lbl_803DD3F4 = 0;
    lbl_803DD3F8 = mathSinf(lbl_803E0308 * (f32)(s16)lbl_803DD3F4 / lbl_803E030C);
}

/* ---- Effect20_func04 (FUN_800cd430, v1.0) ---- */
extern f32 lbl_803DB880;
extern f32 lbl_803DB884;
extern f32 lbl_803E031C;
extern f32 lbl_803E0324;
extern f32 lbl_803E0328;
extern f32 lbl_803E032C;
extern f32 lbl_803E0330;
extern f32 lbl_803E0334;
extern f32 lbl_803E0338;
extern f32 lbl_803E033C;
extern f32 lbl_803E0340;
extern f32 lbl_803E034C;
extern f32 lbl_803E0350;
extern f32 lbl_803E0354;
extern f32 lbl_803E0358;
extern f32 lbl_803E035C;
extern f32 lbl_803E0360;
extern f32 lbl_803E0364;
extern f32 lbl_803E0368;
extern f32 lbl_803E036C;
extern f32 lbl_803E0370;
extern f32 lbl_803E0374;
extern f32 lbl_803E0378;
extern f32 lbl_803E037C;
extern f32 lbl_803E0380;
extern f32 lbl_803E0384;
extern f32 lbl_803E0388;
extern f32 lbl_803E038C;
extern f32 lbl_803E0390;
extern f32 lbl_803E0394;
extern f32 lbl_803E0398;
extern f32 lbl_803E039C;
extern f32 lbl_803E03A0;
extern f32 lbl_803E03A4;
extern f32 lbl_803E03A8;
extern f32 lbl_803E03AC;
extern f32 lbl_803E03B0;
extern f32 lbl_803E03B4;
extern f32 lbl_803E03B8;
extern f32 lbl_803E03BC;
extern f32 lbl_803E03C0;
extern f32 lbl_803E03C4;
extern f32 lbl_803E03C8;
extern f32 lbl_803E03CC;
extern f32 lbl_803E03D0;
extern f32 lbl_803E03D4;
extern f32 lbl_803E03D8;
extern f32 lbl_803E03DC;
extern f32 lbl_803E03E0;
extern f32 lbl_803E03E4;
extern f32 lbl_803E03E8;
extern f32 lbl_803E03EC;
extern f32 lbl_803E03F0;
extern f32 lbl_803E03F4;
extern f32 lbl_803E03F8;
extern f32 lbl_803E03FC;
extern f32 lbl_803E0400;
extern f32 lbl_803E0404;
extern f32 lbl_803E0408;
extern f32 lbl_803E040C;
extern f32 lbl_803E0410;
extern f32 lbl_803E0414;
extern f32 lbl_803E0418;
extern f32 lbl_803E041C;
extern f32 lbl_803E0420;
extern f32 lbl_803E0424;
extern f32 lbl_803E0428;
extern f32 lbl_803E042C;
extern f32 lbl_803E0430;
extern f32 lbl_803E0434;
extern f32 lbl_803E0438;
extern f32 lbl_803E043C;
extern f32 lbl_803E0440;
extern f32 lbl_803E0444;
extern f32 lbl_803E0448;
extern f32 lbl_803E044C;
extern f32 lbl_803E0450;
extern f32 lbl_803E0454;
extern f32 lbl_803E0458;
extern f32 lbl_803E045C;
extern f64 lbl_803E0460;
extern f32 lbl_803E0468;
extern f32 lbl_803E046C;
extern f32 lbl_803E0470;
extern f32 lbl_803E0474;
extern f32 lbl_803E0478;
extern f32 lbl_803E047C;
extern f32 lbl_803E0480;
extern f32 lbl_803E0484;
extern f32 lbl_803E0488;
extern f32 lbl_803E048C;
extern f32 lbl_803E0490;
extern f32 lbl_803E0494;
extern f32 lbl_803E0498;
extern f32 lbl_803E049C;
extern f32 lbl_803E04A0;
extern f32 lbl_803E04A4;
extern f32 lbl_803E04A8;
extern f32 lbl_803E04AC;
extern f32 lbl_803E04B0;
extern f32 lbl_803E04B4;
extern f32 lbl_803E04B8;
extern f32 lbl_803E04BC;
extern f32 lbl_803E04C0;
extern f32 lbl_803E04C4;
extern f32 lbl_803E04C8;
extern void vecRotateZXY(void* params, f32* vec);
extern int randFn_80080100(int range);

int Effect20_func04(void* sourceObj, int effectId, s16* spawnParams, u32 spawnFlags,
                    u8 modelId, f32* extraArgs)
{
    int ret;
    int intVal;
    int variant;
    f32 trigVal;
    f32 angle;
    f32 radius;
    PartFxSpawn cfg;

    ret = 0;
    lbl_803DB880 = lbl_803DB880 + lbl_803E0310;
    if (lbl_803DB880 > 1.0f) lbl_803DB880 = lbl_803E0314;
    lbl_803DB884 = lbl_803DB884 + lbl_803E031C;
    if (lbl_803DB884 > 1.0f) lbl_803DB884 = lbl_803E0320;
    if (sourceObj == 0) return -1;
    if ((spawnFlags & 0x200000) != 0)
    {
        if (spawnParams == 0) return -1;
        cfg.sourcePosY = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.sourcePosZ = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.sourcePosW = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.sourcePosX = ((PartFxSpawnParams*)spawnParams)->unk8;
        cfg.sourceVecZ = ((PartFxSpawnParams*)spawnParams)->unk4;
        cfg.sourceVecY = ((PartFxSpawnParams*)spawnParams)->unk2;
        cfg.sourceVecX = *spawnParams;
        cfg.modelIdByte = modelId;
    }
    cfg.behaviorFlags = 0;
    cfg.renderFlags = 0;
    cfg.effectIdByte = (u8)effectId;
    cfg.attachedSource = sourceObj;
    cfg.startPosX = lbl_803E0324;
    cfg.startPosY = lbl_803E0324;
    cfg.startPosZ = lbl_803E0324;
    cfg.velocityX = lbl_803E0324;
    cfg.velocityY = lbl_803E0324;
    cfg.velocityZ = lbl_803E0324;
    cfg.scale = lbl_803E0324;
    cfg.lifetimeFrames = 0;
    cfg.quadVertex3Pad06 = -1;
    cfg.initialAlpha = 0xff;
    cfg.linkGroup = 0;
    cfg.textureId = 0;
    cfg.colorWord0 = 0xffff;
    cfg.colorWord1 = 0xffff;
    cfg.colorWord2 = 0xffff;
    cfg.overrideColor0 = 0xffff;
    cfg.overrideColor1 = 0xffff;
    cfg.overrideColor2 = 0xffff;
    switch (effectId)
    {
    case 0x79e:
        if (extraArgs != NULL)
        {
            cfg.velocityX = lbl_803E0320 * *extraArgs + lbl_803E0310 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.velocityY = lbl_803E0320 * extraArgs[1] + lbl_803E0310 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.velocityZ = lbl_803E0320 * extraArgs[2] + lbl_803E0310 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
        }
        cfg.scale = lbl_803E0328 * (f32)(s32)
        randomGetRange(0x32, 100);
        cfg.lifetimeFrames = 100;
        cfg.behaviorFlags = 0x80480200;
        cfg.renderFlags = 0x8000800;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x84;
        break;
    case 0x79f:
        trigVal = lbl_803E0310 * (f32)(s32)
        randomGetRange(0x32, 100);
        cfg.scale = (extraArgs != NULL ? *extraArgs : lbl_803E0318) * trigVal;
        cfg.lifetimeFrames = 0x1e;
        cfg.behaviorFlags = 0x180010;
        cfg.renderFlags = 0x8000;
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0xc80;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0xffff;
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = 0xffff;
        cfg.overrideColor1 = 0xffff;
        cfg.overrideColor2 = 0xffff;
        break;
    case 0x7a0:
        if (spawnParams != NULL)
        {
            cfg.lifetimeFrames = (int)((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.behaviorFlags = 0x80080210;
            cfg.renderFlags = 0x8000800;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E032C * (f32)(s32)
            randomGetRange(0x32, 100)
            )
            ;
        }
        else
        {
            cfg.velocityX = lbl_803E0330 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.velocityY = lbl_803E0330 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.velocityZ = lbl_803E0330 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.lifetimeFrames = randomGetRange(0x14, 0x28);
            cfg.behaviorFlags = 0x80010;
            cfg.renderFlags = 0x8480800;
            cfg.scale = lbl_803E032C * (f32)(s32)
            randomGetRange(0x32, 100);
        }
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0xdb;
        break;
    case 0x7a1:
        if (spawnParams != NULL)
        {
            cfg.lifetimeFrames = (int)((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.behaviorFlags = 0x80080210;
            cfg.renderFlags = 0x8000800;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E032C * (f32)(s32)
            randomGetRange(0x32, 100)
            )
            ;
        }
        else
        {
            cfg.velocityX = lbl_803E0334 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.velocityY = lbl_803E0334 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.velocityZ = lbl_803E0334 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.lifetimeFrames = randomGetRange(0x14, 0x28);
            cfg.behaviorFlags = 0x80010;
            cfg.renderFlags = 0x8480800;
            cfg.scale = lbl_803E032C * (f32)(s32)
            randomGetRange(0x32, 100);
        }
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0x157;
        break;
    case 0x7a2:
        if (extraArgs != NULL)
        {
            cfg.velocityX = lbl_803E0338 * *extraArgs + lbl_803E0310 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.velocityY = lbl_803E0338 * extraArgs[1] + lbl_803E0310 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.velocityZ = lbl_803E0338 * extraArgs[2] + lbl_803E0310 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
        }
        cfg.lifetimeFrames = randomGetRange(10, 0x1e);
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 0x400800;
        cfg.scale = lbl_803E033C * (f32)(s32)
        randomGetRange(0x32, 100);
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0xde;
        break;
    case 0x7a3:
        intVal = randomGetRange(0xffff8001, 0x7fff);
        angle = (lbl_803E0344 * (f32)(s32)
        intVal
        )
        /
        lbl_803E0348;
        trigVal = mathCosf(angle);
        cfg.velocityX = (lbl_803E0340 * (f32)(s32)
        randomGetRange(100, 0x96)
        )
        *trigVal;
        trigVal = mathSinf(angle);
        cfg.velocityY = (lbl_803E0340 * (f32)(s32)
        randomGetRange(100, 0x96)
        )
        *trigVal;
        cfg.velocityZ = lbl_803E0324;
        cfg.lifetimeFrames = randomGetRange(0x14, 0x1e);
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 0x480800;
        cfg.scale = lbl_803E033C * (f32)(s32)
        randomGetRange(0x32, 100);
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0xde;
        break;
    case 0x7a4:
        if (extraArgs != NULL)
        {
            cfg.velocityX = lbl_803E0338 * *extraArgs + lbl_803E0310 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.velocityY = lbl_803E0338 * extraArgs[1] + lbl_803E0310 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.velocityZ = lbl_803E0338 * extraArgs[2] + lbl_803E0310 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
        }
        cfg.lifetimeFrames = randomGetRange(10, 0x1e);
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 0x400800;
        cfg.scale = lbl_803E033C * (f32)(s32)
        randomGetRange(0x32, 100);
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0xc22;
        break;
    case 0x7a5:
        intVal = randomGetRange(0xffff8001, 0x7fff);
        angle = (lbl_803E0344 * (f32)(s32)
        intVal
        )
        /
        lbl_803E0348;
        trigVal = mathCosf(angle);
        cfg.velocityX = (lbl_803E0330 * (f32)(s32)
        randomGetRange(100, 0x96)
        )
        *trigVal;
        trigVal = mathSinf(angle);
        cfg.velocityY = (lbl_803E0330 * (f32)(s32)
        randomGetRange(100, 0x96)
        )
        *trigVal;
        cfg.velocityZ = lbl_803E0324;
        cfg.lifetimeFrames = randomGetRange(0x1e, 0x28);
        cfg.behaviorFlags = 0x480000;
        cfg.renderFlags = 0x480800;
        cfg.scale = lbl_803E033C * (f32)(s32)
        randomGetRange(0x32, 100);
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0xc22;
        break;
    case 0x7a6:
        if (spawnParams != NULL)
        {
            cfg.lifetimeFrames = (int)((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.behaviorFlags = 0x80080210;
            cfg.renderFlags = 0x8000800;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E032C * (f32)(s32)
            randomGetRange(0x32, 100)
            )
            ;
        }
        else
        {
            cfg.velocityX = lbl_803E0334 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.velocityY = lbl_803E0334 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.velocityZ = lbl_803E0334 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.lifetimeFrames = randomGetRange(0x14, 0x28);
            cfg.behaviorFlags = 0x80010;
            cfg.renderFlags = 0x8480800;
            cfg.scale = lbl_803E032C * (f32)(s32)
            randomGetRange(0x32, 100);
        }
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0xc7e;
        break;
    case 0x7a7:
        if (spawnParams != NULL)
        {
            cfg.lifetimeFrames = (int)((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.behaviorFlags = 0x80080210;
            cfg.renderFlags = 0x8000800;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E032C * (f32)(s32)
            randomGetRange(0x32, 100)
            )
            ;
        }
        else
        {
            cfg.velocityX = lbl_803E0334 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.velocityY = lbl_803E0334 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.velocityZ = lbl_803E0334 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.lifetimeFrames = randomGetRange(0x14, 0x28);
            cfg.behaviorFlags = 0x80010;
            cfg.renderFlags = 0x8480800;
            cfg.scale = lbl_803E032C * (f32)(s32)
            randomGetRange(0x32, 100);
        }
        cfg.initialAlpha = 0xff;
        cfg.textureId = 0xc13;
        break;
    case 0x7a8:
        if (spawnParams != NULL)
        {
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E034C * (f32)(s32)
            randomGetRange(100, 200)
            )
            ;
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0350 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            +((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10 * ((PartFxSpawnParams*)spawnParams)->unk8;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0350 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            +((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0354 * (f32)(s32)
            randomGetRange(0x50, 100)
            )
            ;
            cfg.lifetimeFrames = randomGetRange(1, 0x14) + 10;
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = (spawnFlags | 0x80200);
            cfg.renderFlags = 0x4040800;
        }
        break;
    case 0x7a9:
        if (spawnParams != NULL)
        {
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0358 * (f32)(s32)
            randomGetRange(100, 200)
            )
            ;
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0334 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            +((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10 * ((PartFxSpawnParams*)spawnParams)->unk8;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0334 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            +((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0354 * (f32)(s32)
            randomGetRange(0x50, 100)
            )
            ;
            cfg.lifetimeFrames = randomGetRange(1, 0x14) + 10;
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = (spawnFlags | 0x80200);
            cfg.renderFlags = 0x4040800;
        }
        break;
    case 0x7aa:
        if (spawnParams != NULL)
        {
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E035C * (f32)(s32)
            randomGetRange(100, 200)
            )
            ;
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0314 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            +((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10 * ((PartFxSpawnParams*)spawnParams)->unk8;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0314 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            +((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0360 * (f32)(s32)
            randomGetRange(0x50, 100)
            )
            ;
            cfg.lifetimeFrames = randomGetRange(1, 0x23) + 0x19;
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = (spawnFlags | 0x80200);
            cfg.renderFlags = 0x4040800;
            cfg.renderFlags |= 0x20;
            cfg.overrideColor0 = 0xffff;
            cfg.overrideColor1 = 0xffff;
            cfg.overrideColor2 = randomGetRange(0, 0xffff);
            cfg.colorWord0 = 0xffff;
            cfg.colorWord1 = randomGetRange(0, 0x7fff);
            cfg.colorWord2 = (ushort)cfg.overrideColor2;
        }
        break;
    case 0x7ab:
        if (spawnParams != NULL)
        {
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0364 * (f32)(s32)
            randomGetRange(100, 200)
            )
            ;
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0368 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            +((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0368 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            +((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0354 * (f32)(s32)
            randomGetRange(0x23, 100)
            )
            ;
            cfg.lifetimeFrames = randomGetRange(1, 0x12) + 10;
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = (spawnFlags | 0x80080200);
            cfg.renderFlags = 0x4010800;
            ret = 1;
        }
        break;
    case 0x7ac:
        if (spawnParams != NULL)
        {
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0364 * (f32)(s32)
            randomGetRange(100, 200)
            )
            ;
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E036C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            +((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10 * ((PartFxSpawnParams*)spawnParams)->unk8;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E036C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            +((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0354 * (f32)(s32)
            randomGetRange(0x50, 100)
            )
            ;
            cfg.lifetimeFrames = randomGetRange(1, 0x17) + 5;
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = (spawnFlags | 0x80080200);
            cfg.renderFlags = 0x40800;
        }
        break;
    case 0x7ad:
        if (spawnParams != NULL)
        {
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0370 * (f32)(s32)
            randomGetRange(100, 200)
            )
            ;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0374 * (f32)(s32)
            randomGetRange(0xf, 0x14) + ((PartFxSpawnParams*)spawnParams)->unk10
            )
            ;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0378 * (f32)(s32)
            randomGetRange(0x50, 0x8c)
            )
            ;
            cfg.lifetimeFrames = randomGetRange(0, 10) + 0x32;
            cfg.textureId = 0xc10;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x80100;
            cfg.renderFlags = 0x4010020;
            cfg.colorWord0 = (u16)(((PartFxSpawnParams*)spawnParams)->unk6 >> 1);
            cfg.colorWord1 = (u16)(((PartFxSpawnParams*)spawnParams)->unk6 >> 1);
            cfg.colorWord2 = (u16)(((PartFxSpawnParams*)spawnParams)->unk6 >> 1);
            cfg.overrideColor0 = (uint)((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.overrideColor1 = (uint)((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.overrideColor2 = (uint)((PartFxSpawnParams*)spawnParams)->unk6;
        }
        break;
    case 0x7ae:
        if (spawnParams != NULL)
        {
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E037C * (f32)(s32)
            randomGetRange(100, 200)
            )
            ;
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0380 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0374 * (f32)(s32)
            randomGetRange(0xf, 0x14) + ((PartFxSpawnParams*)spawnParams)->unk10
            )
            ;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0380 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0384 * (f32)(s32)
            randomGetRange(0x50, 100)
            )
            ;
            cfg.lifetimeFrames = randomGetRange(0, 10) + 0x32;
            cfg.textureId = 0xc0d;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x80480000;
            cfg.renderFlags = 0x410800;
        }
        break;
    case 0x7af:
        if (spawnParams != NULL)
        {
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0388 * (f32)(s32)
            randomGetRange(100, 200)
            )
            ;
            cfg.startPosY = (lbl_803E038C + ((PartFxSpawnParams*)spawnParams)->unk10) * ((PartFxSpawnParams*)
                spawnParams)->unk8;
            cfg.scale = lbl_803E0390 * ((PartFxSpawnParams*)spawnParams)->unk8;
            cfg.lifetimeFrames = 5;
            cfg.textureId = 0x5e6;
            cfg.initialAlpha = ((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.behaviorFlags = 0x80200;
            cfg.renderFlags = 0x4088000;
            cfg.colorWord0 = 0xffff;
            cfg.colorWord1 = 0xffff;
            cfg.colorWord2 = 0xffff;
            cfg.overrideColor0 = 0xffff;
            cfg.overrideColor1 = 0xffff;
            cfg.overrideColor2 = 0xffff;
        }
        break;
    case 0x7b0:
        if (spawnParams != NULL)
        {
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0388 * (f32)(s32)
            randomGetRange(100, 200)
            )
            ;
            cfg.startPosY = (lbl_803E038C + ((PartFxSpawnParams*)spawnParams)->unk10) * ((PartFxSpawnParams*)
                spawnParams)->unk8;
            cfg.scale = lbl_803E0390 * ((PartFxSpawnParams*)spawnParams)->unk8;
            cfg.lifetimeFrames = 0xf;
            cfg.textureId = 0x5e6;
            cfg.initialAlpha = ((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.behaviorFlags = 0x80100;
            cfg.renderFlags = 0x4088000;
            cfg.colorWord0 = 0xffff;
            cfg.colorWord1 = 0xffff;
            cfg.colorWord2 = 0xffff;
            cfg.overrideColor0 = 0xffff;
            cfg.overrideColor1 = 0xffff;
            cfg.overrideColor2 = 0xffff;
        }
        break;
    case 0x7b1:
        if (spawnParams != NULL)
        {
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0394 * (f32)(s32)
            randomGetRange(0xffffffe5, 100)
            )
            ;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0398 * (f32)(s32)
            randomGetRange(10, 0x14)
            )
            ;
            cfg.lifetimeFrames = randomGetRange(0x23, 100);
            cfg.initialAlpha = 0xff;
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.behaviorFlags = 0x80480100;
            cfg.renderFlags = 0x8010800;
        }
        break;
    case 0x7b2:
        if (spawnParams != NULL)
        {
            cfg.velocityX = lbl_803E0390 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.velocityZ = lbl_803E0390 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.scale = lbl_803E039C * (f32)(s32)
            randomGetRange(0x1c, 0x20);
            cfg.lifetimeFrames = (int)((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.textureId = *spawnParams;
            cfg.behaviorFlags = 0x480204;
            cfg.renderFlags = 0x808;
        }
        break;
    case 0x7b3:
        if (spawnParams != NULL)
        {
            cfg.scale = lbl_803E03A0 * ((PartFxSpawnParams*)spawnParams)->unk8;
            cfg.lifetimeFrames = (int)((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk10 * (f32)(s32)
            randomGetRange(0x154, 0x2d5);
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.textureId = *spawnParams;
            cfg.behaviorFlags = 0x80114;
            cfg.renderFlags = 0x4000800;
        }
        break;
    case 0x7b4:
        if (spawnParams != NULL)
        {
            cfg.velocityX = lbl_803E0390 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.velocityZ = lbl_803E0390 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.scale = lbl_803E039C * (f32)(s32)
            randomGetRange(0x1c, 0x20);
            cfg.lifetimeFrames = (int)((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.textureId = *spawnParams;
            cfg.behaviorFlags = 0x480004;
            cfg.renderFlags = 0x480800;
        }
        break;
    case 0x7b5:
        if (spawnParams != NULL)
        {
            if (((PartFxSpawnParams*)spawnParams)->unk6 != 0)
            {
                cfg.scale = lbl_803E031C * ((PartFxSpawnParams*)spawnParams)->unk8 * (f32)(s32)
                randomGetRange(6, 10);
                cfg.behaviorFlags = 0xc1080000;
                cfg.renderFlags = 0x4400800;
                cfg.lifetimeFrames = 10;
            }
            else
            {
                cfg.scale = lbl_803E0330 * ((PartFxSpawnParams*)spawnParams)->unk8;
                cfg.behaviorFlags = 0xc1180000;
                cfg.renderFlags = 0x4400800;
                cfg.lifetimeFrames = randomGetRange(0x1c, 0x22) + 10;
            }
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10 * ((PartFxSpawnParams*)spawnParams)->unk8;
            cfg.velocityZ = lbl_803E0314 * (((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03A4 * (f32)(s32)
            randomGetRange(100, 0x96)
            )
            )
            ;
            vecRotateZXY(sourceObj, &cfg.velocityX);
            cfg.textureId = 0xc0a;
            cfg.renderFlags = cfg.renderFlags | 0x20;
            cfg.overrideColor0 = 0xffff;
            cfg.overrideColor1 = 0xffff;
            cfg.overrideColor2 = randomGetRange(0, 0xffff);
            cfg.colorWord0 = 0xffff;
            cfg.colorWord1 = randomGetRange(0, 0x7fff);
            cfg.colorWord2 = (ushort)cfg.overrideColor2;
        }
        break;
    case 0x7b6:
        if (spawnParams != NULL)
        {
            if (((PartFxSpawnParams*)spawnParams)->unk6 != 0)
            {
                cfg.scale = lbl_803E031C * ((PartFxSpawnParams*)spawnParams)->unk8 * (f32)(s32)
                randomGetRange(6, 10);
                cfg.behaviorFlags = 0x81080000;
                cfg.renderFlags = 0x4400800;
                cfg.lifetimeFrames = 10;
            }
            else
            {
                cfg.scale = lbl_803E0330 * ((PartFxSpawnParams*)spawnParams)->unk8;
                cfg.behaviorFlags = 0x81180000;
                cfg.renderFlags = 0x4400800;
                cfg.lifetimeFrames = randomGetRange(0x1c, 0x22) + 10;
            }
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10 * ((PartFxSpawnParams*)spawnParams)->unk8;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.velocityZ = lbl_803E0314 * (((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03A4 * (f32)(s32)
            randomGetRange(100, 0x96)
            )
            )
            ;
            vecRotateZXY(sourceObj, &cfg.velocityX);
            cfg.textureId = 0x5f5;
        }
        break;
    case 0x7b7:
        if (spawnParams != NULL)
        {
            if (extraArgs != NULL)
            {
                cfg.velocityX = lbl_803E0320 * *extraArgs + lbl_803E0310 * (f32)(s32)
                randomGetRange(0xffffff9c, 100);
                if (lbl_803E0324 != cfg.velocityY)
                {
                    cfg.velocityY = lbl_803E0320 * extraArgs[1] + lbl_803E0310 * (f32)(s32)
                    randomGetRange(0xffffff9c, 100);
                }
                cfg.velocityZ = lbl_803E0320 * extraArgs[2] + lbl_803E0310 * (f32)(s32)
                randomGetRange(0xffffff9c, 100);
            }
            else
            {
                cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03A8 * (f32)(s32)
                randomGetRange(0x5a, 100)
                )
                ;
            }
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unk8 * (f32)(s32)
            randomGetRange(0xffffffec, 0x14);
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk8 * (f32)(s32)
            randomGetRange(0xffffffec, 0x14);
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (f32)(s32)
            randomGetRange(0xffffffec, 0x14);
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0310 * (f32)(s32)
            randomGetRange(0x5a, 100)
            )
            ;
            cfg.initialAlpha = randomGetRange(0x9b, 0xff);
            cfg.lifetimeFrames = ((PartFxSpawnParams*)spawnParams)->unk4 + randomGetRange(1, 0x14);
            if (((PartFxSpawnParams*)spawnParams)->unk2 != 0)
            {
                cfg.behaviorFlags = 0x80080000;
            }
            else
            {
                cfg.behaviorFlags = 0x80480000;
            }
            if (*spawnParams != 0)
            {
                cfg.renderFlags = 0x4400800;
            }
            else
            {
                cfg.renderFlags = 0x4400000;
            }
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.linkGroup = 0xf;
        }
        break;
    case 0x7b8:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        }
        cfg.scale = lbl_803E03AC * (f32)(s32)
        randomGetRange(0x46, 0x50);
        cfg.lifetimeFrames = 5;
        cfg.textureId = 0x2d;
        cfg.behaviorFlags = 0x180200;
        cfg.renderFlags = 0;
        break;
    case 0x7b9:
        if (spawnParams != NULL)
        {
            cfg.velocityX = lbl_803E0390 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.velocityY = lbl_803E0390 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.velocityZ = lbl_803E0390 * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.lifetimeFrames = (int)*(short*)((int)extraArgs + 6);
            cfg.textureId = *(short*)extraArgs;
            cfg.scale = lbl_803E039C * (f32)(s32)
            randomGetRange(0x1c, 0x20);
            cfg.behaviorFlags = 0x480200;
            cfg.renderFlags = 0x808;
        }
        break;
    case 0x7ba:
        if (spawnParams != NULL)
        {
            cfg.lifetimeFrames = (int)*(short*)((int)extraArgs + 6);
            cfg.textureId = *(short*)extraArgs;
            cfg.scale = lbl_803E03A0 * extraArgs[2];
            cfg.behaviorFlags = 0x80110;
            cfg.renderFlags = 0x4000800;
        }
        break;
    case 0x7bb:
        if (spawnParams != NULL)
        {
            if (((PartFxSpawnParams*)spawnParams)->unk6 != 0)
            {
                cfg.scale = lbl_803E03B0 * ((PartFxSpawnParams*)spawnParams)->unk8 * (f32)(s32)
                randomGetRange(7, 10);
                cfg.behaviorFlags = 0xc0080200;
                cfg.renderFlags = 0x4010000;
                cfg.lifetimeFrames = 10;
                cfg.initialAlpha = 0x7f;
            }
            else
            {
                cfg.scale = lbl_803E0330 * ((PartFxSpawnParams*)spawnParams)->unk8;
                cfg.behaviorFlags = 0xc0180200;
                cfg.renderFlags = 0x4010000;
                cfg.lifetimeFrames = randomGetRange(0x1c, 0x22) + 10;
                cfg.initialAlpha = randomGetRange((s32)((PartFxSpawnParams*)spawnParams)->unk4,
                                                  ((PartFxSpawnParams*)spawnParams)->unk4 + 10);
            }
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10 * ((PartFxSpawnParams*)spawnParams)->unk8;
            cfg.velocityZ = lbl_803E03B4 * (((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03A8 * (f32)(s32)
            randomGetRange(100, 0x96)
            )
            )
            ;
            vecRotateZXY(sourceObj, &cfg.velocityX);
            cfg.textureId = 0xc10;
        }
        break;
    case 0x7bc:
        if (spawnParams != NULL)
        {
            if (((PartFxSpawnParams*)spawnParams)->unk6 != 0)
            {
                cfg.scale = lbl_803E03B0 * ((PartFxSpawnParams*)spawnParams)->unk8 * (f32)(s32)
                randomGetRange(7, 10);
                cfg.behaviorFlags = 0xc1080200;
                cfg.renderFlags = 0x5010000;
                cfg.lifetimeFrames = 10;
                cfg.initialAlpha = 0x7f;
            }
            else
            {
                cfg.scale = lbl_803E0330 * ((PartFxSpawnParams*)spawnParams)->unk8;
                cfg.behaviorFlags = 0xc1180200;
                cfg.renderFlags = 0x5010000;
                cfg.lifetimeFrames = randomGetRange(0x1c, 0x22) + 10;
                cfg.initialAlpha = randomGetRange((s32)((PartFxSpawnParams*)spawnParams)->unk4,
                                                  ((PartFxSpawnParams*)spawnParams)->unk4 + 10);
            }
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10 * ((PartFxSpawnParams*)spawnParams)->unk8;
            cfg.velocityZ = lbl_803E03B4 * (((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03B8 * (f32)(s32)
            randomGetRange(100, 0x96)
            )
            )
            ;
            vecRotateZXY(sourceObj, &cfg.velocityX);
            cfg.textureId = 0xc10;
        }
        break;
    case 0x7bd:
        if (spawnParams != NULL)
        {
            cfg.scale = *(f32*)&lbl_803E0310 * ((PartFxSpawnParams*)spawnParams)->unk8;
            cfg.behaviorFlags = 0x83000200;
            cfg.renderFlags = 0x1200000;
            cfg.lifetimeFrames = randomGetRange(10, 0x18);
            cfg.initialAlpha = 0xff;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10 * ((PartFxSpawnParams*)spawnParams)->unk8;
            cfg.velocityX = lbl_803E03BC * (((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0330 * (f32)(s32)
            randomGetRange(0xffffff6a, 0x96)
            )
            )
            ;
            cfg.velocityY = lbl_803E03BC * (((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0330 * (f32)(s32)
            randomGetRange(0xffffff6a, 0x96)
            )
            )
            ;
            cfg.velocityZ = lbl_803E0314 * (((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03C0 * (f32)(s32)
            randomGetRange(100, 0x96)
            )
            )
            ;
            vecRotateZXY(sourceObj, &cfg.velocityX);
            cfg.textureId = 0xc10;
        }
        break;
    case 0x7be:
        if (spawnParams != NULL)
        {
            if (extraArgs != NULL)
            {
                cfg.startPosX = extraArgs[3];
                cfg.startPosY = extraArgs[4];
                cfg.startPosZ = extraArgs[5];
                if (extraArgs[2] > lbl_803E0324)
                {
                    cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unkC * (((PartFxSpawnParams*)spawnParams)->unk8 *
                        (lbl_803E03C4 * (f32)(s32)
                    randomGetRange(100, 0x6b)
                    )
                    )
                    ;
                }
                else if (extraArgs[2] < lbl_803E0324)
                {
                    cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unkC * (((PartFxSpawnParams*)spawnParams)->unk8 *
                        (lbl_803E03C4 * (f32)(s32)
                    randomGetRange(100, 0x6b)
                    )
                    )
                    ;
                }
                else
                {
                    cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unkC * (((PartFxSpawnParams*)spawnParams)->unk8 *
                        (lbl_803E03B8 * (f32)(s32)
                    randomGetRange(100, 0x6b)
                    )
                    )
                    ;
                }
            }
            else
            {
                cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unkC * (((PartFxSpawnParams*)spawnParams)->unk8 * (
                    lbl_803E03B8 * (f32)(s32)
                randomGetRange(100, 0x6b)
                )
                )
                ;
            }
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03C8 * (f32)(s32)
            randomGetRange(0x1c, 0x22)
            )
            ;
            cfg.lifetimeFrames = randomGetRange(0x14, 0x1b);
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x80004;
            cfg.renderFlags = 0x8002820;
            if (((PartFxSpawnParams*)spawnParams)->unk4 != 0)
            {
                cfg.colorWord0 = 0xff2d;
                cfg.colorWord1 = 0xa8f;
                cfg.colorWord2 = 0x2c;
                cfg.overrideColor0 = 0xf78f;
                cfg.overrideColor1 = 0x9126;
                cfg.overrideColor2 = 0x4828;
            }
            else
            {
                cfg.colorWord0 = 0x69;
                cfg.colorWord1 = 0x863;
                cfg.colorWord2 = 0x7fff;
                cfg.overrideColor0 = 0x7fff;
                cfg.overrideColor1 = 0x2d1a;
                cfg.overrideColor2 = 0x8000;
            }
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
        }
        break;
    case 0x7bf:
        if (spawnParams != NULL)
        {
            if (extraArgs != NULL)
            {
                cfg.startPosX = extraArgs[3];
                cfg.startPosY = extraArgs[4];
                cfg.startPosZ = extraArgs[5];
            }
            cfg.scale = (lbl_803E0374 + ((PartFxSpawnParams*)spawnParams)->unkC) * (((PartFxSpawnParams*)spawnParams)->
                unk8 * (lbl_803E03CC * (f32)(s32)
            randomGetRange(10, 0xd)
            )
            )
            ;
            cfg.lifetimeFrames = randomGetRange(1, 2) + 2;
            cfg.behaviorFlags = 0x80014;
            cfg.renderFlags = 0x4000820;
            cfg.initialAlpha = (int)(lbl_803E03D0 * ((PartFxSpawnParams*)spawnParams)->unkC) + 0x40;
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            if (((PartFxSpawnParams*)spawnParams)->unk4 != 0)
            {
                cfg.colorWord0 = 0xff87;
                cfg.colorWord1 = 0x4817;
                cfg.colorWord2 = 0x23;
                cfg.overrideColor0 = 0xf78f;
                cfg.overrideColor1 = 0xffa9;
                cfg.overrideColor2 = 0xb32b;
            }
            else
            {
                cfg.colorWord0 = 0x7fff;
                cfg.colorWord1 = 0x1806;
                cfg.colorWord2 = 0x4cb3;
                cfg.overrideColor0 = 0xf48c;
                cfg.overrideColor1 = 0x9882;
                cfg.overrideColor2 = 0xd97d;
            }
        }
        break;
    case 0x7c0:
        if (spawnParams != NULL)
        {
            if (extraArgs != NULL)
            {
                cfg.startPosX = extraArgs[3];
                cfg.startPosY = extraArgs[4];
                cfg.startPosZ = extraArgs[5];
            }
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03D4 * (f32)(s32)
            randomGetRange(0x2d, 0x3a)
            )
            ;
            cfg.lifetimeFrames = randomGetRange(1, 7) + 0x1e;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x80004;
            cfg.renderFlags = 0x8440820;
            cfg.colorWord0 = 0xfb54;
            cfg.colorWord1 = 0;
            cfg.colorWord2 = 0;
            cfg.overrideColor0 = 0xffff;
            cfg.overrideColor1 = 0x8347;
            cfg.overrideColor2 = 0x9b49;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unkC * (((PartFxSpawnParams*)spawnParams)->unk8 * (
                lbl_803E03D8 * (f32)(s32)
            randomGetRange(100, 0x6c)
            )
            )
            ;
            cfg.velocityY = lbl_803E0324;
            cfg.velocityX = lbl_803E0324;
            if (extraArgs != NULL)
            {
                vecRotateZXY(extraArgs, &cfg.velocityX);
            }
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
        }
        break;
    case 0x7c1:
        if (spawnParams != NULL)
        {
            if (extraArgs != NULL)
            {
                cfg.startPosX = extraArgs[3];
                cfg.startPosY = extraArgs[4];
                cfg.startPosZ = extraArgs[5];
            }
            cfg.scale = (lbl_803E0374 + ((PartFxSpawnParams*)spawnParams)->unkC) * (((PartFxSpawnParams*)spawnParams)->
                unk8 * (lbl_803E03DC * (f32)(s32)
            randomGetRange(2, 0xd)
            )
            )
            ;
            cfg.lifetimeFrames = 0x11;
            cfg.behaviorFlags = 0x80114;
            cfg.renderFlags = 0x4000900;
            intVal = (int)(lbl_803E03D0 * ((PartFxSpawnParams*)spawnParams)->unkC);
            cfg.initialAlpha = intVal + 0x40;
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
        }
        break;
    case 0x7c2:
        if (spawnParams != NULL)
        {
            cfg.velocityY = lbl_803E0350 * (f32)(s32)
            randomGetRange(0, 100);
            cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unk8 * ((lbl_803E03E0 + cfg.velocityY) * (lbl_803E03E4 *
                (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            )
            ;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * ((lbl_803E03E0 + cfg.velocityY) * (lbl_803E03E4 *
                (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            )
            ;
            cfg.velocityY = -cfg.velocityY * ((PartFxSpawnParams*)spawnParams)->unk8;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03B0 * (f32)(s32)
            randomGetRange(0x19, 0x32)
            )
            ;
            cfg.startPosY = lbl_803E03E8 * ((PartFxSpawnParams*)spawnParams)->unk8;
            cfg.lifetimeFrames = randomGetRange(0x28, 0x50);
            cfg.textureId = 0xc10;
            cfg.initialAlpha = '@';
            cfg.behaviorFlags = 0x80104;
            cfg.renderFlags = 0x4800808;
        }
        break;
    case 0x7c3:
        if (spawnParams != NULL)
        {
            intVal = randomGetRange(0, 0xffff);
            radius = lbl_803E0330 * (f32)(s32)
            randomGetRange(0xffffff9c, 100) + (f32)((PartFxSpawnParams*)spawnParams)->unk6;
            angle = (lbl_803E0344 * (f32)(s32)
            intVal
            )
            /
            lbl_803E0348;
            trigVal = mathSinf(angle);
            cfg.startPosX = radius * trigVal + ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = lbl_803E0314 * (f32)(s32)
            randomGetRange(0, (s32)((PartFxSpawnParams*)spawnParams)->unk4) + ((PartFxSpawnParams*)spawnParams)->unk10;
            trigVal = mathCosf(angle);
            cfg.startPosZ = radius * trigVal + ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.lifetimeFrames = randomGetRange(10, 0x28);
            cfg.textureId = 0x156;
            cfg.behaviorFlags = 0x80480104;
            cfg.renderFlags = 0x4000800;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03EC * (f32)(s32)
            randomGetRange(0x31, 0x39)
            )
            ;
            cfg.initialAlpha = 0xff;
        }
        break;
    case 0x7c4:
        if (spawnParams != NULL)
        {
            if (extraArgs != NULL)
            {
                cfg.startPosX = extraArgs[3];
                cfg.startPosY = extraArgs[4];
                cfg.startPosZ = extraArgs[5];
            }
            cfg.scale = (lbl_803E0374 + ((PartFxSpawnParams*)spawnParams)->unkC) * (((PartFxSpawnParams*)spawnParams)->
                unk8 * (lbl_803E03CC * (f32)(s32)
            randomGetRange(10, 0xd)
            )
            )
            ;
            cfg.lifetimeFrames = randomGetRange(1, 2) + 2;
            cfg.behaviorFlags = 0x80004;
            cfg.renderFlags = 0x4000820;
            cfg.initialAlpha = (int)(lbl_803E03D0 * ((PartFxSpawnParams*)spawnParams)->unkC) + 0x40;
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            if (((PartFxSpawnParams*)spawnParams)->unk4 != 0)
            {
                cfg.colorWord0 = 0xff87;
                cfg.colorWord1 = 0x4817;
                cfg.colorWord2 = 0x23;
                cfg.overrideColor0 = 0xf78f;
                cfg.overrideColor1 = 0xffa9;
                cfg.overrideColor2 = 0xb32b;
            }
            else
            {
                cfg.colorWord0 = 0x7fff;
                cfg.colorWord1 = 0x1806;
                cfg.colorWord2 = 0x4cb3;
                cfg.overrideColor0 = 0xf48c;
                cfg.overrideColor1 = 0x9882;
                cfg.overrideColor2 = 0xd97d;
            }
        }
        break;
    case 0x7c5:
        if (spawnParams != NULL)
        {
            if (extraArgs != NULL)
            {
                cfg.startPosX = extraArgs[3];
                cfg.startPosY = extraArgs[4];
                cfg.startPosZ = extraArgs[5];
            }
            cfg.scale = (lbl_803E0374 + ((PartFxSpawnParams*)spawnParams)->unkC) * (((PartFxSpawnParams*)spawnParams)->
                unk8 * (lbl_803E03DC * (f32)(s32)
            randomGetRange(2, 0xd)
            )
            )
            ;
            cfg.lifetimeFrames = 0x11;
            cfg.behaviorFlags = 0x80104;
            cfg.renderFlags = 0x4000900;
            intVal = (int)(lbl_803E03D0 * ((PartFxSpawnParams*)spawnParams)->unkC);
            cfg.initialAlpha = intVal + 0x40;
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
        }
        break;
    case 0x7c6:
        cfg.scale = lbl_803E03A8;
        cfg.lifetimeFrames = randomGetRange(0x27, 0x31);
        cfg.behaviorFlags = 0x180000;
        cfg.renderFlags = 0x408000;
        cfg.textureId = 0x5ff;
        break;
    case 0x7c7:
        if (spawnParams != NULL)
        {
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E034C * (f32)(s32)
            randomGetRange(100, 200)
            )
            ;
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0350 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            +((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0350 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            +((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0354 * (f32)(s32)
            randomGetRange(0x50, 100)
            )
            ;
            cfg.lifetimeFrames = randomGetRange(1, 0x14) + 10;
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x80200;
            cfg.renderFlags = 0x4040800;
        }
        break;
    case 0x7c8:
        if (spawnParams != NULL)
        {
            cfg.velocityX = lbl_803E034C * (f32)(s32)
            randomGetRange(0xfffffed4, 300);
            cfg.velocityY = lbl_803E034C * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.velocityZ = lbl_803E034C * (f32)(s32)
            randomGetRange(0xfffffed4, 300);
            cfg.startPosY = lbl_803E03F0;
            cfg.scale = lbl_803E03F4;
            cfg.lifetimeFrames = randomGetRange(0x19, 0x20);
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.behaviorFlags = 0x80100;
            cfg.renderFlags = 0x40808;
        }
        break;
    case 0x7c9:
        cfg.velocityX = lbl_803E03F8 * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.velocityY = lbl_803E03FC * (f32)(s32)
        randomGetRange(0, 100);
        cfg.velocityZ = lbl_803E0400 * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.scale = lbl_803E0404 * (f32)(s32)
        randomGetRange(0xf, 0x14);
        cfg.lifetimeFrames = randomGetRange(300, 0x1c2);
        cfg.textureId = 0xc10;
        cfg.behaviorFlags = 0x8000100;
        cfg.renderFlags = 0x1000000;
        cfg.initialAlpha = 0x7f;
        break;
    case 0x7ca:
        if (spawnParams != NULL)
        {
            cfg.velocityX = lbl_803E035C * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.velocityY = lbl_803E0408 * (f32)(s32)
            randomGetRange(0, 100);
            cfg.velocityZ = lbl_803E035C * (f32)(s32)
            randomGetRange(0xffffff9c, 100);
            cfg.scale = lbl_803E03E4 * (f32)(s32)
            randomGetRange(1, 0x14);
            cfg.lifetimeFrames = randomGetRange(100, 0x78);
            cfg.textureId = 0x605;
            if (((PartFxSpawnParams*)spawnParams)->unk2 == 1)
            {
                cfg.colorWord0 = 0x2234;
                cfg.colorWord1 = 0x8a54;
                cfg.colorWord2 = 0xfff6;
                cfg.overrideColor0 = 0x2234;
                cfg.overrideColor1 = 0x8a54;
                cfg.overrideColor2 = 0xfff6;
            }
            else if (((PartFxSpawnParams*)spawnParams)->unk2 == 2)
            {
                cfg.colorWord0 = 0xfff6;
                cfg.colorWord1 = 0x1524;
                cfg.colorWord2 = 0x1524;
                cfg.overrideColor0 = 0xfff6;
                cfg.overrideColor1 = 0x1524;
                cfg.overrideColor2 = 0x1524;
            }
            else
            {
                cfg.colorWord0 = 0xfff6;
                cfg.colorWord1 = 0x8a54;
                cfg.colorWord2 = 0x2234;
                cfg.overrideColor0 = 0xfff6;
                cfg.overrideColor1 = 0x8a54;
                cfg.overrideColor2 = 0x2234;
            }
            cfg.behaviorFlags = 0x80110;
            cfg.renderFlags = 0x8002828;
            cfg.initialAlpha = -0x40;
        }
        break;
    case 0x7cb:
        if (spawnParams != NULL)
        {
            cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E034C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E034C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E034C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.scale = lbl_803E040C;
            cfg.lifetimeFrames = (int)
            (((PartFxSpawnParams*)spawnParams)->unk8 * (f32)(s32)
            randomGetRange(0x32, 0x3c)
            )
            ;
            cfg.textureId = 0x88;
            cfg.behaviorFlags = 0x480400;
            cfg.renderFlags = 0x80800;
        }
        break;
    case 0x7cc:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0380 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0380 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0380 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.scale = lbl_803E031C * (f32)(s32)
            randomGetRange(5, 0x14);
            cfg.lifetimeFrames = randomGetRange(0x2a, 0x32);
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.behaviorFlags = 0x580000;
            cfg.renderFlags = 0x800;
        }
        break;
    case 0x7cd:
        if (spawnParams != NULL)
        {
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0358 * (f32)(s32)
            randomGetRange(100, 200)
            )
            ;
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0334 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            +((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0334 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            +((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0354 * (f32)(s32)
            randomGetRange(0x50, 100)
            )
            ;
            cfg.lifetimeFrames = randomGetRange(1, 0x14) + 10;
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x280201;
            cfg.renderFlags = 0x4040800;
        }
        break;
    case 0x7ce:
        if (spawnParams != NULL)
        {
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0358 * (f32)(s32)
            randomGetRange(100, 200)
            )
            ;
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0334 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            +((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0334 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            +((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0354 * (f32)(s32)
            randomGetRange(0x50, 100)
            )
            ;
            cfg.lifetimeFrames = randomGetRange(5, 0xf);
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x280201;
            cfg.renderFlags = 0x4040800;
        }
        break;
    case 1999:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.scale = lbl_803E0410 * ((PartFxSpawnParams*)spawnParams)->unk8;
            cfg.lifetimeFrames = 10;
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.initialAlpha = 0x7f;
            cfg.behaviorFlags = 0x280101;
            cfg.renderFlags = 0x822;
            cfg.colorWord0 = 0x75b;
            cfg.colorWord1 = 0x1642;
            cfg.colorWord2 = 0xffff;
            cfg.overrideColor0 = 0x656a;
            cfg.overrideColor1 = 0x9f8;
            cfg.overrideColor2 = 0xffff;
            if (((PartFxSpawnParams*)spawnParams)->unk4 != 0)
            {
                cfg.behaviorFlags |= 0x20000000LL;
            }
        }
        break;
    case 2000:
        if (spawnParams != NULL)
        {
            if (extraArgs == NULL)
            {
                cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0370 * (f32)(s32)
                randomGetRange(100, 200)
                )
                ;
                cfg.velocityZ = lbl_803E0414 * (((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0418 * (f32)(s32)
                randomGetRange(100, 200)
                )
                )
                ;
            }
            else
            {
                cfg.velocityY = lbl_803E0328 * (f32)(s32)
                randomGetRange(100, 200);
                cfg.velocityZ = lbl_803E041C * (((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0420 * (f32)(s32)
                randomGetRange(0x32, 100)
                )
                )
                ;
            }
            cfg.startPosX = lbl_803E03E0 * (f32)(s32)
            randomGetRange(0xffffffec, 0x14) + ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = lbl_803E0374 * (f32)(s32)
            randomGetRange(0xf, 0x14) + ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0378 * (f32)(s32)
            randomGetRange(0x50, 0x8c)
            )
            ;
            cfg.lifetimeFrames = randomGetRange(0, 10) + 0xf;
            cfg.textureId = 0xc10;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x20080100;
            cfg.renderFlags = 0x4010020;
            cfg.colorWord0 = (u16)(((PartFxSpawnParams*)spawnParams)->unk6 >> 1);
            cfg.colorWord1 = (u16)(((PartFxSpawnParams*)spawnParams)->unk6 >> 1);
            cfg.colorWord2 = (u16)(((PartFxSpawnParams*)spawnParams)->unk6 >> 1);
            cfg.overrideColor0 = (uint)((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.overrideColor1 = (uint)((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.overrideColor2 = (uint)((PartFxSpawnParams*)spawnParams)->unk6;
        }
        break;
    case 0x7d1:
        if (spawnParams != NULL)
        {
            if (extraArgs == NULL)
            {
                cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0328 * (f32)(s32)
                randomGetRange(100, 200)
                )
                ;
                cfg.velocityZ = lbl_803E0424 * (((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0418 * (f32)(s32)
                randomGetRange(100, 200)
                )
                )
                ;
            }
            else
            {
                cfg.velocityY = lbl_803E0328 * (f32)(s32)
                randomGetRange(100, 200);
                cfg.velocityZ = lbl_803E0424 * (((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0370 * (f32)(s32)
                randomGetRange(100, 200)
                )
                )
                ;
            }
            cfg.startPosY = lbl_803E0380 * (f32)(s32)
            randomGetRange(0xffffffec, 0x14) + ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosX = lbl_803E0380 * (f32)(s32)
            randomGetRange(0xffffffec, 0x14) + ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0354 * (f32)(s32)
            randomGetRange(0x50, 100)
            )
            ;
            cfg.lifetimeFrames = randomGetRange(1, 0x14) + 10;
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x20080200;
            cfg.renderFlags = 0x4040800;
        }
        break;
    case 0x7d2:
        if (spawnParams != NULL)
        {
            if (*spawnParams != 0)
            {
                cfg.startPosY = lbl_803E0428;
                cfg.velocityX = lbl_803E0328 * (f32)(s32)
                randomGetRange(0xffffff9c, 100);
                cfg.velocityY = lbl_803E03B0 * (f32)(s32)
                randomGetRange(0xffffff9c, 100);
                cfg.velocityZ = lbl_803E0328 * (f32)(s32)
                randomGetRange(0xffffff9c, 100);
            }
            else
            {
                cfg.velocityX = lbl_803E0358 * (f32)(s32)
                randomGetRange(0xffffff9c, 100);
                cfg.velocityY = lbl_803E036C * (f32)(s32)
                randomGetRange(0xffffff9c, 100);
                cfg.velocityZ = lbl_803E0358 * (f32)(s32)
                randomGetRange(0xffffff9c, 100);
                cfg.startPosY = lbl_803E0314 * (f32)(s32)
                randomGetRange(100, 200);
            }
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (f32)(s32)
            randomGetRange(5, 10);
            cfg.lifetimeFrames = (int)((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk4;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x80110;
            cfg.renderFlags = 0x20900;
        }
        break;
    case 0x7d3:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E042C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E042C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E042C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.scale = lbl_803E0430 * (f32)(s32)
            randomGetRange(10, 0x14);
            cfg.lifetimeFrames = ((PartFxSpawnParams*)spawnParams)->unk2 + randomGetRange(1, 0x28);
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x480104;
            cfg.renderFlags = 0x8000080;
        }
        break;
    case 0x7d4:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E042C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E042C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E042C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.scale = lbl_803E0430 * (f32)(s32)
            randomGetRange(10, 0x14);
            cfg.lifetimeFrames = ((PartFxSpawnParams*)spawnParams)->unk2 + randomGetRange(1, 0x28);
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x1480104;
            cfg.renderFlags = 0x8000080;
        }
        break;
    case 0x7d5:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E042C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E042C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E042C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.scale = lbl_803E0430 * (f32)(s32)
            randomGetRange(10, 0x14);
            cfg.lifetimeFrames = ((PartFxSpawnParams*)spawnParams)->unk2 + randomGetRange(1, 0x28);
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x48010c;
            cfg.renderFlags = 0x8000080;
        }
        break;
    case 0x7d6:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E042C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E042C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E042C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.scale = lbl_803E0430 * (f32)(s32)
            randomGetRange(10, 0x14);
            cfg.lifetimeFrames = ((PartFxSpawnParams*)spawnParams)->unk2 + randomGetRange(1, 0x28);
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x40480104;
            cfg.renderFlags = 0x8000080;
        }
        break;
    case 0x7d7:
        cfg.scale = lbl_803E03E4;
        cfg.lifetimeFrames = (uint)framesThisStep * 3;
        cfg.initialAlpha = 0x32;
        cfg.textureId = 0x605;
        cfg.behaviorFlags = 0x80200;
        cfg.renderFlags = 0x820;
        cfg.colorWord0 = 0;
        cfg.colorWord1 = 0;
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = 0x656a;
        cfg.overrideColor1 = 0;
        cfg.overrideColor2 = 0xffff;
        break;
    case 0x7d8:
        cfg.startPosY = lbl_803E0434;
        cfg.startPosZ = lbl_803E0438;
        cfg.velocityZ = lbl_803E043C;
        cfg.scale = lbl_803E03B0 * (f32)(s32)
        randomGetRange(0x50, 0x58);
        cfg.lifetimeFrames = randomGetRange(0xd2, 0xe6);
        cfg.textureId = 0x7b;
        cfg.colorWord0 = 0xfaab;
        cfg.colorWord1 = 0xa9f;
        cfg.colorWord2 = 0x1d3;
        cfg.overrideColor0 = 0x7fff;
        cfg.overrideColor1 = 0x7fff;
        cfg.overrideColor2 = 0xff4b;
        cfg.initialAlpha = ',';
        cfg.behaviorFlags = 0x80004;
        cfg.renderFlags = 0x420820;
        if (spawnParams != NULL)
        {
            cfg.startPosX = lbl_803E03A8 * (f32)(s32)
            randomGetRange(0xffffff9c, 100) + cfg.startPosX;
            cfg.startPosY = lbl_803E03A8 * (f32)(s32)
            randomGetRange(0xffffff9c, 100) + cfg.startPosY;
            cfg.velocityZ = lbl_803E0440 * (f32)(s32)
            randomGetRange(0x5a, 0x6e);
            cfg.scale = lbl_803E035C;
            cfg.behaviorFlags |= 0x400000LL;
        }
        break;
    case 0x7d9:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        }
        cfg.scale = lbl_803E0330 * ((PartFxSpawnParams*)spawnParams)->unk8;
        cfg.lifetimeFrames = 10;
        cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
        cfg.initialAlpha = '@';
        cfg.behaviorFlags = 0x80104;
        cfg.renderFlags = 0x880;
        break;
    case 0x7da:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        }
        cfg.scale = lbl_803E0330 * ((PartFxSpawnParams*)spawnParams)->unk8;
        cfg.lifetimeFrames = 0x14;
        cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
        cfg.initialAlpha = 0x30;
        cfg.behaviorFlags = 0x80104;
        cfg.renderFlags = 0x880;
        break;
    case 0x7db:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        }
        cfg.scale = lbl_803E0330 * ((PartFxSpawnParams*)spawnParams)->unk8;
        cfg.lifetimeFrames = 0x14;
        cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
        cfg.initialAlpha = 0x30;
        cfg.behaviorFlags = 0x80104;
        cfg.renderFlags = 0x4000880;
        break;
    case 0x7dc:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E042C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E042C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E042C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.scale = ((f32)((PartFxSpawnParams*)spawnParams)->unk4 / lbl_803E0444) * (lbl_803E033C * (f32)(s32)
            randomGetRange(5, 100)
            )
            ;
            cfg.lifetimeFrames = ((PartFxSpawnParams*)spawnParams)->unk2 + randomGetRange(1, 0x28);
            cfg.initialAlpha = *spawnParams + randomGetRange(0x20, 0x40);
            cfg.textureId = 0x605;
            cfg.behaviorFlags = 0x80104;
            cfg.renderFlags = 0x8a0;
            variant = ((PartFxSpawnParams*)spawnParams)->unk6;
            switch (variant)
            {
            case 0x160:
                cfg.colorWord0 = 0;
                cfg.colorWord1 = 0xffff;
                cfg.colorWord2 = 0;
                cfg.overrideColor0 = 0x656a;
                cfg.overrideColor1 = 0xffff;
                cfg.overrideColor2 = 5000;
                break;
            case 0xde:
                cfg.colorWord0 = 0xffff;
                cfg.colorWord1 = 0x7fff;
                cfg.colorWord2 = 0;
                cfg.overrideColor0 = 0xffff;
                cfg.overrideColor1 = 0xffff;
                cfg.overrideColor2 = 5000;
                break;
            case 0x200:
                cfg.colorWord0 = 0xffff;
                cfg.colorWord1 = 0;
                cfg.colorWord2 = 0;
                cfg.overrideColor0 = 0xffff;
                cfg.overrideColor1 = 0x7fff;
                cfg.overrideColor2 = 5000;
                break;
            case 0xdd:
                cfg.colorWord0 = 40000;
                cfg.colorWord1 = 0;
                cfg.colorWord2 = 0;
                cfg.overrideColor0 = 0xffff;
                cfg.overrideColor1 = 0x7ffd;
                cfg.overrideColor2 = 0x4000;
                break;
            case 0xe0:
                cfg.colorWord0 = 0;
                cfg.colorWord1 = 0;
                cfg.colorWord2 = 0xffff;
                cfg.overrideColor0 = 0x656a;
                cfg.overrideColor1 = 0;
                cfg.overrideColor2 = 0xffff;
                break;
            case 0xe4:
                cfg.colorWord0 = 40000;
                cfg.colorWord1 = 40000;
                cfg.colorWord2 = 0xffff;
                cfg.overrideColor0 = 0xffff;
                cfg.overrideColor1 = 0xffff;
                cfg.overrideColor2 = 0xffff;
                break;
            case 0xdf:
                cfg.colorWord0 = 0;
                cfg.colorWord1 = 0;
                cfg.colorWord2 = 0xffff;
                cfg.overrideColor0 = 12000;
                cfg.overrideColor1 = randomGetRange(0x4b0, 32000);
                cfg.overrideColor2 = 0xffff;
                break;
            case 0x7b:
                cfg.colorWord0 = 0;
                cfg.colorWord1 = 0x7fff;
                cfg.colorWord2 = 0xffff;
                cfg.overrideColor0 = randomGetRange(0x4b0, 32000);
                cfg.overrideColor1 = 0xffff;
                cfg.overrideColor2 = 0xffff;
                break;
            default:
                cfg.colorWord0 = 0;
                cfg.colorWord1 = 0;
                cfg.colorWord2 = 0xffff;
                cfg.overrideColor0 = 0x656a;
                cfg.overrideColor1 = 0;
                cfg.overrideColor2 = 0xffff;
                break;
            }
        }
        break;
    case 0x7dd:
        if (spawnParams != NULL)
        {
            cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03A8 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03A8 * (f32)(s32)
            randomGetRange(0, 100)
            )
            ;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03A8 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.scale = lbl_803E034C * ((PartFxSpawnParams*)spawnParams)->unk8;
            cfg.lifetimeFrames = randomGetRange(0x1e, 0x6e);
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x3000000;
            cfg.renderFlags = 0x780880;
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
        }
        break;
    case 0x7de:
        if (spawnParams != NULL)
        {
            cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0340 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0334 * (f32)(s32)
            randomGetRange(0x32, 100)
            )
            ;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0340 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.scale = lbl_803E0448 * ((PartFxSpawnParams*)spawnParams)->unk8;
            cfg.lifetimeFrames = (int)
            (cfg.velocityY * (f32)(s32)
            randomGetRange(0x19, 100)
            )
            ;
            cfg.behaviorFlags = 0x1482000;
            cfg.renderFlags = 0x8400880;
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
        }
        break;
    case 0x7df:
        if (spawnParams != NULL)
        {
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8;
            vecRotateZXY(spawnParams, &cfg.velocityX);
            cfg.startPosX = cfg.startPosX + cfg.velocityX;
            cfg.startPosZ = cfg.startPosZ + cfg.velocityZ;
            cfg.velocityX = lbl_803E0324;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E044C * (f32)(s32)
            randomGetRange(0x32, 100)
            )
            ;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0310 * (f32)(s32)
            randomGetRange(0x4b, 100)
            )
            ;
            vecRotateZXY(spawnParams, &cfg.velocityX);
            cfg.scale = lbl_803E034C;
            cfg.lifetimeFrames = (int)
            (cfg.velocityY * (f32)(s32)
            randomGetRange(0x32, 100)
            )
            ;
            cfg.initialAlpha = 0x7f;
            cfg.behaviorFlags = 0x3000000;
            cfg.renderFlags = 0x1600080;
            cfg.textureId = 0xc10;
        }
        break;
    case 0x7e0:
        cfg.velocityX = lbl_803E0450 * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.velocityZ = lbl_803E0454 * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.scale = lbl_803E0408;
        cfg.lifetimeFrames = randomGetRange(0x28, 0x32);
        cfg.textureId = 0xc10;
        cfg.initialAlpha = 0x5a;
        cfg.behaviorFlags = 0xa100000;
        cfg.renderFlags = 0x400000;
        break;
    case 0x7e1:
        if (spawnParams != NULL)
        {
            cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03B0 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E034C * (f32)(s32)
            randomGetRange(0x32, 100)
            )
            ;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03B0 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.scale = lbl_803E042C;
            cfg.lifetimeFrames = (int)
            (cfg.velocityY * (f32)(s32)
            randomGetRange(0x32, 100)
            )
            ;
            cfg.initialAlpha = 0x7f;
            cfg.behaviorFlags = 0x1080000;
            cfg.renderFlags = 0x5400080;
            cfg.textureId = 0xc10;
        }
        break;
    case 0x7e2:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.velocityX = lbl_803E03E4 * (f32)(s32)
            randomGetRange(0xffffffd8, 0x28);
            cfg.velocityY = lbl_803E036C * (f32)(s32)
            randomGetRange(10, 0x50);
            cfg.velocityZ = lbl_803E03E4 * (f32)(s32)
            randomGetRange(0xffffffd8, 0x28);
            cfg.scale = lbl_803E033C * (f32)(s32)
            randomGetRange(0xf, 0x1e);
            cfg.lifetimeFrames = randomGetRange(0x122, 0x15e);
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x86000008;
            cfg.renderFlags = 0x1000000;
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
            if (((PartFxSpawnParams*)spawnParams)->unk2 == 1)
            {
                cfg.colorWord0 = (ushort)(randomGetRange(0x63bf, 0xffff) & 0xffff);
                cfg.overrideColor0 = cfg.colorWord0;
                cfg.colorWord1 = (ushort)(randomGetRange(0x3caf, 0xd8ef) & 0xffff);
                cfg.overrideColor1 = cfg.colorWord1;
                cfg.colorWord2 = (ushort)(randomGetRange(0x159f, 0x3caf) & 0xffff);
                cfg.overrideColor2 = cfg.colorWord2;
                cfg.renderFlags = cfg.renderFlags | 0x20;
            }
            else if (((PartFxSpawnParams*)spawnParams)->unk2 == 2)
            {
                cfg.colorWord0 = (ushort)(randomGetRange(0x3caf, 0x7fff) & 0xffff);
                cfg.overrideColor0 = cfg.colorWord0;
                cfg.colorWord1 = (ushort)(randomGetRange(0x7fff, 0xffff) & 0xffff);
                cfg.overrideColor1 = cfg.colorWord1;
                cfg.colorWord2 = (ushort)(randomGetRange(0x159f, 0x3caf) & 0xffff);
                cfg.overrideColor2 = cfg.colorWord2;
                cfg.renderFlags = cfg.renderFlags | 0x20;
            }
            if (((PartFxSpawnParams*)spawnParams)->unk4 != 0)
            {
                cfg.behaviorFlags |= 0x800000LL;
                cfg.initialAlpha = 'A';
            }
            cfg.sourceVecX = randomGetRange(0, 0xffff);
            cfg.sourceVecY = randomGetRange(0, 0xffff);
            cfg.sourceVecX = randomGetRange(0, 0xffff);
            cfg.sourcePosY = (f32)(s32)
            randomGetRange(0xe6, 800);
            cfg.sourcePosZ = (f32)(s32)
            randomGetRange(0xe6, 800);
            cfg.sourcePosW = (f32)(s32)
            randomGetRange(0xe6, 800);
        }
        break;
    case 0x7e3:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.velocityX = lbl_803E03E4 * (f32)(s32)
            randomGetRange(0xffffffd8, 0x28);
            cfg.velocityY = lbl_803E0458 * (f32)(s32)
            randomGetRange(10, 0x50);
            cfg.velocityZ = lbl_803E03E4 * (f32)(s32)
            randomGetRange(0xffffffd8, 0x28);
            cfg.scale = lbl_803E033C * (f32)(s32)
            randomGetRange(10, 0x14);
            cfg.lifetimeFrames = randomGetRange(0x122, 0x15e);
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x80008;
            cfg.renderFlags = 0x5000000;
            cfg.textureId = 0xc10;
        }
        break;
    case 0x7e4:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.velocityX = lbl_803E03E4 * (f32)(s32)
            randomGetRange(0xffffffd8, 0x28);
            cfg.velocityY = lbl_803E036C * (f32)(s32)
            randomGetRange(10, 0x50);
            cfg.velocityZ = lbl_803E03E4 * (f32)(s32)
            randomGetRange(0xffffffd8, 0x28);
            cfg.scale = lbl_803E045C * (f32)(s32)
            randomGetRange(5, 10);
            cfg.lifetimeFrames = randomGetRange(0x122, 0x15e);
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x80008;
            cfg.renderFlags = 0x5000100;
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
        }
        break;
    case 0x7e5:
        if (extraArgs != NULL)
        {
            cfg.velocityX = *extraArgs;
            cfg.velocityY = extraArgs[1];
            cfg.velocityZ = extraArgs[2];
        }
        cfg.scale = lbl_803E033C * (f32)(s32)
        randomGetRange(0x44, 100);
        cfg.lifetimeFrames = randomGetRange(100, 0x82);
        cfg.textureId = 0xc10;
        cfg.initialAlpha = randomGetRange(0x28, 0x2c);
        cfg.behaviorFlags = 0x180100;
        cfg.renderFlags = 0x5080800;
        break;
    case 0x7e6:
        if (spawnParams != NULL)
        {
            if (extraArgs != NULL)
            {
                cfg.velocityX = *extraArgs;
                cfg.velocityY = extraArgs[1];
                cfg.velocityZ = extraArgs[2];
            }
            else
            {
                cfg.velocityX = lbl_803E0324;
                cfg.velocityY = lbl_803E0324;
                cfg.velocityZ = lbl_803E0324;
            }
            cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E034C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            +cfg.velocityX;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E036C * (f32)(s32)
            randomGetRange(0x32, 100)
            )
            +cfg.velocityY;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E034C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            +cfg.velocityZ;
            cfg.scale = (f32)(
                ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0460 * (f32)(s32)randomGetRange(0x44, 100))
            )
            ;
            cfg.lifetimeFrames = randomGetRange(0x2d, 0x5f);
            cfg.textureId = 0xc10;
            cfg.behaviorFlags = 0x180100;
            cfg.renderFlags = 0x5080000;
            if (*spawnParams == 3)
            {
                cfg.initialAlpha = randomGetRange(0x26, 0x2b);
                cfg.renderFlags = cfg.renderFlags | 0x800;
            }
            else
            {
                cfg.initialAlpha = randomGetRange(0x26, 0x2b);
            }
        }
        break;
    case 0x7e7:
        cfg.velocityX = lbl_803E03F8 * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.velocityY = lbl_803E03FC * (f32)(s32)
        randomGetRange(0, 100);
        cfg.velocityZ = lbl_803E0400 * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.scale = lbl_803E0404 * (f32)(s32)
        randomGetRange(0xf, 0x14);
        cfg.lifetimeFrames = randomGetRange(0x96, 300);
        cfg.textureId = 0xc10;
        cfg.behaviorFlags = 0x8000100;
        cfg.renderFlags = 0x820;
        cfg.colorWord0 = 0;
        cfg.colorWord1 = 0xffff;
        cfg.colorWord2 = 0;
        cfg.overrideColor0 = 0;
        cfg.overrideColor1 = 0xffff;
        cfg.overrideColor2 = 0x4000;
        cfg.initialAlpha = '@';
        break;
    case 0x7e8:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        }
        cfg.scale = lbl_803E0330 * ((PartFxSpawnParams*)spawnParams)->unk8;
        cfg.lifetimeFrames = 10;
        cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
        cfg.initialAlpha = '@';
        cfg.behaviorFlags = 0x80100;
        cfg.renderFlags = 0x800;
        break;
    case 0x7e9:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        }
        cfg.scale = lbl_803E0330 * ((PartFxSpawnParams*)spawnParams)->unk8;
        cfg.lifetimeFrames = 0x14;
        cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
        cfg.initialAlpha = 0x0;
        cfg.behaviorFlags = 0x80100;
        cfg.renderFlags = 0x800;
        break;
    case 0x7ea:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        }
        cfg.scale = lbl_803E0330 * ((PartFxSpawnParams*)spawnParams)->unk8;
        cfg.lifetimeFrames = 0x14;
        cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
        cfg.initialAlpha = 0x0;
        cfg.behaviorFlags = 0x80100;
        cfg.renderFlags = 0x4000800;
        break;
    case 0x7eb:
        if (spawnParams != NULL)
        {
            if (extraArgs != NULL)
            {
                cfg.startPosX = extraArgs[3];
                cfg.startPosY = extraArgs[4];
                cfg.startPosZ = extraArgs[5];
            }
            intVal = randomGetRange(0, 4);
            if (intVal != 0)
            {
                cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unkC * (((PartFxSpawnParams*)spawnParams)->unk8 * (
                    lbl_803E03C4 * (f32)(s32)
                randomGetRange(100, 0x6b)
                )
                )
                ;
                cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03C8 * (f32)(s32)
                randomGetRange(0x1c, 0x22)
                )
                ;
                cfg.initialAlpha = 0xff;
                cfg.behaviorFlags = 0x80080000;
                cfg.renderFlags = 0x8002820;
            }
            else
            {
                cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E042C * (f32)(s32)
                randomGetRange(0x1c, 0x22)
                )
                ;
                cfg.initialAlpha = 0xff;
                cfg.behaviorFlags = 0x80000;
                cfg.renderFlags = 0x8000820;
            }
            cfg.lifetimeFrames = randomGetRange(0x14, 0x1b);
            cfg.colorWord0 = 2000;
            cfg.colorWord1 = 2000;
            cfg.colorWord2 = 0x7fff;
            cfg.overrideColor0 = 7000;
            cfg.overrideColor1 = 0x7fff;
            cfg.overrideColor2 = 0xffff;
            cfg.textureId = ((PartFxSpawnParams*)spawnParams)->unk6;
        }
        break;
    case 0x7ec:
        if (spawnParams != NULL)
        {
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E033C * (f32)(s32)
            randomGetRange(0x1e, 0x46)
            )
            ;
            cfg.lifetimeFrames = randomGetRange(0x1e, 0x28);
            cfg.initialAlpha = randomGetRange(0x40, 0x7f);
            cfg.textureId = 0x605;
            cfg.behaviorFlags = (u32)randFn_80080100;
            cfg.renderFlags = 0x28a0;
            cfg.colorWord0 = 0;
            cfg.colorWord1 = 0x7fff;
            cfg.colorWord2 = 0xffff;
            cfg.overrideColor0 = randomGetRange(40000, 0xffff);
            cfg.overrideColor1 = randomGetRange(0x4b0, 32000);
            cfg.overrideColor2 = 0xffff;
        }
        break;
    case 0x7ed:
        cfg.startPosY = lbl_803E0468;
        cfg.startPosZ = lbl_803E0324;
        cfg.velocityY = lbl_803E0424;
        cfg.scale = lbl_803E03B0 * (f32)(s32)
        randomGetRange(0x50, 0x58);
        cfg.lifetimeFrames = randomGetRange(0x50, 0x5a);
        cfg.textureId = 0x7b;
        cfg.colorWord0 = 0xfaab;
        cfg.colorWord1 = 0xa9f;
        cfg.colorWord2 = 0x1d3;
        cfg.overrideColor0 = 0x7fff;
        cfg.overrideColor1 = 0x7fff;
        cfg.overrideColor2 = 0xff4b;
        cfg.initialAlpha = ',';
        cfg.behaviorFlags = 0x200c0004;
        cfg.renderFlags = 0x420820;
        if (spawnParams != NULL)
        {
            cfg.startPosX = lbl_803E03A8 * (f32)(s32)
            randomGetRange(0xffffff9c, 100) + cfg.startPosX;
            cfg.startPosY = lbl_803E03A8 * (f32)(s32)
            randomGetRange(0xffffff9c, 100) + cfg.startPosY;
            cfg.velocityY = lbl_803E0358 * (f32)(s32)
            randomGetRange(0x5a, 0x6e);
            cfg.scale = lbl_803E035C;
            cfg.behaviorFlags |= 0x400000LL;
        }
        break;
    case 0x7ee:
        if (spawnParams != NULL)
        {
            cfg.scale = lbl_803E03B0 * (f32)(s32)
            randomGetRange(0x1e, 0x46);
            cfg.behaviorFlags = (u32)randFn_80080100;
            cfg.renderFlags = 0x8a0;
            cfg.colorWord0 = randomGetRange(40000, 0xffff);
            cfg.colorWord1 = randomGetRange(0x4b0, 32000);
            cfg.colorWord2 = 0xffff;
            cfg.overrideColor0 = 0;
            cfg.overrideColor1 = 0x7fff;
            cfg.overrideColor2 = 0xffff;
            cfg.lifetimeFrames = randomGetRange(0x1c, 0x22) + 0x14;
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.velocityZ = lbl_803E0324;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8;
            if (((PartFxSpawnParams*)spawnParams)->unk6 != 0)
            {
                cfg.velocityX = lbl_803E0374;
            }
            else
            {
                cfg.velocityX = lbl_803E046C;
            }
            cfg.textureId = 0x605;
        }
        break;
    case 0x7ef:
    case 0x801:
    case 0x808:
        cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.velocityX = lbl_803E0470 * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.velocityY = lbl_803E0474 * (f32)(s32)
        randomGetRange(0x32, 100);
        cfg.velocityZ = lbl_803E0478 * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.scale = lbl_803E047C * (f32)(s32)
        randomGetRange(0x14, 100);
        if (effectId == 0x808)
        {
            cfg.scale = cfg.scale * lbl_803E0314;
        }
        cfg.lifetimeFrames = randomGetRange(0x14, 100);
        cfg.textureId = 0xc10;
        cfg.colorWord0 = 0xffe4;
        cfg.colorWord1 = 0x15;
        cfg.colorWord2 = 0xc67b;
        cfg.overrideColor0 = 0x1378;
        cfg.overrideColor1 = 0xfec0;
        cfg.overrideColor2 = 0x2d55;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80080200;
        if ((effectId == 0x7ef) || (effectId == 0x808))
        {
            cfg.behaviorFlags |= 0x200001LL;
        }
        cfg.renderFlags = 0x4080820;
        break;
    case 0x7f0:
        cfg.velocityX = lbl_803E0480 * (f32)(s32)
        randomGetRange(0x32, 100);
        cfg.velocityY = lbl_803E040C;
        cfg.scale = lbl_803E0484;
        cfg.lifetimeFrames = 0x73;
        cfg.textureId = 0x632;
        cfg.colorWord0 = 0;
        cfg.colorWord1 = 0;
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = 0xffff;
        cfg.overrideColor1 = 0xffff;
        cfg.overrideColor2 = 0xffff;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x40180140;
        cfg.renderFlags = 0x820;
        break;
    case 0x7f1:
        cfg.velocityY = lbl_803E0380 * (f32)(s32)
        randomGetRange(8, 10);
        cfg.startPosY = lbl_803E0488;
        cfg.scale = lbl_803E0420 * (f32)(s32)
        randomGetRange(6, 0xc);
        cfg.lifetimeFrames = randomGetRange(0x3c, 0x5a);
        cfg.behaviorFlags = 0x80180000;
        cfg.renderFlags = 0x5440820;
        cfg.textureId = 0xc0b;
        cfg.initialAlpha = '@';
        cfg.colorWord0 = 0;
        cfg.colorWord1 = 0xffff;
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = 0xffff;
        cfg.overrideColor1 = 0;
        cfg.overrideColor2 = 0xffff;
        break;
    case 0x7f2:
        cfg.startPosY = lbl_803E048C;
        cfg.velocityX = lbl_803E0340 * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.velocityY = lbl_803E0368 * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.velocityZ = lbl_803E0340 * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.scale = lbl_803E0490;
        cfg.lifetimeFrames = randomGetRange(0xc, 0x3d);
        cfg.textureId = 0x605;
        cfg.colorWord0 = 0xffcc;
        cfg.colorWord1 = 0x23a8;
        cfg.colorWord2 = 0x325f;
        cfg.overrideColor0 = 0xfec1;
        cfg.overrideColor1 = 0x130c;
        cfg.overrideColor2 = 0xacf;
        cfg.initialAlpha = 0x80;
        cfg.behaviorFlags = 0x80100;
        cfg.renderFlags = 0x80820;
        break;
    case 0x7f3:
        if (spawnParams != NULL)
        {
            cfg.lifetimeFrames = 0x37;
            cfg.textureId = 0xc86;
            cfg.initialAlpha = -0xd;
            cfg.behaviorFlags = 0x80100;
            cfg.renderFlags = 0x828;
            if (((PartFxSpawnParams*)spawnParams)->unk6 == 0)
            {
                cfg.scale = lbl_803E0368 * (f32)(s32)
                randomGetRange(10, 0x14);
                cfg.startPosY = lbl_803E048C;
                cfg.colorWord0 = 0xffcc;
                cfg.colorWord1 = 0x23a8;
                cfg.colorWord2 = 0x325f;
                cfg.overrideColor0 = 0xfec1;
                cfg.overrideColor1 = 0x130c;
                cfg.overrideColor2 = 0xacf;
            }
            if (((PartFxSpawnParams*)spawnParams)->unk6 == 1)
            {
                cfg.scale = lbl_803E040C * (f32)(s32)
                randomGetRange(10, 0x14);
                cfg.startPosY = lbl_803E0494;
                cfg.colorWord0 = 0x23a8;
                cfg.colorWord1 = 0xffcc;
                cfg.colorWord2 = 0x325f;
                cfg.overrideColor0 = 0x130c;
                cfg.overrideColor1 = 0xfec1;
                cfg.overrideColor2 = 0xacf;
            }
            if (((PartFxSpawnParams*)spawnParams)->unk6 == 2)
            {
                cfg.scale = lbl_803E0498 * (f32)(s32)
                randomGetRange(10, 0x14);
                cfg.startPosY = lbl_803E0494;
                cfg.colorWord0 = 0xffcc;
                cfg.colorWord1 = 0xffcc;
                cfg.colorWord2 = 0x325f;
                cfg.overrideColor0 = 0xfec1;
                cfg.overrideColor1 = 0xffcc;
                cfg.overrideColor2 = 0xacf;
            }
        }
        break;
    case 0x7f4:
        cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
        cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
        cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        cfg.velocityX = *extraArgs;
        cfg.velocityY = extraArgs[1];
        cfg.velocityZ = extraArgs[2];
        cfg.scale = lbl_803E033C * (f32)(s32)
        randomGetRange(0x50, 0x58);
        cfg.textureId = 0x7b;
        cfg.lifetimeFrames = 0x50;
        variant = ((PartFxSpawnParams*)spawnParams)->unk6;
        if ((variant == 0) || (variant == 3))
        {
            cfg.colorWord0 = 65000;
            cfg.colorWord1 = 10000;
            cfg.colorWord2 = 10000;
            cfg.lifetimeFrames = 0x55;
        }
        else if ((variant == 1) || (variant == 4))
        {
            cfg.colorWord0 = 0;
            cfg.colorWord1 = 65000;
            cfg.colorWord2 = 0;
        }
        else if ((variant == 2) || (variant == 5))
        {
            cfg.colorWord0 = 0;
            cfg.colorWord1 = 0;
            cfg.colorWord2 = 65000;
        }
        if (((PartFxSpawnParams*)spawnParams)->unk6 >= 3)
        {
            cfg.overrideColor0 = 65000;
            cfg.overrideColor1 = 65000;
            cfg.overrideColor2 = 0;
            cfg.lifetimeFrames = 0x5a;
        }
        else
        {
            cfg.overrideColor0 = (uint)cfg.colorWord0;
            cfg.overrideColor1 = (uint)cfg.colorWord1;
            cfg.overrideColor2 = (uint)cfg.colorWord2;
        }
        cfg.initialAlpha = ',';
        cfg.behaviorFlags = 0x80002;
        cfg.renderFlags = 0x420820;
        break;
    case 0x7f5:
        if (spawnParams != NULL)
        {
            if (((PartFxSpawnParams*)spawnParams)->unk6 != 0)
            {
                cfg.scale = lbl_803E049C * (*(f32*)&lbl_803E031C * ((PartFxSpawnParams*)spawnParams)->unk8);
                cfg.behaviorFlags = 0x81080000;
                cfg.renderFlags = 0x4400800;
                cfg.lifetimeFrames = 10;
            }
            else
            {
                cfg.scale = lbl_803E0330 * ((PartFxSpawnParams*)spawnParams)->unk8;
                cfg.behaviorFlags = 0x81180000;
                cfg.renderFlags = 0x8400800;
                cfg.lifetimeFrames = randomGetRange(0x14, 0x1a) + 10;
            }
            cfg.velocityY = lbl_803E0314 * (((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E04A0 * (f32)(s32)
            randomGetRange(100, 0x96)
            )
            )
            ;
            vecRotateZXY(sourceObj, &cfg.velocityX);
            cfg.textureId = 0x5f5;
            cfg.initialAlpha = 0x80;
        }
        break;
    case 0x7f7:
        if (spawnParams != NULL)
        {
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0350 * (f32)(s32)
            randomGetRange(200, 300)
            )
            ;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E042C * (f32)(s32)
            randomGetRange(0x37, 0x41)
            )
            ;
            cfg.lifetimeFrames = (int)
            (((PartFxSpawnParams*)spawnParams)->unk8 * (f32)(s32)
            randomGetRange(0x1e, 0x28)
            )
            ;
            cfg.textureId = 0xc10;
            cfg.initialAlpha = 0x20;
            cfg.behaviorFlags = 0xc0080100;
            cfg.renderFlags = 0x4000800;
        }
        break;
    case 0x7f9:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E034C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03E4 * (f32)(s32)
            randomGetRange(0x32, 100)
            )
            ;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E04A4 * (f32)(s32)
            randomGetRange(0, 100)
            )
            ;
            cfg.scale = lbl_803E0330 * ((PartFxSpawnParams*)spawnParams)->unk8;
            cfg.lifetimeFrames = randomGetRange(0x3c, 0x4b);
            cfg.textureId = 0xc73;
            cfg.colorWord0 = 5000;
            variant = randomGetRange(0, 10000);
            cfg.colorWord1 = variant + 10000;
            variant = randomGetRange(0, 10000);
            cfg.colorWord2 = variant + 20000;
            cfg.overrideColor0 = 0;
            cfg.overrideColor1 = randomGetRange(0, 10000);
            intVal = randomGetRange(0, 10000);
            cfg.overrideColor2 = intVal + 20000;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x1080004;
            cfg.renderFlags = 0x800a020;
        }
        break;
    case 0x7fa:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E034C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03E4 * (f32)(s32)
            randomGetRange(0x32, 100)
            )
            ;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E04A8 * (f32)(s32)
            randomGetRange(0, 100)
            )
            ;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E040C * (f32)(s32)
            randomGetRange(10, 0x1e)
            )
            ;
            cfg.lifetimeFrames = randomGetRange(0x32, 0x50);
            cfg.textureId = 0xc10;
            cfg.colorWord0 = 0xffcf;
            cfg.colorWord1 = 0xf987;
            cfg.colorWord2 = 0xfff8;
            cfg.overrideColor0 = 0x7a;
            cfg.overrideColor1 = 0x57d2;
            cfg.overrideColor2 = 0xffee;
            cfg.initialAlpha = randomGetRange(0x7b, 0xff);
            cfg.behaviorFlags = 0x40080204;
            cfg.renderFlags = 0x4080820;
        }
        break;
    case 0x7fb:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E04AC * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E04AC * (f32)(s32)
            randomGetRange(0x32, 0x96)
            )
            ;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E04AC * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.scale = lbl_803E0330 * ((PartFxSpawnParams*)spawnParams)->unk8;
            cfg.lifetimeFrames = randomGetRange(0x28, 0x41);
            cfg.textureId = 0xc73;
            cfg.colorWord0 = 5000;
            variant = randomGetRange(0, 10000);
            cfg.colorWord1 = variant + 10000;
            variant = randomGetRange(0, 10000);
            cfg.colorWord2 = variant + 20000;
            cfg.overrideColor0 = 0;
            cfg.overrideColor1 = randomGetRange(0, 10000);
            intVal = randomGetRange(0, 10000);
            cfg.overrideColor2 = intVal + 20000;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x1080000;
            cfg.renderFlags = 0x800a020;
        }
        break;
    case 0x7fc:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E034C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03E4 * (f32)(s32)
            randomGetRange(0x32, 100)
            )
            ;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E034C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0310 * (f32)(s32)
            randomGetRange(10, 0x1e)
            )
            ;
            cfg.lifetimeFrames = randomGetRange(0x32, 0x50);
            cfg.textureId = 0xc10;
            cfg.colorWord0 = 0xffcf;
            cfg.colorWord1 = 0xf987;
            cfg.colorWord2 = 0xfff8;
            cfg.overrideColor0 = 0x7a;
            cfg.overrideColor1 = 0x57d2;
            cfg.overrideColor2 = 0xffee;
            cfg.initialAlpha = randomGetRange(0x40, 0x7f);
            cfg.behaviorFlags = 0x40080200;
            cfg.renderFlags = 0x4000820;
        }
        break;
    case 0x7fd:
        cfg.startPosX = lbl_803E03E8 - (f32)(s32)
        randomGetRange(0, 4);
        cfg.startPosY = lbl_803E03E8 - (f32)(s32)
        randomGetRange(0, 4);
        cfg.startPosZ = lbl_803E03E8 - (f32)(s32)
        randomGetRange(0, 4);
        cfg.scale = lbl_803E04AC;
        cfg.lifetimeFrames = randomGetRange(8, 0xe);
        cfg.behaviorFlags = 0x110100;
        cfg.renderFlags = 0x4000000;
        cfg.textureId = 0xdf;
        break;
    case 0x7fe:
        cfg.scale = lbl_803E04B0 * (f32)(s32)
        randomGetRange(100, 200);
        cfg.lifetimeFrames = randomGetRange(0x43, 100);
        cfg.textureId = 0xc10;
        cfg.colorWord0 = 0x7fff;
        cfg.colorWord1 = 0x7fff;
        cfg.colorWord2 = 0x7fff;
        cfg.overrideColor0 = 0x65a7;
        cfg.overrideColor1 = 0x433a;
        cfg.overrideColor2 = 0x1855;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x80180200;
        cfg.renderFlags = 0x5000020;
        break;
    case 0x7ff:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03B8 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E0330 * (f32)(s32)
            randomGetRange(0, 100)
            )
            ;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03B8 * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.scale = lbl_803E04B4 * ((PartFxSpawnParams*)spawnParams)->unk8 * (f32)(s32)
            randomGetRange(0x19, 100);
            cfg.lifetimeFrames = randomGetRange(0x28, 0xa5);
            cfg.textureId = 0xc73;
            cfg.colorWord0 = 15000;
            variant = randomGetRange(0, 10000);
            cfg.colorWord1 = variant + 20000;
            variant = randomGetRange(0, 10000);
            cfg.colorWord2 = variant + 30000;
            cfg.overrideColor0 = 10000;
            cfg.overrideColor1 = randomGetRange(10000, 20000);
            intVal = randomGetRange(0, 10000);
            cfg.overrideColor2 = intVal + 30000;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x1080000;
            cfg.renderFlags = 0x800a020;
        }
        break;
    case 0x800:
        if (spawnParams != NULL)
        {
            cfg.startPosX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.startPosY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.startPosZ = ((PartFxSpawnParams*)spawnParams)->unk14;
            cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E034C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E03E4 * (f32)(s32)
            randomGetRange(0x32, 100)
            )
            ;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E034C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.scale = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E04B8 * (f32)(s32)
            randomGetRange(10, 0x1e)
            )
            ;
            intVal = randomGetRange(0, 1) * 100;
            cfg.lifetimeFrames = randomGetRange(0x32, 0xb4) + intVal;
            cfg.textureId = 0xc10;
            cfg.colorWord0 = 0xffcf;
            cfg.colorWord1 = 0xf987;
            cfg.colorWord2 = 0xfff8;
            cfg.overrideColor0 = 0x7a;
            cfg.overrideColor1 = 0x57d2;
            cfg.overrideColor2 = 0xffee;
            cfg.initialAlpha = randomGetRange(0x40, 0x7f);
            cfg.behaviorFlags = 0x40080200;
            cfg.renderFlags = 0x4000820;
        }
        break;
    case 0x802:
        cfg.velocityX = lbl_803E04AC * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.velocityY = lbl_803E0350 * (f32)(s32)
        randomGetRange(0x28, 100);
        cfg.velocityZ = lbl_803E04AC * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.scale = lbl_803E04B8 * (f32)(s32)
        randomGetRange(4, 10);
        cfg.lifetimeFrames = randomGetRange(0x19, 0x23);
        cfg.textureId = 0xc10;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0xffff;
        cfg.colorWord2 = 50000;
        cfg.overrideColor0 = 0xffff;
        cfg.overrideColor1 = 54000;
        cfg.overrideColor2 = 0x7fff;
        cfg.initialAlpha = randomGetRange(0x54, 0x7a);
        cfg.behaviorFlags = 0x1080200;
        cfg.renderFlags = 0x5000020;
        break;
    case 0x803:
        cfg.velocityX = lbl_803E04BC * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.velocityY = lbl_803E04BC * (f32)(s32)
        randomGetRange(0xffffffb5, 100);
        cfg.scale = lbl_803E036C;
        cfg.lifetimeFrames = 0x32;
        cfg.colorWord0 = 2000;
        cfg.colorWord1 = 2000;
        variant = randomGetRange(0xffffec78, 5000);
        cfg.colorWord2 = variant + 10000;
        cfg.overrideColor0 = 8000;
        cfg.overrideColor1 = 8000;
        intVal = randomGetRange(0xffffec78, 5000);
        cfg.overrideColor2 = intVal + 12000;
        cfg.textureId = 0x639;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x1080004;
        cfg.renderFlags = 0x408028;
        break;
    case 0x804:
        if (spawnParams != NULL)
        {
            cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E042C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E042C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk8 * (lbl_803E042C * (f32)(s32)
            randomGetRange(0xffffff9c, 100)
            )
            ;
            cfg.scale = lbl_803E0430 * (f32)(s32)
            randomGetRange(10, 0x14);
            cfg.lifetimeFrames = ((PartFxSpawnParams*)spawnParams)->unk2 + randomGetRange(1, 0x28);
            cfg.textureId = 0xdf;
            cfg.initialAlpha = 0xff;
            cfg.behaviorFlags = 0x480100;
            cfg.renderFlags = 0x8000000;
        }
        break;
    case 0x805:
        cfg.startPosY = lbl_803E0324;
        cfg.startPosZ = lbl_803E0324;
        cfg.scale = lbl_803E04B4 * (f32)(s32)
        randomGetRange(0x50, 0x58);
        cfg.lifetimeFrames = randomGetRange(100, 0x6e);
        cfg.textureId = 0x7b;
        if (((PartFxSpawnParams*)spawnParams)->unk2 == 0)
        {
            cfg.colorWord0 = 20000;
            cfg.colorWord1 = 20000;
            cfg.colorWord2 = 0xffff;
            cfg.overrideColor0 = 20000;
            cfg.overrideColor1 = 10000;
            cfg.overrideColor2 = 0xffff;
        }
        else
        {
            cfg.colorWord0 = 0xffff;
            cfg.colorWord1 = 50000;
            cfg.colorWord2 = 0;
            cfg.overrideColor0 = 0xffff;
            cfg.overrideColor1 = 50000;
            cfg.overrideColor2 = 0;
        }
        cfg.initialAlpha = ',';
        cfg.behaviorFlags = 0x80004;
        cfg.renderFlags = 0x420820;
        cfg.velocityX = *extraArgs;
        cfg.velocityY = extraArgs[1];
        cfg.velocityZ = extraArgs[2];
        break;
    case 0x806:
        cfg.startPosZ = lbl_803E0488;
        vecRotateZXY(sourceObj, &cfg.startPosX);
        cfg.velocityY = lbl_803E04C0;
        cfg.scale = lbl_803E0328 * (f32)(s32)
        randomGetRange(0x50, 0x5f);
        cfg.lifetimeFrames = 0xfa;
        cfg.textureId = 0x7b;
        cfg.colorWord0 = 0xfaab;
        cfg.colorWord1 = 0xa9f;
        cfg.colorWord2 = 0x1d3;
        cfg.overrideColor0 = 0x7fff;
        cfg.overrideColor1 = 0x7fff;
        cfg.overrideColor2 = 0xff4b;
        cfg.initialAlpha = randomGetRange(0x32, 0x36);
        cfg.behaviorFlags = 0x80000;
        cfg.renderFlags = 0x4000820;
        break;
    case 0x807:
        cfg.startPosZ = lbl_803E0488;
        vecRotateZXY(sourceObj, &cfg.startPosX);
        cfg.velocityY = lbl_803E04C4;
        cfg.scale = lbl_803E0328 * (f32)(s32)
        randomGetRange(0x50, 0x5f);
        cfg.lifetimeFrames = 0xfa;
        cfg.textureId = 0x7b;
        cfg.colorWord0 = 2000;
        cfg.colorWord1 = 2000;
        cfg.colorWord2 = 0xfaab;
        cfg.overrideColor0 = 0x7fff;
        cfg.overrideColor1 = 0x7fff;
        cfg.overrideColor2 = 0xff4b;
        cfg.initialAlpha = randomGetRange(0x32, 0x36);
        cfg.behaviorFlags = 0x80000;
        cfg.renderFlags = 0x4000820;
        break;
    case 0x809:
        cfg.velocityX = lbl_803E04AC * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.velocityY = lbl_803E0330 * (f32)(s32)
        randomGetRange(0x28, 100);
        cfg.velocityZ = lbl_803E04AC * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.scale = lbl_803E036C * (f32)(s32)
        randomGetRange(4, 10);
        cfg.lifetimeFrames = randomGetRange(0x19, 0x23);
        cfg.textureId = 0xc10;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = 0xffff;
        cfg.colorWord2 = 50000;
        cfg.overrideColor0 = 0xffff;
        cfg.overrideColor1 = 58000;
        cfg.overrideColor2 = 38000;
        cfg.initialAlpha = randomGetRange(0xb8, 0xde);
        cfg.behaviorFlags = 0x1080200;
        cfg.renderFlags = 0x5000020;
        break;
    case 0x80a:
        cfg.velocityX = lbl_803E04AC * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.velocityY = lbl_803E04AC * (f32)(s32)
        randomGetRange(0x28, 100);
        cfg.velocityZ = lbl_803E04AC * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.scale = lbl_803E036C * (f32)(s32)
        randomGetRange(4, 10);
        cfg.lifetimeFrames = randomGetRange(0x19, 0x23);
        cfg.textureId = 0xc10;
        cfg.initialAlpha = randomGetRange(0x40, 0x7f);
        cfg.behaviorFlags = 0x80010;
        cfg.renderFlags = 0x4400800;
        break;
    case 0x80b:
        cfg.velocityX = lbl_803E0330 * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.velocityY = lbl_803E0330 * (f32)(s32)
        randomGetRange(0x28, 100);
        cfg.velocityZ = lbl_803E0330 * (f32)(s32)
        randomGetRange(0xffffff9c, 100);
        cfg.scale = lbl_803E03B0 * (f32)(s32)
        randomGetRange(4, 10);
        cfg.lifetimeFrames = randomGetRange(0x19, 0x23);
        cfg.textureId = 0xc10;
        cfg.initialAlpha = 0xff;
        cfg.behaviorFlags = 0x3000000;
        cfg.renderFlags = 0x600820;
        cfg.colorWord0 = 0xffff;
        cfg.colorWord1 = (u16)randomGetRange(0x7fff, 0xffff);
        cfg.colorWord2 = 0xffff;
        cfg.overrideColor0 = cfg.colorWord0;
        cfg.overrideColor1 = cfg.colorWord1;
        cfg.overrideColor2 = cfg.colorWord2;
        break;
    case 0x80c:
        if (spawnParams != NULL)
        {
            cfg.velocityX = ((PartFxSpawnParams*)spawnParams)->unkC;
            cfg.velocityY = ((PartFxSpawnParams*)spawnParams)->unk10;
            cfg.velocityZ = ((PartFxSpawnParams*)spawnParams)->unk14;
        }
        cfg.startPosZ = (f32)(s32)
        randomGetRange(0xfffffff0, 0x10);
        cfg.startPosY = lbl_803E04C8;
        cfg.scale = lbl_803E0310 * (f32)(s32)
        randomGetRange(4, 8);
        cfg.lifetimeFrames = randomGetRange(0xf, 0x14);
        cfg.textureId = 0xc10;
        cfg.initialAlpha = randomGetRange(0x20, 0x40);
        cfg.behaviorFlags = 0x1080010;
        cfg.renderFlags = 0x4400800;
        break;
    default:
        return -1;
    }
    cfg.behaviorFlags = cfg.behaviorFlags | spawnFlags;
    if (((cfg.behaviorFlags & 1) != 0) && ((cfg.behaviorFlags & 2) != 0)) cfg.behaviorFlags ^= 2LL;
    if ((cfg.behaviorFlags & 1) != 0)
    {
        if ((spawnFlags & 0x200000) != 0)
        {
            cfg.startPosX = cfg.startPosX + cfg.sourcePosY;
            cfg.startPosY = cfg.startPosY + cfg.sourcePosZ;
            cfg.startPosZ = cfg.startPosZ + cfg.sourcePosW;
        }
        else
        {
            if (cfg.attachedSource != 0)
            {
                cfg.startPosX = cfg.startPosX + *(f32*)((char*)cfg.attachedSource + 0x18);
                cfg.startPosY = cfg.startPosY + *(f32*)((char*)cfg.attachedSource + 0x1c);
                cfg.startPosZ = cfg.startPosZ + *(f32*)((char*)cfg.attachedSource + 0x20);
            }
        }
    }
    ret = (*gExpgfxInterface)->spawnEffect(&cfg, -1, effectId, ret);
    return ret;
}


void Effect20_func05(void)
{
    f32 sum;
    f32 step;
    sum = lbl_803DB888 + (step = lbl_803E0310 * timeDelta);
    lbl_803DB888 = sum;
    if (sum > 1.0f) lbl_803DB888 = lbl_803E0314;
    sum = lbl_803DB88C + step;
    lbl_803DB88C = sum;
    if (sum > 1.0f) lbl_803DB88C = lbl_803E0320;
    lbl_803DD400 = lbl_803DD400 + (s32)framesThisStep * 0x64;
    if (lbl_803DD400 > 0x7fff) lbl_803DD400 = 0;
    lbl_803DD40C = mathSinf(lbl_803E0344 * (f32)(s16)lbl_803DD400 / lbl_803E0348);
    lbl_803DD404 = lbl_803DD404 + (s32)framesThisStep * 0x32;
    if (lbl_803DD404 > 0x7fff) lbl_803DD404 = 0;
    lbl_803DD408 = mathSinf(lbl_803E0344 * (f32)(s16)lbl_803DD404 / lbl_803E0348);
}

/* Trivial 4b 0-arg blr leaves. */
void Effect16_func03_nop(void)
{
}

void Effect16_release(void)
{
}

void Effect16_initialise(void)
{
}

void Effect15_func05_nop(void)
{
}

void Effect15_func03_nop(void)
{
}

void Effect15_release(void)
{
}

void Effect15_initialise(void)
{
}

void Effect13_func05_nop(void)
{
}

void Effect13_func03_nop(void)
{
}

void Effect13_release(void)
{
}

void Effect13_initialise(void)
{
}

void Effect17_func03_nop(void)
{
}

void Effect17_release(void)
{
}

void Effect17_initialise(void)
{
}

void Effect18_func03_nop(void)
{
}

void Effect18_release(void)
{
}

void Effect18_initialise(void)
{
}

void Effect19_func03_nop(void)
{
}

void Effect19_release(void)
{
}

void Effect19_initialise(void)
{
}

void Effect20_func03_nop(void)
{
}

void Effect20_release(void)
{
}

void Effect20_initialise(void)
{
}

/* 8b "li r3, N; blr" returners. */
int Checkpoint_func09_ret_1(void) { return 0x1; }

extern f32 lbl_803E0504;
extern f32 lbl_803E0508;
extern f32 Curve_EvalHermite(f32* values, f32 t, f32* outTangent);

/* Advance along the checkpoint curve by dist; write position/angles to out. */
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

/* segment pragma-stack balance (re-split): */
#pragma dont_inline reset
#pragma dont_inline reset

/* === moved from main/dll/df_partfx.c [800D6660-800D7568) (TU re-split, docs/boundary_audit.md) === */
#pragma scheduling on
#pragma peephole on
#include "main/dll/df_partfx.h"
#include "main/dll/rom_curve_interface.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/baddie_state.h"
#include "main/objanim.h"
#include "main/resource.h"
#include "main/screen_transition.h"



/*
 * --INFO--
 *
 * Function: Checkpoint_func07
 * EN v1.0 Address: 0x800D6660
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x800D6844
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern f32 sqrtf(f32 x);
extern f32 lbl_803E050C;
extern f32 lbl_803E0510;
extern f32 lbl_803E0514;
extern f32 lbl_803E0518;

#pragma scheduling off
#pragma peephole off
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
#pragma peephole reset
#pragma scheduling reset


/*
 * --INFO--
 *
 * Function: FUN_800d7780
 * EN v1.0 Address: 0x800D7780
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x800D7CFC
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d7780(undefined param_1);


/* Trivial 4b 0-arg blr leaves. */
void Checkpoint_release(void)
{
}





























/* 8b "li r3, N; blr" returners. */

/* sda21 accessors. */

/* Pattern wrappers. */
void Checkpoint_reset(void) { extern u32 lbl_803DD410; /* #57 */ lbl_803DD410 = 0x0; }

/* 12b 3-insn patterns. */


/* misc 8b leaves */

/* Pattern wrappers. */

/* sda21 writers. */
#pragma peephole off
#pragma peephole reset

/* fcmp-eq-to-bool. */

/* multi-store leaf (single float broadcast). */


/* Checkpoint table initialiser. */
extern u32 lbl_8039CA98[];

#pragma scheduling off
#pragma peephole off







#pragma opt_common_subs off
#pragma opt_common_subs reset

#pragma opt_common_subs off
#pragma opt_common_subs reset


#pragma peephole reset
#pragma scheduling reset


#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
#pragma opt_common_subs reset
#pragma peephole reset
#pragma scheduling reset


#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
#pragma opt_common_subs reset
#pragma peephole reset
#pragma scheduling reset

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
#pragma scheduling reset

/* Checkpoint_Add: sorted insertion of (entry->_14 as key, entry as pointer) into lbl_8039C458 table. */
typedef struct CheckpointSlot
{
    u32 key;
    void* entry;
} CheckpointSlot;

#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
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
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off

#pragma scheduling reset

#pragma scheduling off
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
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
#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
#pragma opt_common_subs reset

struct PartDesc
{
    s16 ang[3];
    f32 sc[4];
};
#pragma scheduling off
#pragma peephole off

#pragma scheduling off
#pragma peephole off
#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
#pragma opt_common_subs reset
#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
#pragma opt_common_subs reset
typedef struct
{
    u8 r;
    u8 g;
    u8 b;
    u8 a;
} HudColor;

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
#pragma scheduling reset
#pragma peephole reset
