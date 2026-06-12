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
extern f32 lbl_803E01C4;
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
extern f32 lbl_803E022C;
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
u32 Checkpoint_find(s32 key, s32* idx_out);

extern f32 lbl_803E04D8;
extern f32 lbl_803E04DC;
extern f32 lbl_803E04E0;
extern f32 lbl_803E04E4;
extern f32 mathCosf(f32 x);


/* Build particle quad positions from a checkpoint pair. */
#pragma dont_inline off
s32 fn_800D55BC(u8* p, s32 idx, f32* out1, f32* out2, f32* out3, u8 mode, f32 fa, f32 fb);

/* Set *p to lbl_803DD414 (sign-extended) and return lbl_803DD418. */
u32 Checkpoint_func0E(s32* p);

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
s32 Checkpoint_func0F(PartFxItem* p);

/* Find item in lbl_803DD418 array whose rank equals target_rank. */
PartFxItem* Checkpoint_func10(s32 target_rank);

/* Init random offsets / chain advance with lookup. */
void Checkpoint_func0A(s32 key, f32* out_vec, u8* flag_byte);

/* Walk a chain via Checkpoint_find lookups starting from o->_0x10. */
void Checkpoint_func0C(PartFxNode* o);

/* Append v to array pointed to by lbl_803DD41C, capped at 10 entries.
 * NOTE: stuck at ~78% ? instruction scheduling differs. */
void Checkpoint_func0D(u32 v);

/* Tick: counter1, counter2 + rate*timeDelta; clamp; periodic sin. */
void Effect16_func05(void);

void Effect17_func05(void);

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

int Effect19_func04(void* sourceObj, int effectId, s16* spawnParams, u32 spawnFlags, u8 modelId, f32* extraArgs);

int Effect13_func04(void* sourceObj, int effectId, s16* spawnParams, u32 spawnFlags, u8 modelId);

int Effect17_func04(void* sourceObj, int effectId, s16* spawnParams, u32 spawnFlags, u8 modelId, s16* extraArgs);

int Effect16_func04(void* sourceObj, int effectId, s16* spawnParams, u32 spawnFlags, u8 modelId, s16* extraArgs);

int Effect15_func04(void* sourceObj, int effectId, s16* spawnParams, u32 spawnFlags, u8 modelId, f32* extraArgs);

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

void Effect19_func05(void);

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

int Effect20_func04(void* sourceObj, int effectId, s16* spawnParams, u32 spawnFlags, u8 modelId, f32* extraArgs);


void Effect20_func05(void);

/* Trivial 4b 0-arg blr leaves. */
void Effect16_func03_nop(void);

void Effect16_release(void);

void Effect16_initialise(void);

void Effect15_func05_nop(void);

void Effect15_func03_nop(void);

void Effect15_release(void);

void Effect15_initialise(void);

void Effect13_func05_nop(void);

void Effect13_func03_nop(void);

void Effect13_release(void);

void Effect13_initialise(void);

void Effect17_func03_nop(void);

void Effect17_release(void);

void Effect17_initialise(void);

void Effect18_func03_nop(void)
{
}

void Effect18_release(void)
{
}

void Effect18_initialise(void)
{
}

void Effect19_func03_nop(void);

void Effect19_release(void);

void Effect19_initialise(void);

void Effect20_func03_nop(void);

void Effect20_release(void);

void Effect20_initialise(void);

/* 8b "li r3, N; blr" returners. */
int Checkpoint_func09_ret_1(void);

extern f32 lbl_803E0504;
extern f32 lbl_803E0508;
extern f32 Curve_EvalHermite(f32* values, f32 t, f32* outTangent);

/* Advance along the checkpoint curve by dist; write position/angles to out. */
s32 Checkpoint_func08(u8* out, u8* o, f32 dist, s32 p3, u8 flag);

void Checkpoint_onGameLoop(void);

/* segment pragma-stack balance (re-split): */
#pragma dont_inline reset
#pragma dont_inline reset

/* === moved from main/dll/df_partfx.c [800D6660-800D7568) (TU re-split, docs/boundary_audit.md) === */
#pragma scheduling on
#pragma peephole on
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/baddie_state.h"



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
int Checkpoint_func07(int* obj, int* state);
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


/* Trivial 4b 0-arg blr leaves. */
void Checkpoint_release(void);





























/* 8b "li r3, N; blr" returners. */

/* sda21 accessors. */

/* Pattern wrappers. */
void Checkpoint_reset(void);

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
void Checkpoint_initialise(void);
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
void Checkpoint_Add(int* entry);
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
void Checkpoint_remove(int* obj);
#pragma opt_common_subs reset
#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
#pragma opt_common_subs reset

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

#pragma opt_common_subs off
#pragma opt_common_subs reset



extern f64 lbl_803E0520;
extern f32 lbl_803E051C;
extern f32 lbl_803E0528;
extern f32 lbl_803E052C;
extern f32 lbl_803E0530;
extern f32 lbl_803E0534;
extern f32 lbl_803E0538;

void Checkpoint_func06(int* obj, int* state, int filter);
#pragma scheduling reset
#pragma peephole reset
