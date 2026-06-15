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
FUN_800c8110(int sourceObj, undefined4 effectType, undefined2* spawnParams, uint spawnFlags, u8 argByte,
             int variant)
{
    undefined4 result;
    uint roll;
    int desc[3];
    undefined2 tmplRotX;
    undefined2 tmplRotY;
    undefined2 tmplRotZ;
    undefined4 tmplScale;
    float tmplPosX;
    float tmplPosY;
    float tmplPosZ;
    float velX;
    float velY;
    float velZ;
    float posX;
    float posY;
    float posZ;
    float scale;
    undefined2 word58;
    undefined2 effectId;
    uint flagsA;
    undefined4 flagsB;
    undefined4 word4c;
    uint word48;
    uint word44;
    undefined2 word40;
    undefined2 word3e;
    undefined2 word3c;
    u8 byte3a;
    u8 alpha;
    u8 byte37;
    u8 tmplByte;
    undefined4 pad30;
    uint rnd0;
    undefined4 biasC0;
    uint rnd1;
    undefined4 pad20;
    uint rnd2;
    undefined4 pad18;
    uint rnd3;

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
    if (sourceObj == 0)
    {
        result = 0xffffffff;
    }
    else
    {
        if ((spawnFlags & 0x200000) != 0)
        {
            if (spawnParams == (undefined2*)0x0)
            {
                return 0xffffffff;
            }
            tmplPosX = ((PartFxSpawnParams*)spawnParams)->posX;
            tmplPosY = ((PartFxSpawnParams*)spawnParams)->posY;
            tmplPosZ = ((PartFxSpawnParams*)spawnParams)->posZ;
            tmplScale = *(undefined4*)&((PartFxSpawnParams*)spawnParams)->scale;
            tmplRotZ = ((PartFxSpawnParams*)spawnParams)->unk4;
            tmplRotY = ((PartFxSpawnParams*)spawnParams)->unk2;
            tmplRotX = *spawnParams;
            tmplByte = argByte;
        }
        flagsA = 0;
        flagsB = 0;
        byte3a = (undefined)effectType;
        posX = lbl_803E0E4C;
        posY = lbl_803E0E4C;
        posZ = lbl_803E0E4C;
        velX = lbl_803E0E4C;
        velY = lbl_803E0E4C;
        velZ = lbl_803E0E4C;
        scale = lbl_803E0E4C;
        desc[2] = 0;
        desc[1] = 0xffffffff;
        alpha = 0xff;
        byte37 = 0;
        effectId = 0;
        word40 = 0xffff;
        word3e = 0xffff;
        word3c = 0xffff;
        word4c = 0xffff;
        word48 = 0xffff;
        word44 = 0xffff;
        word58 = 0;
        desc[0] = sourceObj;
        switch (effectType)
        {
        case 0x73a:
            rnd0 = randomGetRange(8, 10);
            velY = lbl_803E0E50 * (f32)(s32)
            rnd0;
            roll = randomGetRange(0, 0x28);
            if (roll == 0)
            {
                rnd0 = randomGetRange(0x15, 0x29);
                scale = lbl_803E0E38 *
                    (f32)(s32)
                rnd0;
                desc[2] = 0x1cc;
            }
            else
            {
                rnd0 = randomGetRange(8, 0x14);
                scale = lbl_803E0E38 *
                    (f32)(s32)
                rnd0;
                desc[2] = randomGetRange(0x5a, 0x78);
            }
            flagsA = 0x80180200;
            flagsB = 0x1000020;
            effectId = 0xc0b;
            alpha = 0x7f;
            word3c = 0x3fff;
            word3e = 0x3fff;
            word40 = 0x3fff;
            word44 = 0xffff;
            word48 = 0xffff;
            word4c = 0xffff;
            posY = lbl_803E0E54;
            break;
        case 0x73b:
            rnd0 = randomGetRange(0xffffffec, 0x14);
            velX = lbl_803E0E50 * (f32)(s32)
            rnd0;
            rnd1 = randomGetRange(8, 0x14);
            velY = lbl_803E0E50 * (f32)(s32)
            rnd1;
            rnd2 = randomGetRange(0xffffffec, 0x14);
            velZ = lbl_803E0E50 * (f32)(s32)
            rnd2;
            scale = lbl_803E0E58;
            desc[2] = 0x32;
            flagsA = 0x3000200;
            flagsB = 0x200020;
            effectId = 0x33;
            alpha = 0xff;
            word40 = 0xffff;
            word3e = 0xffff;
            word3c = 0xffff;
            word4c = 0xffff;
            word48 = randomGetRange(0, 0x8000);
            posY = lbl_803E0E5C;
            word44 = word48;
            break;
        default:
            return 0xffffffff;
        case 0x73d:
            rnd2 = randomGetRange(0xfffffff6, 10);
            posX = lbl_803E0E3C * (f32)(s32)
            rnd2;
            rnd1 = randomGetRange(0xfffffff6, 100);
            posY = lbl_803E0E50 * (f32)(s32)
            rnd1;
            rnd0 = randomGetRange(0xfffffff6, 10);
            posZ = lbl_803E0E3C * (f32)(s32)
            rnd0;
            rnd3 = randomGetRange(7, 9);
            scale = lbl_803E0E60 *
                lbl_803E0E64 * (f32)(s32)
            rnd3;
            desc[2] = 0x3c;
            flagsA = 0x80100;
            byte37 = 0x10;
            effectId = 0xde;
            break;
        case 0x73e:
            rnd3 = randomGetRange(0xfffffff6, 10);
            posX = lbl_803E0E3C * (f32)(s32)
            rnd3;
            rnd2 = randomGetRange(0xfffffff6, 100);
            posY = lbl_803E0E50 * (f32)(s32)
            rnd2;
            rnd1 = randomGetRange(0xfffffff6, 10);
            posZ = lbl_803E0E3C * (f32)(s32)
            rnd1;
            rnd0 = randomGetRange(7, 9);
            scale = lbl_803E0E60 *
                lbl_803E0E64 * (f32)(s32)
            rnd0;
            desc[2] = 0x3c;
            flagsA = 0x80100;
            byte37 = 0x10;
            effectId = 0xdf;
            break;
        case 0x73f:
            if (variant == 0)
            {
                rnd3 = randomGetRange(0xfffffff6, 10);
                posX = lbl_803E0E3C *
                    (f32)(s32)
                rnd3;
                rnd2 = randomGetRange(0xfffffff6, 100);
                posY = lbl_803E0E50 *
                    (f32)(s32)
                rnd2;
                rnd1 = randomGetRange(0xfffffff6, 10);
                rnd1 = rnd1 ^ 0x80000000;
                posZ = lbl_803E0E3C *
                    (f32)(s32)
                rnd1;
            }
            else
            {
                rnd3 = randomGetRange(0xfffffff6, 10);
                posX = lbl_803E0E3C *
                    (f32)(s32)
                rnd3 +
                    lbl_803E0E68;
                rnd2 = randomGetRange(0xfffffff6, 100);
                posY = lbl_803E0E50 *
                    (f32)(s32)
                rnd2 +
                    lbl_803E0E6C;
                rnd1 = randomGetRange(0xfffffff6, 10);
                rnd1 = rnd1 ^ 0x80000000;
                posZ = lbl_803E0E3C *
                    (f32)(s32)
                rnd1 +
                    lbl_803E0E70;
            }
            biasC0 = 0x43300000;
            rnd3 = randomGetRange(7, 9);
            scale = lbl_803E0E74 *
                lbl_803E0E64 * (f32)(s32)
            rnd3;
            desc[2] = 0x3c;
            flagsA = 0x80100;
            byte37 = 0x10;
            effectId = 0xde;
            break;
        case 0x740:
            if (variant == 0)
            {
                rnd3 = randomGetRange(0xfffffff6, 10);
                posX = lbl_803E0E3C *
                    (f32)(s32)
                rnd3;
                rnd2 = randomGetRange(0xfffffff6, 100);
                posY = lbl_803E0E50 *
                    (f32)(s32)
                rnd2;
                rnd1 = randomGetRange(0xfffffff6, 10);
                rnd1 = rnd1 ^ 0x80000000;
                posZ = lbl_803E0E3C *
                    (f32)(s32)
                rnd1;
            }
            else
            {
                rnd3 = randomGetRange(0xfffffff6, 10);
                posX = lbl_803E0E3C *
                    (f32)(s32)
                rnd3 +
                    lbl_803E0E68;
                rnd2 = randomGetRange(0xfffffff6, 100);
                posY = lbl_803E0E50 *
                    (f32)(s32)
                rnd2 +
                    lbl_803E0E6C;
                rnd1 = randomGetRange(0xfffffff6, 10);
                rnd1 = rnd1 ^ 0x80000000;
                posZ = lbl_803E0E3C *
                    (f32)(s32)
                rnd1 +
                    lbl_803E0E70;
            }
            biasC0 = 0x43300000;
            rnd3 = randomGetRange(7, 9);
            scale = lbl_803E0E74 *
                lbl_803E0E64 * (f32)(s32)
            rnd3;
            desc[2] = 0x3c;
            flagsA = 0x80100;
            byte37 = 0x10;
            effectId = 0xdf;
            break;
        case 0x741:
            if (spawnParams != (undefined2*)0x0)
            {
                posY = ((PartFxSpawnParams*)spawnParams)->posY;
            }
            scale = lbl_803E0E78;
            desc[2] = randomGetRange(0, 0x1e);
            desc[2] = desc[2] + 0x50;
            alpha = 0x60;
            flagsA = 0x80110;
            effectId = 0x7b;
            byte37 = 0x20;
            break;
        case 0x742:
            velZ = lbl_803E0E7C;
            rnd3 = randomGetRange(0xffffffec, 0x14);
            velX = lbl_803E0E80 * (f32)(s32)
            rnd3;
            rnd2 = randomGetRange(0xffffffec, 0x14);
            velY = lbl_803E0E80 * (f32)(s32)
            rnd2;
            scale = lbl_803E0E84;
            desc[2] = randomGetRange(0x46, 0x50);
            alpha = 0xff;
            flagsA = 0x82000104;
            flagsB = 0x400;
            effectId = 0x3f4;
            break;
        case 0x743:
            velZ = lbl_803E0E7C;
            rnd3 = randomGetRange(0xffffffec, 0x14);
            velX = lbl_803E0E80 * (f32)(s32)
            rnd3;
            rnd2 = randomGetRange(0xffffffec, 0x14);
            velY = lbl_803E0E80 * (f32)(s32)
            rnd2;
            scale = lbl_803E0E84;
            desc[2] = randomGetRange(0x46, 0x50);
            alpha = 0xff;
            flagsA = 0x82000104;
            flagsB = 0x400;
            effectId = 0x500;
            break;
        case 0x744:
            roll = randomGetRange(0, 4);
            if (roll == 4)
            {
                scale = lbl_803E0E88;
                alpha = 0x9b;
                flagsA = 0x480000;
                desc[2] = randomGetRange(0x1e, 0x28);
            }
            else
            {
                scale = lbl_803E0E8C;
                alpha = 0x7d;
                flagsA = 0x180000;
                desc[2] = 0x50;
            }
            flagsB = 0x2000000;
            effectId = 0x88;
        }
        flagsA = flagsA | spawnFlags;
        if (((flagsA & 1) != 0) && ((flagsA & 2) != 0))
        {
            flagsA = flagsA ^ 2;
        }
        if ((flagsA & 1) != 0)
        {
            if ((spawnFlags & 0x200000) == 0)
            {
                if (desc[0] != 0)
                {
                    posX = posX + *(float*)(desc[0] + 0x18);
                    posY = posY + *(float*)(desc[0] + 0x1c);
                    posZ = posZ + *(float*)(desc[0] + 0x20);
                }
            }
            else
            {
                posX = posX + tmplPosX;
                posY = posY + tmplPosY;
                posZ = posZ + tmplPosZ;
            }
        }
        result = (*gExpgfxInterface)->spawnEffect(desc, 0xffffffff, effectType, 0);
    }
    return result;
}

undefined4 FUN_800c9030(uint key, int* outIndex)
{
    int hi;
    int lo;
    int mid;

    *outIndex = -1;
    if ((int)key < 0)
    {
        return 0;
    }
    hi = DAT_803de090 + -1;
    lo = 0;
    while (true)
    {
        while (true)
        {
            if (hi < lo)
            {
                *outIndex = -1;
                return 0;
            }
            mid = hi + lo >> 1;
            if (key <= (uint)(&DAT_8039d0b8)[mid * 2]) break;
            lo = mid + 1;
        }
        if ((uint)(&DAT_8039d0b8)[mid * 2] <= key) break;
        hi = mid + -1;
    }
    *outIndex = mid;
    return (&DAT_8039d0bc)[mid * 2];
}

extern s16 lbl_803DD414;
extern s16 lbl_803DD416;

extern f32 lbl_803E04E8;
extern f32 lbl_803E0500;

extern f32 mathSinf(f32 x);

extern f32 sqrtf(f32);

#pragma dont_inline on
CheckpointRouteEntry* Checkpoint_find(s32 key, s32* idx_out)
{
    extern CheckpointSlot lbl_8039C458[]; /* #57 */
    extern s32 lbl_803DD410; /* #57 */
    s32 high;
    s32 low;
    s32 mid;
    *idx_out = -1;
    if (key < 0) return NULL;
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
            return lbl_8039C458[mid].entry;
        }
    }
    *idx_out = -1;
    return NULL;
}

extern f32 lbl_803E04D8;
extern f32 lbl_803E04DC;
extern f32 lbl_803E04E0;
extern f32 lbl_803E04E4;
extern f32 mathCosf(f32 x);

#pragma dont_inline off
s32 fn_800D55BC(CheckpointRouteEntry* p, s32 idx, f32* out1, f32* out2, f32* out3, u8 mode, f32 fa, f32 fb)
{
    s32 ret;
    s32 local_idx;
    CheckpointRouteEntry* q;
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
    q = Checkpoint_find(p->forwardLinkIds[idx], &local_idx);
    if (q == NULL)
    {
        q = Checkpoint_find(p->forwardLinkIds[1 - idx], &local_idx);
        ret = 2;
    }
    if (q == NULL)
    {
        return 0;
    }

    cosA = -mathSinf(lbl_803E04D8 * (f32)(p->heading << 8) / lbl_803E04DC);
    sinA = -mathCosf(lbl_803E04D8 * (f32)(p->heading << 8) / lbl_803E04DC);
    cosB = -mathSinf(lbl_803E04D8 * (f32)(q->heading << 8) / lbl_803E04DC);
    sinB = -mathCosf(lbl_803E04D8 * (f32)(q->heading << 8) / lbl_803E04DC);
    sclA = lbl_803E04E0 * (f32)(u32)p->width;
    sclB = lbl_803E04E0 * (f32)(u32)q->width;

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
            out1[0] = (f32)p->sideOffsets[i] * prodA + p->posX;
            out1[1] = (f32)q->sideOffsets[i] * prodB + q->posX;
            out1[2] = 2.0f * ((f32)(u32)p->waveAmplitude *
                mathSinf(3.1415927f * (f32)(p->wavePhase << 8) / 32768.0f));
            out1[3] = 2.0f * ((f32)(u32)q->waveAmplitude *
                mathSinf(3.1415927f * (f32)(q->wavePhase << 8) / 32768.0f));
            out2[0] = sclA * (f32)p->heightOffsets[i] + p->posY;
            out2[1] = sclB * (f32)q->heightOffsets[i] + q->posY;
            out2[2] = 0.0f;
            out2[3] = 0.0f;
            v3[0] = (f32)p->sideOffsets[i] * prodC + p->posZ;
            v3[1] = (f32)q->sideOffsets[i] * prodD + q->posZ;
            v3[2] = 2.0f * ((f32)(u32)p->waveAmplitude *
                mathCosf(3.1415927f * (f32)(p->wavePhase << 8) / 32768.0f));
            v3[3] = 2.0f * ((f32)(u32)q->waveAmplitude *
                mathCosf(3.1415927f * (f32)(q->wavePhase << 8) / 32768.0f));
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
        out1[0] = fa * (sclA * sinA) + p->posX;
        out1[1] = fa * (sclB * sinB) + q->posX;
        out1[2] = lbl_803E04E4 * ((f32)(u32)p->waveAmplitude *
            mathSinf(lbl_803E04D8 * (f32)(p->wavePhase << 8) / lbl_803E04DC));
        out1[3] = lbl_803E04E4 * ((f32)(u32)q->waveAmplitude *
            mathSinf(lbl_803E04D8 * (f32)(q->wavePhase << 8) / lbl_803E04DC));
        out2[0] = sclA * fb + p->posY;
        out2[1] = sclB * fb + q->posY;
        {
            f32 e8 = lbl_803E04E8;
            out2[2] = e8;
            out2[3] = e8;
        }
        out3[0] = fa * (sclA * -cosA) + p->posZ;
        out3[1] = fa * (sclB * -cosB) + q->posZ;
        out3[2] = lbl_803E04E4 * ((f32)(u32)p->waveAmplitude *
            mathCosf(lbl_803E04D8 * (f32)(p->wavePhase << 8) / lbl_803E04DC));
        out3[3] = lbl_803E04E4 * ((f32)(u32)q->waveAmplitude *
            mathCosf(lbl_803E04D8 * (f32)(q->wavePhase << 8) / lbl_803E04DC));
    }
    else
    {
        s32 pointIdx = mode - 2;
        out1[0] = (f32)p->sideOffsets[pointIdx] * (sclA * sinA) + p->posX;
        out1[1] = (f32)q->sideOffsets[pointIdx] * (sclB * sinB) + q->posX;
        out1[2] = lbl_803E04E4 * ((f32)(u32)p->waveAmplitude *
            mathSinf(lbl_803E04D8 * (f32)(p->wavePhase << 8) / lbl_803E04DC));
        out1[3] = lbl_803E04E4 * ((f32)(u32)q->waveAmplitude *
            mathSinf(lbl_803E04D8 * (f32)(q->wavePhase << 8) / lbl_803E04DC));
        out2[0] = sclA * (f32)p->heightOffsets[pointIdx] + p->posY;
        out2[1] = sclB * (f32)q->heightOffsets[pointIdx] + q->posY;
        {
            f32 e8 = lbl_803E04E8;
            out2[2] = e8;
            out2[3] = e8;
        }
        out3[0] = (f32)p->sideOffsets[pointIdx] * (sclA * -cosA) + p->posZ;
        out3[1] = (f32)q->sideOffsets[pointIdx] * (sclB * -cosB) + q->posZ;
        out3[2] = lbl_803E04E4 * ((f32)(u32)p->waveAmplitude *
            mathCosf(lbl_803E04D8 * (f32)(p->wavePhase << 8) / lbl_803E04DC));
        out3[3] = lbl_803E04E4 * ((f32)(u32)q->waveAmplitude *
            mathCosf(lbl_803E04D8 * (f32)(q->wavePhase << 8) / lbl_803E04DC));
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
    CheckpointRouteEntry* n;
    s32 alt_found;
    n = Checkpoint_find(key, &local_idx);
    if (n == 0) return;
    out_vec[0] = (f32)(s32)
    randomGetRange(-0x63, 0x63) / lbl_803E0500;
    out_vec[1] = (f32)(s32)
    randomGetRange(-0x63, 0x63) / lbl_803E0500;
    out_vec[2] = (f32)(s32)
    randomGetRange(0, 0x63) / lbl_803E0500;
    alt_found = 0;
    {
        s32 v = n->forwardLink0;
        if (v != 0)
        {
            CheckpointRouteEntry* m = Checkpoint_find(v, &local_idx);
            if (m->forwardLink0 > -1)
            {
                alt_found = 1;
            }
        }
    }
    if ((s8) * flag_byte == 0)
    {
        if (alt_found != 0)
        {
            *(s32*)(out_vec + 4) = n->forwardLink0;
        }
        else
        {
            s32 v = n->backLink0;
            if (v > -1)
            {
                *(s32*)(out_vec + 4) = v;
                *flag_byte = 1;
            }
        }
    }
    else
    {
        s32 v = n->backLink0;
        if (v != 0)
        {
            *(s32*)(out_vec + 4) = v;
        }
        else if (alt_found != 0)
        {
            *(s32*)(out_vec + 4) = n->forwardLink0;
            *flag_byte = 0;
        }
    }
}

void Checkpoint_func0C(CheckpointRouteState* o)
{
    s32 local_idx;
    CheckpointRouteEntry* ret;
    s32 nxt;
    ret = Checkpoint_find(o->startCheckpointId, &local_idx);
    if (ret == 0)
    {
        o->currentCheckpointId = 0;
        o->routeProgress = lbl_803E04E8;
    }
    else
    {
        while ((nxt = ret->backLink0) > -1)
        {
            ret = Checkpoint_find(nxt, &local_idx);
            o->linkDepth = o->linkDepth + 1;
        }
        o->currentCheckpointId = o->startCheckpointId;
        o->routeProgress = lbl_803E04E8;
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
    CheckpointRouteEntry* n;
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
        n = Checkpoint_find(*(s32*)(o + 0x10), &local_idx);
        if (n == NULL)
        {
            return 1;
        }
        if (n->forwardLink0 < 0)
        {
            *(s32*)(o + 0x10) = -1;
            return 1;
        }
        alt = 0;
        if (n->forwardLink1 > -1 && *(u8*)(o + 0x30) != 0)
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
            *(s32*)(o + 0x10) = n->backLinkIds[alt];
            *(f32*)(o + 8) = lbl_803E0508;
            if (alt != 0 && *(s32*)(o + 0x10) < 0)
            {
                *(s32*)(o + 0x10) = n->backLink0;
            }
        }
        else if (clamp == 1 && seg < dist)
        {
            *(s32*)(o + 0x10) = n->forwardLinkIds[alt];
            *(f32*)(o + 8) = lbl_803E04E8;
            if (alt != 0 && *(s32*)(o + 0x10) < 0)
            {
                *(s32*)(o + 0x10) = n->forwardLink0;
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

#include "main/game_object.h"

extern f32 sqrtf(f32 x);
extern f32 lbl_803E050C;
extern f32 lbl_803E0510;
extern f32 lbl_803E0514;
extern f32 lbl_803E0518;

#pragma opt_common_subs off
int Checkpoint_func07(GameObject* obj, CheckpointRouteState* state)
{
    extern int getAngle(f32 dx, f32 dz); /* #57 */
    s32 slotC;
    s32 slot8;
    CheckpointRouteEntry* cp;
    CheckpointRouteEntry* cp2;
    short ang;
    f32 cosv, sinv, cos2, sin2;
    f32 dist, dist2, nx, nz, offs, dz;
    f32 offs2, distA, distB, dx, dy, len, q, proj, proj2, t0, sum, frac, zero;

    if (state->currentCheckpointId < 0)
    {
        state->linkDepth = 0;
        state->routeProgress = lbl_803E04E8;
        if (state->startCheckpointId < 0)
        {
            return 0;
        }
        state->currentCheckpointId = state->startCheckpointId;
    }
    cp = Checkpoint_find(state->currentCheckpointId, &slot8);
    if (cp == NULL)
    {
        state->currentCheckpointId = -1;
        return 0;
    }
    cosv = mathSinf((lbl_803E04D8 * (f32)(cp->heading << 8)) / lbl_803E04DC);
    sinv = mathCosf((lbl_803E04D8 * (f32)(cp->heading << 8)) / lbl_803E04DC);
    offs = -(cp->posX * cosv + cp->posZ * sinv);
    dist = offs + (cosv * obj->anim.localPosX + sinv * obj->anim.localPosZ);
    if (cp->backLink0 > -1 && dist >= lbl_803E04E8)
    {
        state->currentCheckpointId = cp->backLink0;
        state->routeProgress = lbl_803E050C;
        state->linkDepth = state->linkDepth - 1;
        return cp->heading;
    }
    if (cp->forwardLink0 < 0)
    {
        return cp->heading;
    }
    cp2 = Checkpoint_find(cp->forwardLink0, &slotC);
    ang = getAngle(cp2->posX - cp->posX, cp2->posZ - cp->posZ);
    cos2 = mathSinf((lbl_803E04D8 * (f32)(cp2->heading << 8)) / lbl_803E04DC);
    sin2 = mathCosf((lbl_803E04D8 * (f32)(cp2->heading << 8)) / lbl_803E04DC);
    offs2 = -(cp2->posX * cos2 + cp2->posZ * sin2);
    dist2 = offs2 + (cos2 * obj->anim.localPosX + sin2 * obj->anim.localPosZ);
    zero = lbl_803E04E8;
    if (dist2 < zero)
    {
        state->currentCheckpointId = cp->forwardLink0;
        state->routeProgress = zero;
        state->linkDepth = state->linkDepth + 1;
        return ang;
    }
    distA = offs + (cosv * cp2->posX + sinv * cp2->posZ);
    distB = offs2 + (cos2 * cp->posX + sin2 * cp->posZ);
    if (((distA < zero && dist < zero) || (distA >= lbl_803E04E8 && dist >= lbl_803E04E8)) &&
        ((distB <= lbl_803E04E8 && dist2 <= lbl_803E04E8) || (distB > lbl_803E04E8 && dist2 > lbl_803E04E8)))
    {
        dx = cp->posX - cp2->posX;
        dy = cp->posY - cp2->posY;
        dz = cp->posZ - cp2->posZ;
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
        state->routeProgress = frac;
        if (state->routeProgress < lbl_803E04E8)
        {
            state->routeProgress = lbl_803E04E8;
        }
        if (state->routeProgress >= lbl_803E0518)
        {
            state->routeProgress = lbl_803E0518;
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

/* Checkpoint_Add: sorted insertion of route entries by their checkpoint key. */
#pragma opt_common_subs off
#pragma peephole off
void Checkpoint_Add(CheckpointRouteEntry* entry)
{
    extern CheckpointSlot lbl_8039C458[]; /* #57 */
    extern u32 lbl_803DD410; /* #57 */
    int i = 0;
    CheckpointSlot* p = lbl_8039C458;
    int count;
    while (i < (count = lbl_803DD410) && (u32)entry->sortKey > p[i].key)
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
    lbl_8039C458[i].key = entry->sortKey;
}
#pragma opt_common_subs reset

#pragma opt_common_subs off
void Checkpoint_remove(CheckpointRouteEntry* obj)
{
    extern CheckpointSlot lbl_8039C458[]; /* #57 */
    extern u32 lbl_803DD410; /* #57 */
    int count;
    int i = 0;
    CheckpointSlot* p = lbl_8039C458;
    CheckpointSlot* e;

    while (i < (count = lbl_803DD410) && (u32)obj->sortKey != p[i].key)
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

void Checkpoint_func06(GameObject* obj, CheckpointRouteState* state, int filter)
{
    extern CheckpointSlot lbl_8039C458[]; /* #57 */
    extern u32 lbl_803DD410; /* #57 */
    int stack[64];
    char visited[200];
    s32 cur;
    s32 slot;
    int k, count, i, j;
    CheckpointRouteEntry* cp;
    CheckpointRouteEntry* n;
    CheckpointRouteEntry* e;
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
    cp = Checkpoint_find(state->startCheckpointId, &cur);
    if (cp != NULL)
    {
        stack[count++] = cur;
    }
    else
    {
        for (i = 0; i < (int)lbl_803DD410; i++)
        {
            e = lbl_8039C458[i].entry;
            if (visited[i] == 0 && (filter == -1 || e->group == filter))
            {
                ddx = e->posX - obj->anim.localPosX;
                ddy = e->posY - obj->anim.localPosY;
                ddz = e->posZ - obj->anim.localPosZ;
                if (ddz * ddz + (ddx * ddx + ddy * ddy) < lbl_803E051C)
                {
                    stack[count++] = i;
                    for (j = i; j < (int)lbl_803DD410; j++)
                    {
                        if (filter == lbl_8039C458[j].entry->group)
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
            cp = lbl_8039C458[cur].entry;
        }
        else
        {
            state->startCheckpointId = -1;
            return;
        }
        if (cp == NULL)
        {
            return;
        }
        for (k = 0; k < 2; k++)
        {
            n = Checkpoint_find(cp->forwardLinkIds[k], &slot);
            if (n != NULL)
            {
                cos1 = mathSinf((lbl_803E04D8 * (f32)(cp->heading << 8)) / lbl_803E04DC);
                sin1 = mathCosf((lbl_803E04D8 * (f32)(cp->heading << 8)) / lbl_803E04DC);
                offs1 = -(cp->posX * cos1 + cp->posZ * sin1);
                cos2 = mathSinf((lbl_803E04D8 * (f32)(n->heading << 8)) / lbl_803E04DC);
                sin2 = mathCosf((lbl_803E04D8 * (f32)(n->heading << 8)) / lbl_803E04DC);
                offs2 = -(n->posX * cos2 + n->posZ * sin2);
                dist1 = offs1 + (cos1 * obj->anim.localPosX + sin1 * obj->anim.localPosZ);
                dist2 = offs2 + (cos2 * obj->anim.localPosX + sin2 * obj->anim.localPosZ);
                distA = offs1 + (cos1 * n->posX + sin1 * n->posZ);
                distB = offs2 + (cos2 * cp->posX + sin2 * cp->posZ);
                if (((distA <= lbl_803E04E8 && dist1 <= lbl_803E04E8) || (distA > lbl_803E04E8 && dist1 > lbl_803E04E8))
                    &&
                    ((distB <= lbl_803E04E8 && dist2 <= lbl_803E04E8) || (distB > lbl_803E04E8 && dist2 >
                        lbl_803E04E8)))
                {
                    dx = cp->posX - n->posX;
                    dy = cp->posY - n->posY;
                    dz = cp->posZ - n->posZ;
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
                    b1 = (f32)cp->width;
                    width = frac * ((f32)n->width - b1) + b1;
                    px = -(dx * frac - cp->posX);
                    py = -(dy * frac - cp->posY);
                    pz = -(dz * frac - cp->posZ);
                    outY = (obj->anim.localPosY - py) / width;
                    outX = (-(px * nz - pz * nx) + (obj->anim.localPosX * nz - obj->anim.localPosZ * nx)) / width;
                    if (outX < lbl_803E0530 || outX > lbl_803E0534 || outY < lbl_803E0538 || outY > lbl_803E0534)
                    {
                    }
                    else
                    {
                        state->startCheckpointId = cp->checkpointId;
                        state->matchedCheckpointId = cp->checkpointId;
                        state->localX = outX;
                        state->localY = outY;
                        state->pathT = frac;
                        state->group = cp->group;
                        return;
                    }
                }
            }
        }
        if (visited[cur] == 0)
        {
            for (k = 1; k >= 0; k--)
            {
                n = Checkpoint_find(cp->backLinkIds[k], &slot);
                if (n != NULL && visited[slot] == 0 && count < 0x3c)
                {
                    stack[count++] = slot;
                }
                n = Checkpoint_find(cp->forwardLinkIds[k], &slot);
                if (n != NULL && visited[slot] == 0 && count < 0x3c)
                {
                    stack[count++] = slot;
                }
            }
            visited[cur] = 1;
        }
    }
}
