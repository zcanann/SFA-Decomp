#include "main/newshadows.h"
#include "main/game_object.h"
#include "main/objanim_internal.h"

extern float ABS();
extern undefined4 FUN_800033a8();
extern undefined4 FUN_80003494();
extern undefined4 FUN_8000693c();
extern undefined4 FUN_8000694c();
extern undefined4 FUN_80006954();
extern undefined4 FUN_80006974();
extern void* FUN_8000697c();
extern undefined4 FUN_80006984();
extern undefined4 FUN_80006988();
extern void* FUN_800069a8();
extern undefined4 FUN_800069b8();
extern undefined4 FUN_800069bc();
extern undefined4 FUN_800069d4();
extern undefined4 FUN_800069f4();
extern double FUN_800069f8();
extern undefined4 FUN_80006a00();
extern int FUN_800176d0();
extern uint FUN_80017730();
extern u32 randomGetRange(int min, int max);
extern uint FUN_800177bc();
extern undefined4 FUN_80017814();
extern int FUN_80017970();
extern undefined4 FUN_80017a50();
extern int FUN_80017a54();
extern undefined4 FUN_8003b7dc();
extern undefined4 FUN_8003b878();
extern undefined4 FUN_80040cd0();
extern undefined4 FUN_80045be8();
extern undefined4 FUN_80048048();
extern char FUN_80048094();
extern int FUN_800537a0();
extern undefined4 FUN_8005398c();
extern uint FUN_8005d00c();
extern uint FUN_8005d06c();
extern undefined4 FUN_800606a4();
extern undefined4 FUN_800606a8();
extern undefined4 FUN_80060710();
extern ushort FUN_80061198();
extern undefined4 FUN_80064384();
extern undefined4 objAudioFn_8006ef38();
extern undefined4 FUN_8006f788();
extern undefined4 FUN_8006f790();
extern void gxSetZMode_();
extern undefined4 FUN_800709e8();
extern undefined4 FUN_80080f6c();
extern undefined4 FUN_802420b0();
extern undefined4 FUN_802420e0();
extern undefined4 FUN_802475e4();
extern undefined4 FUN_80247618();
extern undefined4 FUN_80247a48();
extern undefined4 FUN_80247a7c();
extern undefined4 FUN_80247b70();
extern undefined4 FUN_80247dfc();
extern undefined4 FUN_80247edc();
extern undefined4 FUN_80247ef8();
extern double SeekTwiceBeforeRead();
extern double FUN_80247f90();
extern undefined4 FUN_80258c24();
extern undefined4 FUN_80258c48();
extern undefined4 FUN_80259400();
extern undefined4 FUN_80259504();
extern undefined4 FUN_80259858();
extern undefined4 FUN_80259c0c();
extern undefined4 FUN_8025aeac();
extern undefined4 FUN_8025b054();
extern undefined4 FUN_8025b210();
extern undefined4 FUN_8025b280();
extern undefined4 FUN_8025d6ac();
extern undefined4 FUN_8025da64();
extern undefined4 FUN_8025da88();
extern undefined4 FUN_8028680c();
extern undefined4 FUN_80286820();
extern undefined8 FUN_80286834();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286858();
extern undefined4 FUN_8028686c();
extern undefined4 FUN_80286880();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_802947f8();
extern undefined4 FUN_802949e8();
extern undefined4 SQRT();

extern undefined2 DAT_8030f470;
extern undefined2 DAT_8030f484;
extern undefined2 DAT_8030f498;
extern undefined2 DAT_8030f4ac;
extern undefined2 DAT_8030f4c0;
extern undefined2 DAT_8030f4d4;
extern undefined2 DAT_8030f4e8;
extern undefined2 DAT_8030f4fc;
extern undefined2 DAT_8030f510;
extern undefined4 DAT_8030f524;
extern undefined DAT_8038eba8;
extern undefined4 DAT_8038ebb8;
extern undefined4 DAT_8038ee3c;
extern undefined4 DAT_8038ee40;
extern undefined4 DAT_8038ee44;
extern undefined4 DAT_8038ee48;
extern int DAT_8038eec8;
extern int DAT_8038ef08;
extern undefined4 DAT_8038ef0c;
extern undefined4 DAT_8038ef10;
extern undefined4 DAT_8038fd18;
extern undefined4 DAT_8038fd48;
extern undefined4 DAT_8038fd50;
extern undefined4 DAT_8038fd54;
extern undefined4 DAT_8038fd74;
extern undefined4 DAT_8038fd78;
extern undefined4 DAT_8038fd7c;
extern undefined4 DAT_8038fd7d;
extern int DAT_803925b8;
extern undefined4 DAT_803925bc;
extern undefined4 DAT_803925c0;
extern undefined4 DAT_803925c4;
extern undefined4 DAT_803925c8;
extern undefined4 DAT_803925cc;
extern undefined4 DAT_803925d0;
extern undefined4 DAT_803925d4;
extern undefined4 DAT_803925d8;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dc2c8;
extern undefined4 DAT_803dd970;
extern undefined4 DAT_803ddbf8;
extern undefined4 DAT_803ddbfc;
extern undefined4 DAT_803ddc00;
extern undefined4 DAT_803ddc04;
extern undefined4 DAT_803ddc08;
extern undefined4 DAT_803ddc0c;
extern undefined4 DAT_803ddc10;
extern undefined4 DAT_803ddc14;
extern undefined4 DAT_803ddc18;
extern undefined4 DAT_803ddc1c;
extern undefined4 DAT_803ddc20;
extern undefined4 DAT_803ddc30;
extern undefined4 DAT_803ddc34;
extern undefined4 DAT_803ddc38;
extern undefined4 DAT_803ddc3c;
extern undefined4 DAT_803ddc40;
extern undefined4 DAT_803ddc44;
extern undefined4 DAT_803ddc48;
extern undefined4 DAT_803ddc4c;
extern undefined4 DAT_803ddc50;
extern undefined4 DAT_803ddc54;
extern undefined4 DAT_803ddc58;
extern undefined4 DAT_803ddc5c;
extern undefined4 DAT_803ddc60;
extern undefined4 DAT_803ddc64;
extern undefined4 DAT_803ddc68;
extern f64 DOUBLE_803df9d8;
extern f64 DOUBLE_803df9e0;
extern f64 DOUBLE_803dfa08;
extern f64 DOUBLE_803dfa48;
extern f32 lbl_803DC074;
extern f32 lbl_803DC2D0;
extern f32 lbl_803DDA58;
extern f32 lbl_803DDA5C;
extern f32 lbl_803DDB4C;
extern f32 lbl_803DDB50;
extern f32 lbl_803DDC24;
extern f32 lbl_803DDC28;
extern f32 lbl_803DDC2C;
extern f32 lbl_803DF988;
extern f32 lbl_803DF98C;
extern f32 lbl_803DF990;
extern f32 lbl_803DF994;
extern f32 lbl_803DF998;
extern f32 lbl_803DF99C;
extern f32 lbl_803DF9A0;
extern f32 lbl_803DF9A4;
extern f32 lbl_803DF9A8;
extern f32 lbl_803DF9AC;
extern f32 lbl_803DF9B0;
extern f32 lbl_803DF9B4;
extern f32 lbl_803DF9B8;
extern f32 lbl_803DF9BC;
extern f32 lbl_803DF9C0;
extern f32 lbl_803DF9C4;
extern f32 lbl_803DF9C8;
extern f32 lbl_803DF9CC;
extern f32 lbl_803DF9D0;
extern f32 lbl_803DF9E8;
extern f32 lbl_803DF9EC;
extern f32 lbl_803DF9F0;
extern f32 lbl_803DF9F4;
extern f32 lbl_803DF9F8;
extern f32 lbl_803DF9FC;
extern f32 lbl_803DFA00;
extern f32 lbl_803DFA10;
extern f32 lbl_803DFA14;
extern f32 lbl_803DFA18;
extern f32 lbl_803DFA1C;
extern f32 lbl_803DFA20;
extern f32 lbl_803DFA2C;
extern f32 lbl_803DFA30;
extern f32 lbl_803DFA34;
extern f32 lbl_803DFA38;
extern f32 lbl_803DFA3C;
extern f32 lbl_803DFA40;
extern f32 lbl_803DFA50;
extern f32 lbl_803DFA54;
extern f32 lbl_803DFA58;
extern f32 lbl_803DFA5C;
extern f32 lbl_803DFA60;
extern f32 lbl_803DFA6C;
extern f32 lbl_803DFA70;
extern f32 lbl_803DFA74;
extern f32 lbl_803DFA78;
extern f32 lbl_803DFA7C;
extern f32 lbl_803DFA84;
extern f32 lbl_803DFA88;
extern f32 lbl_803DFA8C;
extern f32 lbl_803DFA90;
extern f32 lbl_803DFA94;
extern f32 lbl_803DFA98;
extern f32 lbl_803DFA9C;

/*
 * --INFO--
 *
 * Function: FUN_8006a028
 * EN v1.0 Address: 0x8006A028
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8006A1A4
 * EN v1.1 Size: 5424b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void DCFlushRange(void* addr, u32 nBytes);

/* Box-blur a square tiled texture in place (8-bit and 16-bit texel paths). */
void fn_8006A028(u8* texData, int size, int window, u32 fill)
{
    u8 blurred[128];
    u8 row[152];
    u8* data;

    data = texData + 0x60;
    if (window % 8 == 0)
    {
        int nfill = window >> 3;
        u32 y;

        for (y = 0; y < size; y++)
        {
            u32* tile = (u32*)(data + ((y & 3) * 8 + (y >> 2) * 4 * size));
            u32* dst = (u32*)row;
            u32* src;
            u32 sum;
            u32 i;
            u32 x;
            int k;

            for (i = 0; i < nfill; i++)
            {
                *dst = fill;
                dst++;
            }
            src = tile;
            for (x = 0; x < size; x += 8)
            {
                dst[0] = src[0];
                dst[1] = src[1];
                dst += 2;
                src += 8;
            }
            for (i = 0; i < nfill; i++)
            {
                *dst = fill;
                dst++;
            }
            sum = 0;
            for (k = 0; k < window; k++)
            {
                sum += row[k];
            }
            for (k = 0; k < size; k++)
            {
                blurred[k] = sum / window;
                sum = sum - row[k] + (row + window)[k];
            }
            src = (u32*)blurred;
            for (x = 0; x < size; x += 8)
            {
                tile[0] = src[0];
                tile[1] = src[1];
                src += 2;
                tile += 8;
            }
        }
        {
            u32 x;

            for (x = 0; x < size; x++)
            {
                u8* col = data + ((x & 7) + (x >> 3) * 32);
                u32* dst = (u32*)row;
                u8* gp;
                u8* bp;
                u32 sum;
                u32 i;
                u32 yy;
                int k;

                for (i = 0; i < nfill; i++)
                {
                    *dst = fill;
                    dst++;
                }
                gp = col;
                bp = row + (window >> 1);
                for (yy = 0; yy < size; yy += 4)
                {
                    bp[0] = gp[0];
                    bp[1] = gp[8];
                    bp[2] = gp[16];
                    bp[3] = gp[24];
                    bp += 4;
                    gp += (size >> 3) * 32;
                }
                dst = (u32*)(row + (size + (window >> 1)));
                for (i = 0; i < nfill; i++)
                {
                    *dst = fill;
                    dst++;
                }
                sum = 0;
                for (k = 0; k < window; k++)
                {
                    sum += row[k];
                }
                for (k = 0; k < size; k++)
                {
                    blurred[k] = sum / window;
                    sum = sum - row[k] + (row + window)[k];
                }
                bp = blurred;
                for (yy = 0; yy < size; yy += 4)
                {
                    col[0] = bp[0];
                    col[8] = bp[1];
                    col[16] = bp[2];
                    col[24] = bp[3];
                    bp += 4;
                    col += (size >> 3) * 32;
                }
            }
        }
    }
    else
    {
        int nfill = window >> 2;
        u16 fillhw = fill;
        u32 y;

        for (y = 0; y < size; y++)
        {
            u16* tile = (u16*)(data + ((y & 3) * 8 + (y >> 2) * 4 * size));
            u16* dst = (u16*)row;
            u16* src;
            u32 sum;
            u32 i;
            u32 x;
            int k;

            for (i = 0; i < nfill; i++)
            {
                *dst = fillhw;
                dst++;
            }
            src = tile;
            for (x = 0; x < size; x += 8)
            {
                dst[0] = src[0];
                dst[1] = src[1];
                dst[2] = src[2];
                dst[3] = src[3];
                dst += 4;
                src += 16;
            }
            for (i = 0; i < nfill; i++)
            {
                *dst = fillhw;
                dst++;
            }
            sum = 0;
            for (k = 0; k < window; k++)
            {
                sum += row[k];
            }
            for (k = 0; k < size; k++)
            {
                blurred[k] = sum / window;
                sum = sum - row[k] + (row + window)[k];
            }
            src = (u16*)blurred;
            for (x = 0; x < size; x += 8)
            {
                tile[0] = src[0];
                tile[1] = src[1];
                tile[2] = src[2];
                tile[3] = src[3];
                src += 4;
                tile += 16;
            }
        }
        {
            u32 x;

            for (x = 0; x < size; x++)
            {
                u8* col = data + ((x & 7) + (x >> 3) * 32);
                u16* dst = (u16*)row;
                u8* gp;
                u8* bp;
                u32 sum;
                u32 i;
                u32 yy;
                int k;

                for (i = 0; i < nfill; i++)
                {
                    *dst = fillhw;
                    dst++;
                }
                gp = col;
                bp = row + (window >> 1);
                for (yy = 0; yy < size; yy += 4)
                {
                    bp[0] = gp[0];
                    bp[1] = gp[8];
                    bp[2] = gp[16];
                    bp[3] = gp[24];
                    bp += 4;
                    gp += (size >> 3) * 32;
                }
                dst = (u16*)(row + (size + (window >> 1)));
                for (i = 0; i < nfill; i++)
                {
                    *dst = fillhw;
                    dst++;
                }
                sum = 0;
                for (k = 0; k < window; k++)
                {
                    sum += row[k];
                }
                for (k = 0; k < size; k++)
                {
                    blurred[k] = sum / window;
                    sum = sum - row[k] + (row + window)[k];
                }
                bp = blurred;
                for (yy = 0; yy < size; yy += 4)
                {
                    col[0] = bp[0];
                    col[8] = bp[1];
                    col[16] = bp[2];
                    col[24] = bp[3];
                    bp += 4;
                    col += (size >> 3) * 32;
                }
            }
        }
    }
    DCFlushRange(data, size * size);
}

/*
 * --INFO--
 *
 * Function: FUN_8006a02c
 * EN v1.0 Address: 0x8006A02C
 * EN v1.0 Size: 676b
 * EN v1.1 Address: 0x8006B6D4
 * EN v1.1 Size: 728b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on
void newshadows_captureProjectedShadow(ushort* object)
{
    float fb;
    int val;
    float* ptr;
    double fa;
    double ff;
    double fc;
    double fd;
    double fe;
    float fg;
    float tmp;
    float tmp2;
    float tmp3;
    float tmp4;
    float tmp5;
    float fbuf[15];

    FUN_80017a50(object, fbuf, '\0');
    FUN_8000693c((double)(*(float*)(object + 6) - lbl_803DDA58), (double)*(float*)(object + 8),
                 (double)(*(float*)(object + 10) - lbl_803DDA5C),
                 (double)(lbl_803DF98C * *(float*)(object + 0x54) * *(float*)(object + 4)),
                 &tmp5, &tmp4, &tmp3, &tmp2, &tmp, &fg);
    tmp2 = lbl_803DF994 * tmp2 + lbl_803DF990;
    tmp = lbl_803DF998 * tmp + lbl_803DF990;
    fb = tmp;
    if (tmp < tmp2)
    {
        fb = tmp2;
    }
    fd = (double)(lbl_803DF99C / fb);
    fc = (double)(float)((double)*(float*)(object + 4) * fd);
    fa = -(double)tmp5;
    fe = (double)tmp4;
    FUN_8025da64((double)(float)((double)lbl_803DF994 * fa),
                 (double)(float)((double)lbl_803DF998 * fe), (double)lbl_803DF9A0,
                 (double)lbl_803DF9A4, (double)lbl_803DF9A8, (double)lbl_803DF9AC);
    if (lbl_803DF9A8 <= tmp3)
    {
        **(float**)(object + 0x32) = lbl_803DF9A8;
    }
    else
    {
        ff = (double)*(float*)(object + 4);
        *(float*)(object + 4) = (float)fc;
        FUN_80040cd0(1);
        FUN_8003b878(0, 0, 0, 0, (int)object, 1);
        FUN_80040cd0(0);
        *(float*)(object + 4) = (float)ff;
        val = FUN_80017a54((int)object);
        *(ushort*)(val + 0x18) = *(ushort*)(val + 0x18) & ~0x8;
        gxSetZMode_(1, 3, 1);
        FUN_80259400(0x100, 0xb0, 0x80, 0x80);
        FUN_80259504(0x80, 0x80, 0x2a, 0);
        FUN_80259c0c((&DAT_8038ee3c)[DAT_803ddc0c] + 0x60, 1);
        fn_8006A028((u8*)(&DAT_8038ee3c)[(DAT_803ddc0c + 1) % 3], 0x80, 0x10, 0);
        **(float**)(object + 0x32) = (float)((double)lbl_803DF9AC / fd);
    }
    FUN_80006988();
    fc = (double)lbl_803DF994;
    *(float*)(*(int*)(object + 0x32) + 0x14) = (float)(fc * -fa);
    fa = (double)lbl_803DF998;
    *(float*)(*(int*)(object + 0x32) + 0x18) = (float)(fa * -fe);
    *(float*)(*(int*)(object + 0x32) + 0x14) =
        (float)((double)*(float*)(*(int*)(object + 0x32) + 0x14) + fc);
    *(float*)(*(int*)(object + 0x32) + 0x18) =
        (float)((double)*(float*)(*(int*)(object + 0x32) + 0x18) + fa);
    fb = lbl_803DF99C;
    ptr = *(float**)(object + 0x32);
    ptr[5] = -(lbl_803DF99C * *ptr - ptr[5]);
    ptr = *(float**)(object + 0x32);
    ptr[6] = -(fb * *ptr - ptr[6]);
    return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006a2d0
 * EN v1.0 Address: 0x8006A2D0
 * EN v1.0 Size: 320b
 * EN v1.1 Address: 0x8006B9AC
 * EN v1.1 Size: 304b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void newshadows_sortQueuedShadowCasters(int queueBase, int casterCount)
{
    int val2;
    float fa;
    undefined4 uval;
    undefined4 uval2;
    int val;
    undefined4 uval3;
    int val4;
    undefined4* ptr;
    int val7;
    int val5;
    int val8;
    int val6;
    int val3;

    val2 = (casterCount + -1) / 9 + (casterCount + -1 >> 0x1f);
    for (val = 1; val <= val2 - (val2 >> 0x1f); val = val * 3 + 1)
    {
    }
    for (; 0 < val; val = val / 3)
    {
        val3 = val + 1;
        val7 = val3 * 0xc;
        val5 = queueBase + val7;
        val2 = (casterCount + 1) - val3;
        if (val3 <= casterCount)
        {
            do
            {
                uval3 = *(undefined4*)(val5 + -0xc);
                fa = *(float*)(val5 + -8);
                uval = *(undefined4*)(val5 + -4);
                val4 = queueBase + val7;
                val6 = val3;
                while ((val < val6 &&
                    (val8 = queueBase + (val6 - val) * 0xc, *(float*)(val8 + -8) < fa)))
                {
                    uval2 = *(undefined4*)(val8 + -8);
                    *(undefined4*)(val4 + -0xc) = *(undefined4*)(val8 + -0xc);
                    *(undefined4*)(val4 + -8) = uval2;
                    *(undefined4*)(val4 + -4) = *(undefined4*)(val8 + -4);
                    val4 = val4 + val * -0xc;
                    val6 = val6 - val;
                }
                ptr = (undefined4*)(queueBase + val6 * 0xc + -0xc);
                *ptr = uval3;
                ptr[1] = fa;
                ptr[2] = uval;
                val5 = val5 + 0xc;
                val3 = val3 + 1;
                val7 = val7 + 0xc;
                val2 = val2 + -1;
            }
            while (val2 != 0);
        }
    }
    return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006a410
 * EN v1.0 Address: 0x8006A410
 * EN v1.0 Size: 2448b
 * EN v1.1 Address: 0x8006BADC
 * EN v1.1 Size: 2596b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void newshadows_renderQueuedShadowCasters(void)
{
    undefined2 uval7;
    undefined2 uval8;
    uint uval3;
    int val2;
    undefined2* ptr;
    ushort uval6;
    uint uval5;
    int* ptr5;
    int val3;
    float* ptr6;
    float* ptr3;
    float* ptr2;
    int val;
    uint uval4;
    uint uval;
    char bval2;
    byte bval;
    uint uval2;
    int* ptr4;
    double fc;
    double fg;
    double fa;
    double savedF21;
    double savedF22;
    double savedF23;
    double fb;
    double savedF24;
    double savedF25;
    double fh;
    double savedF26;
    double fa2;
    double savedF27;
    double fb2;
    double savedF28;
    double fd;
    double savedF29;
    double savedF30;
    double fe;
    double savedF31;
    double ff;
    double savedPs21;
    double savedPs22;
    double savedPs23;
    double savedPs24;
    double savedPs25;
    double savedPs26;
    double savedPs27;
    double savedPs28;
    double savedPs29;
    double savedPs30;
    double savedPs31;
    undefined4 convLo;
    undefined4 convLo2;
    float tmp4;
    float tmp13;
    float tmp14;
    float tmp5;
    float tmp8;
    float tmp9;
    float tmp6;
    float tmp10;
    float tmp11;
    float tmp;
    float tmp2;
    float tmp3;
    undefined buf[12];
    undefined buf2[12];
    float fbuf[16];
    float tmp7;
    float tmp15;
    float tmp16;
    float tmp17;
    float tmp18;
    float tmp19;
    float tmp20;
    float tmp21;
    float tmp22;
    float tmp23;
    float tmp24;
    float tmp25;
    float fbuf2[12];
    float fbuf3[24];
    undefined4 tmp26;
    uint convLo3;
    undefined4 tmp27;
    uint convLo4;
    int tmp12;
    float tmp28;
    float fc2;
    float tmp29;
    float fd2;
    float local_88;
    float fe2;
    float local_78;
    float ff2;
    float local_68;
    float fg2;
    float local_58;
    float fh2;
    float local_48;
    float fa3;
    float local_38;
    float fb3;
    float local_28;
    float fc3;
    float local_18;
    float fd3;
    float local_8;
    float fe3;

    local_8 = (float)savedF31;
    fe3 = (float)savedPs31;
    local_18 = (float)savedF30;
    fd3 = (float)savedPs30;
    local_28 = (float)savedF29;
    fc3 = (float)savedPs29;
    local_38 = (float)savedF28;
    fb3 = (float)savedPs28;
    local_48 = (float)savedF27;
    fa3 = (float)savedPs27;
    local_58 = (float)savedF26;
    fh2 = (float)savedPs26;
    local_68 = (float)savedF25;
    fg2 = (float)savedPs25;
    local_78 = (float)savedF24;
    ff2 = (float)savedPs24;
    local_88 = (float)savedF23;
    fe2 = (float)savedPs23;
    tmp29 = (float)savedF22;
    fd2 = (float)savedPs22;
    tmp28 = (float)savedF21;
    fc2 = (float)savedPs21;
    FUN_8028680c();
    if (DAT_803ddbf8 != 0)
    {
        FUN_800069b8();
        newshadows_sortQueuedShadowCasters(-0x7fc710f8, (uint)DAT_803ddbf8);
        FUN_80006954(1);
        ptr = FUN_800069a8();
        fg = FUN_800069f8();
        FUN_80006a00((double)lbl_803DF9B0);
        FUN_800069f4((double)lbl_803DF9AC);
        fb2 = (double)*(float*)(ptr + 6);
        fa2 = (double)*(float*)(ptr + 8);
        fh = (double)*(float*)(ptr + 10);
        tmp12 = (int)(short)ptr[1];
        uval7 = *ptr;
        uval8 = ptr[2];
        ptr[1] = 0;
        tmp6 = lbl_803DF9A8;
        tmp10 = lbl_803DF9AC;
        tmp11 = lbl_803DF9A8;
        FUN_80060710((double)lbl_803DF9B4, &tmp6, fbuf3);
        FUN_800606a4(&convLo2, &convLo);
        bval = 0;
        uval2 = 0;
        ptr4 = &DAT_8038ef08;
        for (bval2 = '\0'; ((int)bval2 < (int)(uint)DAT_803ddbf8 && (bval2 < 100));
             bval2 = bval2 + '\x01')
        {
            val = *ptr4;
            ptr2 = (float*)((GameObject*)val)->anim.modelState;
            FUN_80006954(0);
            uval6 = FUN_80061198(val, (uint)DAT_803dc070);
            FUN_80006954(1);
            if (4 < (uval6 & 0xff))
            {
                if ((((ObjModelState*)ptr2)->flags & 0x20) != 0)
                {
                    FUN_80003494((uint)buf, val + 0xc, 0xc);
                    FUN_80003494((uint)buf2, val + 0x18, 0xc);
                    FUN_80003494(val + 0xc, (uint)(ptr2 + 8), 0xc);
                    FUN_80003494(val + 0x18, (uint)(ptr2 + 8), 0xc);
                }
                uval3 = uval2 & 0xff;
                val2 = uval3 * 0x68;
                ptr3 = (float*)(&DAT_8038fd18 + val2);
                (&DAT_8038fd7c)[val2] = (char)uval6;
                if ((bval < 8) && (*(char*)(ptr4 + 2) != '\0'))
                {
                    if (bval < 3)
                    {
                        uval4 = 0x100;
                        fb = (double)lbl_803DF9B8;
                    }
                    else if (bval < 5)
                    {
                        uval4 = 0x80;
                        fb = (double)lbl_803DF9BC;
                    }
                    else
                    {
                        uval4 = 0x40;
                        fb = (double)lbl_803DF9C0;
                    }
                    uval = uval4;
                    if (bval == 0)
                    {
                        uval = uval4 << 1;
                    }
                    if (*(char*)(ptr4 + 2) == '\x02')
                    {
                        uval = (uint) * (ushort*)(*(int*)(*(int*)&((GameObject*)val)->anim.modelState + 4) + 10);
                        uval4 = uval;
                    }
                    FUN_80080f6c(val, &tmp, &tmp2, &tmp3);
                    tmp5 = -ptr2[5];
                    tmp8 = -ptr2[6];
                    tmp9 = -ptr2[7];
                    fa = FUN_80247f90(&tmp5, &tmp);
                    if ((fa < (double)lbl_803DF9AC) && ((double)lbl_803DF9C4 < fa))
                    {
                        tmp4 = lbl_803DF9C8 * tmp5 + lbl_803DF9CC * tmp;
                        tmp13 = lbl_803DF9C8 * tmp8 + lbl_803DF9CC * tmp2;
                        tmp14 = lbl_803DF9C8 * tmp9 + lbl_803DF9CC * tmp3;
                        fa = SeekTwiceBeforeRead(&tmp4);
                        if ((double)lbl_803DF9A8 < fa)
                        {
                            FUN_80247edc((double)(float)((double)lbl_803DF9AC / fa), &tmp4, &tmp);
                        }
                    }
                    if (lbl_803DF9D0 < tmp2)
                    {
                        tmp2 = lbl_803DF9D0;
                        FUN_80247ef8(&tmp, &tmp);
                    }
                    fd = -(double)tmp;
                    ff = -(double)tmp2;
                    fe = -(double)tmp3;
                    uval5 = FUN_80017730();
                    DAT_803ddc04 = uval5 & 0xffff;
                    uval5 = FUN_80017730();
                    DAT_803ddc08 = (uval5 & 0xffff) - 0x3fc8;
                    ptr[1] = (short)DAT_803ddc08;
                    *ptr = (short)DAT_803ddc04;
                    fa = (double)(float)(fe * fe +
                        (double)(float)(fd * fd + (double)(float)(ff * ff)
                        ));
                    if ((double)lbl_803DF9A8 < fa)
                    {
                        fc = 1.0 / SQRT(fa);
                        fc = DOUBLE_803df9d8 * fc * -(fa * fc * fc - DOUBLE_803df9e0);
                        fc = DOUBLE_803df9d8 * fc * -(fa * fc * fc - DOUBLE_803df9e0);
                        fa = (double)(float)(fa * DOUBLE_803df9d8 * fc *
                            -(fa * fc * fc - DOUBLE_803df9e0));
                    }
                    if ((double)lbl_803DF9A8 < fa)
                    {
                        fa = (double)(float)((double)lbl_803DF9E8 / fa);
                        fd = (double)(float)(fd * fa);
                        ff = (double)(float)(ff * fa);
                        fe = (double)(float)(fe * fa);
                    }
                    *(undefined4*)(ptr + 0x20) = 0;
                    ptr2[5] = -tmp;
                    ptr2[6] = -tmp2;
                    ptr2[7] = -tmp3;
                    FUN_8006f788(uval);
                    ptr5 = (int*)FUN_80017a54(val);
                    val3 = FUN_80017970(ptr5, 0);
                    *(float*)(ptr + 6) = (float)(fd + (double)*(float*)(val3 + 0xc));
                    *(float*)(ptr + 8) = (float)(ff + (double)*(float*)(val3 + 0x1c));
                    *(float*)(ptr + 10) = (float)(fe + (double)*(float*)(val3 + 0x2c));
                    if (*(int*)&((GameObject*)val)->anim.parent == 0)
                    {
                        *(float*)(ptr + 6) = *(float*)(ptr + 6) + lbl_803DDB50;
                        *(float*)(ptr + 10) = *(float*)(ptr + 10) + lbl_803DDB4C;
                    }
                    fa = (double)*ptr2;
                    fd = -fa;
                    if (*(int*)&((GameObject*)val)->anim.parent != 0)
                    {
                        *(float*)(ptr + 6) = *(float*)(ptr + 6) + lbl_803DDA58;
                        *(float*)(ptr + 10) = *(float*)(ptr + 10) + lbl_803DDA5C;
                    }
                    FUN_8025da88(2, 2, uval - 4, uval - 4);
                    fe = (double)lbl_803DF9A8;
                    tmp26 = 0x43300000;
                    tmp27 = 0x43300000;
                    convLo3 = uval;
                    convLo4 = uval;
                    FUN_8025da64(fe, fe,
                                 (double)(float)((double)CONCAT44(0x43300000, uval) - DOUBLE_803dfa08),
                                 (double)(float)((double)CONCAT44(0x43300000, uval) - DOUBLE_803dfa08), fe
                                 , (double)lbl_803DF9AC);
                    FUN_80247dfc(fd, fa, fd, fa, (double)lbl_803DF9AC, (double)lbl_803DF9EC,
                                 fbuf);
                    FUN_8025d6ac(fbuf, 1);
                    FUN_80006984();
                    FUN_80247b70(fa, fd, fd, fa, fb, fb, fb, fb, ptr3);
                    ptr6 = (float*)FUN_80006974();
                    FUN_802475e4(ptr6, (float*)(&DAT_8038fd48 + val2));
                    FUN_80247618(ptr3, ptr6, ptr3);
                    ((ObjModelState*)ptr2)->shadowCastSlot = ptr3;
                    ptr5 = &DAT_803925b8 + bval;
                    (&DAT_8038fd78)[uval3 * 0x1a] = *ptr5;
                    (&DAT_8038fd7d)[val2] = (&DAT_803dc2c8)[bval];
                    FUN_8003b7dc(val);
                    if (*(char*)(ptr4 + 2) == '\x02')
                    {
                        gxSetZMode_(1, 3, 1);
                        fb = (double)lbl_803DF9A8;
                        FUN_80247a7c(fb, fb, fb, (float*)(&DAT_8038fd48 + val2));
                        (&DAT_8038fd50)[uval3 * 0x1a] = lbl_803DF9F0;
                        (&DAT_8038fd54)[uval3 * 0x1a] = lbl_803DF9F4;
                        (&DAT_8038fd74)[uval3 * 0x1a] = lbl_803DF9AC;
                        FUN_80247618((float*)(&DAT_8038fd48 + val2), ptr6, (float*)(&DAT_8038fd48 + val2));
                        FUN_80259400(0, 0, uval, uval);
                        FUN_80259504((ushort)uval, (ushort)uval, 0x11, 0);
                        FUN_80259858('\0', (byte*)(DAT_803dd970 + 0x1a), '\0', (byte*)(DAT_803dd970 + 0x32));
                        FUN_80259c0c(*(int*)(*(int*)&((GameObject*)val)->anim.modelState + 4) + 0x60, 1);
                        FUN_80045be8();
                        (&DAT_8038fd78)[uval3 * 0x1a] = *(undefined4*)(*(int*)&((GameObject*)val)->anim.modelState +
                            4);
                    }
                    else
                    {
                        if (bval == 0)
                        {
                            gxSetZMode_(1, 3, 1);
                            FUN_80259400(0, 0, uval, uval);
                            FUN_80259504((ushort)uval4, (ushort)uval4, 0x20, 1);
                            FUN_80259c0c(*ptr5 + 0x60, 1);
                            (&DAT_8038fd78)[uval3 * 0x1a] = *ptr5;
                        }
                        bval = bval + 1;
                    }
                }
                else
                {
                    (&DAT_8038fd78)[uval3 * 0x1a] = *(undefined4*)(*(int*)&((GameObject*)val)->anim.modelState + 4);
                    fb = (double)((GameObject*)val)->anim.localPosX;
                    fa = (double)((GameObject*)val)->anim.localPosZ;
                    if (*(int*)&((GameObject*)val)->anim.parent == 0)
                    {
                        fb = (double)(float)(fb - (double)lbl_803DDA58);
                        fa = (double)(float)(fa - (double)lbl_803DDA5C);
                    }
                    FUN_80247a48(-fb, -(double)((GameObject*)val)->anim.localPosY, -fa, fbuf2);
                    tmp7 = lbl_803DF9B8 / *ptr2;
                    tmp15 = lbl_803DF9A8;
                    tmp16 = lbl_803DF9A8;
                    tmp17 = lbl_803DF9B8;
                    tmp18 = lbl_803DF9A8;
                    tmp19 = lbl_803DF9A8;
                    tmp21 = lbl_803DF9B8;
                    tmp22 = lbl_803DF9A8;
                    tmp23 = lbl_803DF9A8;
                    tmp24 = lbl_803DF9A8;
                    tmp25 = lbl_803DF9AC;
                    tmp20 = tmp7;
                    FUN_80247618(&tmp7, fbuf2, ptr3);
                    ptr2[5] = tmp6;
                    ptr2[6] = tmp10;
                    ptr2[7] = tmp11;
                    ((ObjModelState*)ptr2)->shadowCastSlot = ptr3;
                }
                uval2 = uval2 + 1;
                if ((((ObjModelState*)ptr2)->flags & 0x20) != 0)
                {
                    FUN_80003494(val + 0xc, (uint)buf, 0xc);
                    FUN_80003494(val + 0x18, (uint)buf2, 0xc);
                }
            }
            ptr4 = ptr4 + 3;
        }
        if (1 < bval)
        {
            gxSetZMode_(1, 3, 1);
            FUN_80259858('\0', (byte*)(DAT_803dd970 + 0x1a), '\0', (byte*)(DAT_803dd970 + 0x32));
            FUN_80259400(0, 0, 0x100, 0x100);
            FUN_80259504(0x100, 0x100, 0x28, 0);
            FUN_80259c0c(DAT_803925bc + 0x60, 1);
            FUN_80258c24();
            FUN_80045be8();
        }
        FUN_8006f790();
        *(float*)(ptr + 6) = (float)fb2;
        *(float*)(ptr + 8) = (float)fa2;
        *(float*)(ptr + 10) = (float)fh;
        ptr[1] = (short)tmp12;
        *ptr = uval7;
        ptr[2] = uval8;
        uval2 = FUN_8005d00c();
        if (uval2 == 0)
        {
            uval2 = FUN_8005d06c();
            if (uval2 == 0)
            {
                FUN_80006954(0);
                FUN_80006a00(fg);
                FUN_800069f4((double)lbl_803DC2D0);
                FUN_8000694c();
            }
            else
            {
                FUN_80006954(0);
                FUN_80006a00(fg);
                FUN_800069f4((double)lbl_803DFA00);
                FUN_8000694c();
            }
        }
        else
        {
            FUN_80006954(0);
            FUN_80006a00(fg);
            uval2 = FUN_8005d06c();
            if (uval2 == 0)
            {
                FUN_800069f4((double)lbl_803DF9FC);
            }
            else
            {
                FUN_800069f4((double)lbl_803DF9F8);
            }
            FUN_8000694c();
        }
        FUN_80006984();
        FUN_800069d4();
        FUN_80006988();
        FUN_800069bc();
    }
    FUN_80286858();
    return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006ada0
 * EN v1.0 Address: 0x8006ADA0
 * EN v1.0 Size: 372b
 * EN v1.1 Address: 0x8006C500
 * EN v1.1 Size: 316b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void newshadows_queueShadowCaster(int object)
{
    ObjAnimComponent* objAnim;
    ObjModelInstance* modelDef;
    float fc;
    float fd;
    float fe;
    int val;
    double fa;
    double fb;

    if (DAT_803ddbf8 < 300)
    {
        objAnim = (ObjAnimComponent*)object;
        modelDef = objAnim->modelInstance;
        (&DAT_8038ef08)[(uint)DAT_803ddbf8 * 3] = object;
        fc = ((GameObject*)object)->anim.worldPosX - *(float*)(DAT_803ddc68 + 0xc);
        fd = ((GameObject*)object)->anim.worldPosY - *(float*)(DAT_803ddc68 + 0x10);
        fe = ((GameObject*)object)->anim.worldPosZ - *(float*)(DAT_803ddc68 + 0x14);
        fb = (double)(fe * fe + fc * fc + fd * fd);
        if ((double)lbl_803DF9A8 < fb)
        {
            fa = 1.0 / SQRT(fb);
            fa = DOUBLE_803df9d8 * fa * -(fb * fa * fa - DOUBLE_803df9e0);
            fa = DOUBLE_803df9d8 * fa * -(fb * fa * fa - DOUBLE_803df9e0);
            fb = (double)(float)(fb * DOUBLE_803df9d8 * fa *
                -(fb * fa * fa - DOUBLE_803df9e0));
        }
        val = (uint)DAT_803ddbf8 * 0xc;
        *(float*)(&DAT_8038ef0c + val) = (float)((double)((GameObject*)object)->anim.modelState->shadowScale / fb);
        if (modelDef->shadowType == 2)
        {
            (&DAT_8038ef10)[val] = 1;
            if ((modelDef->renderFlags & 4) != 0)
            {
                (&DAT_8038ef10)[val] = 2;
                *(float*)(&DAT_8038ef0c + val) = lbl_803DFA10;
            }
        }
        else
        {
            (&DAT_8038ef10)[val] = 0;
        }
        DAT_803ddbf8 = DAT_803ddbf8 + 1;
    }
    return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006af14
 * EN v1.0 Address: 0x8006AF14
 * EN v1.0 Size: 28b
 * EN v1.1 Address: 0x8006C63C
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void newshadows_getShadowTextureTable4x8(int* tableOut, int* columnsOut, int* rowsOut)
{
    *tableOut = (int)&DAT_8038ee48;
    *columnsOut = 4;
    *rowsOut = 8;
    return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006af30
 * EN v1.0 Address: 0x8006AF30
 * EN v1.0 Size: 20b
 * EN v1.1 Address: 0x8006C65C
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void newshadows_getShadowTextureTable16(int* tableOut, int* countOut)
{
    *tableOut = (int)&DAT_8038eec8;
    *countOut = 0x10;
    return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006af44
 * EN v1.0 Address: 0x8006AF44
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8006C674
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_8006af5c
 * EN v1.0 Address: 0x8006AF5C
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8006C68C
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void newshadows_getShadowTexture(int* textureOut)
{
    *textureOut = DAT_803ddc30;
    return;
}


/*
 * --INFO--
 *
 * Function: FUN_8006af74
 * EN v1.0 Address: 0x8006AF74
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8006C6A4
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void newshadows_getBlankShadowTexture(int* textureOut)
{
    *textureOut = DAT_803ddc38;
    return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006af80
 * EN v1.0 Address: 0x8006AF80
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8006C6B0
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void newshadows_getShadowDirectionTexture(int* textureOut)
{
    *textureOut = DAT_803ddc3c;
    return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006af8c
 * EN v1.0 Address: 0x8006AF8C
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8006C6BC
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void newshadows_getSoftShadowTexture(int* textureOut)
{
    *textureOut = DAT_803ddc40;
    return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006af98
 * EN v1.0 Address: 0x8006AF98
 * EN v1.0 Size: 108b
 * EN v1.1 Address: 0x8006C6C8
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_8006b004
 * EN v1.0 Address: 0x8006B004
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8006C734
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void newshadows_getShadowRampTexture(int* textureOut)
{
    *textureOut = DAT_803ddc1c;
    return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006b010
 * EN v1.0 Address: 0x8006B010
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8006C740
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int newshadows_getSmallShadowTexture(void)
{
    return DAT_803ddc54;
}

/*
 * --INFO--
 *
 * Function: FUN_8006b018
 * EN v1.0 Address: 0x8006B018
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8006C748
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void newshadows_getShadowDiskTexture(int* textureOut)
{
    *textureOut = DAT_803ddc58;
    return;
}


/*
 * --INFO--
 *
 * Function: FUN_8006b030
 * EN v1.0 Address: 0x8006B030
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8006C760
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void newshadows_getShadowNoiseTexture(int* textureOut)
{
    *textureOut = DAT_803ddc60;
    return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006b03c
 * EN v1.0 Address: 0x8006B03C
 * EN v1.0 Size: 120b
 * EN v1.1 Address: 0x8006C76C
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on
void FUN_8006b03c(int param_1, undefined4* param_2, undefined4* param_3, int* param_4, int* param_5)
{
    ObjModelState* modelState = ((GameObject*)param_1)->anim.modelState;
    *param_2 = (&DAT_8038ee3c)[(DAT_803ddc0c + 1) % 3];
    *param_3 = *(undefined4*)&modelState->shadowScale;
    *param_4 = (int)modelState->shadowOffsetX;
    *param_5 = (int)modelState->shadowOffsetY;
    return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006b0b4
 * EN v1.0 Address: 0x8006B0B4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8006C7EC
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
double newshadows_getShadowNoiseScale(void)
{
    return (double)lbl_803DDC24;
}

/*
 * --INFO--
 *
 * Function: FUN_8006b0bc
 * EN v1.0 Address: 0x8006B0BC
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x8006C7F4
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_8006b134
 * EN v1.0 Address: 0x8006B134
 * EN v1.0 Size: 76b
 * EN v1.1 Address: 0x8006C86C
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void newshadows_bindShadowRenderTexture(int textureSlot)
{
    if (*(char*)(DAT_803ddbfc + 0x48) == '\0')
    {
        FUN_8025b054((uint*)(DAT_803ddbfc + 0x20), textureSlot);
    }
    else
    {
        FUN_8025aeac((uint*)(DAT_803ddbfc + 0x20), *(uint**)(DAT_803ddbfc + 0x40), textureSlot);
    }
    return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006b180
 * EN v1.0 Address: 0x8006B180
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8006C8B8
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
int newshadows_getShadowRenderTexture(void)
{
    return DAT_803ddbfc;
}


/*
 * --INFO--
 *
 * Function: FUN_8006b190
 * EN v1.0 Address: 0x8006B190
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8006C8C8
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int newshadows_getInverseShadowRampTexture(void)
{
    return DAT_803ddc18;
}

/*
 * --INFO--
 *
 * Function: FUN_8006b198
 * EN v1.0 Address: 0x8006B198
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8006C8D0
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int newshadows_getRadialFalloffTexture(void)
{
    return DAT_803ddc10;
}

/*
 * --INFO--
 *
 * Function: FUN_8006b1a0
 * EN v1.0 Address: 0x8006B1A0
 * EN v1.0 Size: 76b
 * EN v1.1 Address: 0x8006C8D8
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on
void newshadows_bindShadowCaptureTexture(int textureSlot)
{
    if (*(char*)(DAT_803ddc64 + 0x48) == '\0')
    {
        FUN_8025b054((uint*)(DAT_803ddc64 + 0x20), textureSlot);
    }
    else
    {
        FUN_8025aeac((uint*)(DAT_803ddc64 + 0x20), *(uint**)(DAT_803ddc64 + 0x40), textureSlot);
    }
    return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006b1ec
 * EN v1.0 Address: 0x8006B1EC
 * EN v1.0 Size: 136b
 * EN v1.1 Address: 0x8006C924
 * EN v1.1 Size: 136b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void newshadows_refreshShadowCaptureTexture(void)
{
    FUN_800709e8((double)lbl_803DF9A8, (double)lbl_803DF9A8, DAT_803ddbfc, 0xff, 0x40);
    FUN_80259400(0, 0, 0x50, 0x3c);
    FUN_80259504(0x50, 0x3c, 4, 0);
    FUN_80259c0c(DAT_803ddc64 + 0x60, 1);
    if (*(char*)(DAT_803ddc64 + 0x48) != '\0')
    {
        FUN_8025b280(DAT_803ddc64 + 0x20, *(uint**)(DAT_803ddc64 + 0x40));
    }
    return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006b274
 * EN v1.0 Address: 0x8006B274
 * EN v1.0 Size: 236b
 * EN v1.1 Address: 0x8006C9AC
 * EN v1.1 Size: 236b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void newshadows_flushShadowRenderTargets(void)
{
    FUN_80259400(0, 0, 0x280, 0x1e0);
    FUN_80259504(0x140, 0xf0, 4, 1);
    FUN_80259c0c(DAT_803ddbfc + 0x60, 0);
    FUN_80259400(0, 0, 0x280, 0x1e0);
    FUN_80259504(0x140, 0xf0, 0x11, 1);
    FUN_80259c0c(DAT_803ddc5c + 0x60, 0);
    if (*(char*)(DAT_803ddbfc + 0x48) != '\0')
    {
        FUN_8025b280(DAT_803ddbfc + 0x20, *(uint**)(DAT_803ddbfc + 0x40));
    }
    if (*(char*)(DAT_803ddc5c + 0x48) != '\0')
    {
        FUN_8025b280(DAT_803ddc5c + 0x20, *(uint**)(DAT_803ddc5c + 0x40));
    }
    if ((*(char*)(DAT_803ddbfc + 0x48) == '\0') || (*(char*)(DAT_803ddc5c + 0x48) == '\0'))
    {
        FUN_8025b210();
    }
    FUN_80258c24();
    return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006b360
 * EN v1.0 Address: 0x8006B360
 * EN v1.0 Size: 388b
 * EN v1.1 Address: 0x8006CA98
 * EN v1.1 Size: 416b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void newshadows_updateFrameState(void)
{
    uint uval;
    int val;
    char bval;
    undefined* ptr;
    double fa;
    double savedF31;
    double fb;
    double savedPs31;
    float tmp;
    float tmp2;
    undefined8 tmp3;
    float tmp4;
    float fc;

    tmp4 = (float)savedF31;
    fc = (float)savedPs31;
    val = FUN_800176d0();
    if (val == 0)
    {
        lbl_803DDC2C = lbl_803DFA14 * lbl_803DC074 + lbl_803DDC2C;
        lbl_803DDC28 = lbl_803DFA18 * lbl_803DC074 + lbl_803DDC28;
        if (lbl_803DFA1C < lbl_803DDC2C)
        {
            lbl_803DDC2C = lbl_803DDC2C - lbl_803DFA1C;
        }
        if (lbl_803DFA1C < lbl_803DDC28)
        {
            lbl_803DDC28 = lbl_803DDC28 - lbl_803DFA1C;
        }
    }
    DAT_803ddbf8 = 0;
    DAT_803ddc68 = (int)FUN_800069a8();
    DAT_803ddc20 = DAT_803ddc20 + (ushort)DAT_803dc070 * 0x28a;
    tmp3 = CONCAT44(0x43300000, (uint)DAT_803ddc20);
    fa = (double)FUN_802947f8();
    lbl_803DDC24 = (float)((double)lbl_803DFA20 * fa);
    FUN_800606a8();
    DAT_803ddc0c = (char)(DAT_803ddc0c + 1) + (char)((DAT_803ddc0c + 1) / 3) * -3;
    bval = FUN_80048094();
    if (bval != '\0')
    {
        ptr = FUN_8000697c();
        fb = (double)*(float*)(ptr + 0x1c);
        FUN_80048048(&tmp2, &tmp);
        fa = (double)tmp2;
        if (fb < fa)
        {
            if ((double)tmp < fb)
            {
                uval = (uint)((lbl_803DF99C * (float)(fa - fb)) / (float)(fa - (double)tmp));
                tmp3 = (longlong)(int)
                uval;
            }
            else
            {
                uval = 0x40;
            }
        }
        else
        {
            uval = 0;
        }
        if ((uval & 0xff) != (uint)DAT_803ddc00)
        {
            FUN_80064384(uval & 0xff);
        }
    }
    return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006b4e4
 * EN v1.0 Address: 0x8006B4E4
 * EN v1.0 Size: 20b
 * EN v1.1 Address: 0x8006CC38
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void newshadows_getShadowNoiseScroll(float* xOffsetOut, float* yOffsetOut)
{
    *xOffsetOut = lbl_803DDC2C;
    *yOffsetOut = lbl_803DDC28;
    return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006b4f8
 * EN v1.0 Address: 0x8006B4F8
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x8006CC4C
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_8006b540
 * EN v1.0 Address: 0x8006B540
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x8006CCA0
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void newshadows_freeShadowDirectionTexture(void)
{
    FUN_80017814(DAT_803ddc3c);
    DAT_803ddc3c = 0;
    return;
}

/*
 * --INFO--
 *
 * Function: FUN_8006b56c
 * EN v1.0 Address: 0x8006B56C
 * EN v1.0 Size: 696b
 * EN v1.1 Address: 0x8006CCCC
 * EN v1.1 Size: 464b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on
void newshadows_buildShadowDirectionTexture(void)
{
    float fc;
    float ff;
    float fg;
    float fh;
    double fa2;
    uint uval;
    uint uval2;
    int val;
    double fd;
    double fe;
    double fa;
    double fb2;
    double fc2;
    double fb;
    undefined8 tmp;

    DAT_803ddc3c = FUN_800537a0(0x100, 0x100, 3, '\0', 0, 0, 0, 1, 1);
    fa2 = DOUBLE_803dfa48;
    fh = lbl_803DFA40;
    fg = lbl_803DFA3C;
    ff = lbl_803DFA2C;
    uval = 0;
    fc2 = (double)lbl_803DF9A8;
    fb2 = (double)lbl_803DFA38;
    do
    {
        uval2 = 0;
        tmp = (double)CONCAT44(0x43300000, uval ^ 0x80000000);
        fd = (double)((float)(tmp - fa2) - ff);
        val = 0x100;
        do
        {
            tmp = (double)CONCAT44(0x43300000, uval2 ^ 0x80000000);
            fe = (double)((float)(tmp - fa2) - ff);
            fb = (double)(float)(fd * fd + (double)(float)(fe * fe));
            if (fc2 < fb)
            {
                fa = 1.0 / SQRT(fb);
                fa = DOUBLE_803df9d8 * fa * -(fb * fa * fa - DOUBLE_803df9e0);
                fa = DOUBLE_803df9d8 * fa * -(fb * fa * fa - DOUBLE_803df9e0);
                fb = (double)(float)(fb * DOUBLE_803df9d8 * fa *
                    -(fb * fa * fa - DOUBLE_803df9e0));
            }
            fc = lbl_803DF9A8;
            if (fb <= fb2)
            {
                fc = lbl_803DF9B4 * -(float)((double)lbl_803DF9C8 * fb - (double)lbl_803DFA30)
                    * lbl_803DFA34;
            }
            *(ushort*)
                (DAT_803ddc3c + (uval & 3) * 2 + ((int)uval >> 2) * 0x20 + (uval2 & 3) * 8 +
                    ((int)uval2 >> 2) * 0x800 + 0x60) =
                (ushort)(int)(fh * (float)(fe / fb) * fc + fg) |
                (ushort)(((int)(fh * (float)(fd / fb) * fc + fg) & 0xffffU) << 8);
            uval2 = uval2 + 1;
            val = val + -1;
        }
        while (val != 0);
        uval = uval + 1;
    }
    while ((int)uval < 0x100);
    FUN_802420e0(DAT_803ddc3c + 0x60, *(int*)(DAT_803ddc3c + 0x44));
    return;
}


/*
 * --INFO--
 *
 * Function: FUN_8006dca8
 * EN v1.0 Address: 0x8006DCA8
 * EN v1.0 Size: 148b
 * EN v1.1 Address: 0x8006EF48
 * EN v1.1 Size: 364b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8006dca8(undefined8 param_1, double param_2, undefined4 param_3, undefined4 param_4,
                  uint param_5, int param_6, int param_7)
{
    int iVar1;
    uint uVar2;
    int iVar3;
    undefined8 extraout_f1;
    undefined8 uVar4;
    undefined8 uVar5;
    undefined auStack_48[19];
    undefined auStack_35[8];
    char local_2d;

    uVar5 = FUN_80286840();
    iVar1 = (int)uVar5;
    uVar4 = extraout_f1;
    FUN_800033a8((int)auStack_48, 0, 0x1c);
    uVar2 = 0;
    iVar3 = 8;
    do
    {
        if ((iVar1 >> (uVar2 & 0x3f) & 1U) != 0)
        {
            auStack_35[local_2d] = (char)uVar2;
            local_2d = local_2d + '\x01';
        }
        if ((iVar1 >> (uVar2 + 1 & 0x3f) & 1U) != 0)
        {
            auStack_35[local_2d] = (char)(uVar2 + 1);
            local_2d = local_2d + '\x01';
        }
        if ((iVar1 >> (uVar2 + 2 & 0x3f) & 1U) != 0)
        {
            auStack_35[local_2d] = (char)(uVar2 + 2);
            local_2d = local_2d + '\x01';
        }
        if ((iVar1 >> (uVar2 + 3 & 0x3f) & 1U) != 0)
        {
            auStack_35[local_2d] = (char)(uVar2 + 3);
            local_2d = local_2d + '\x01';
        }
        uVar2 = uVar2 + 4;
        iVar3 = iVar3 + -1;
    }
    while (iVar3 != 0);
    objAudioFn_8006ef38(uVar4, param_2, (int)((ulonglong)uVar5 >> 0x20), auStack_48, param_5, param_6, param_7);
    FUN_8028688c();
    return;
}

/* sda21 accessors. */
extern u32 lbl_803DCFD4;
extern char* lbl_803DCF7C;
extern u32 lbl_803DCF94;
extern u32 lbl_803DCF98;
extern u32 lbl_803DCF90;
u32 textureFn_8006c5c4(void) { return lbl_803DCFD4; }
u32 getLastRenderedFrame(void) { return (u32)lbl_803DCF7C; }
u32 getTextureFn_8006c744(void) { return lbl_803DCF94; }
u32 fn_8006C74C(void) { return lbl_803DCF98; }
u32 fn_8006C754(void) { return lbl_803DCF90; }

/* Pattern wrappers. */
extern u32 lbl_803DCFC4;
extern u32 lbl_803DCFC8;
extern u32 lbl_803DCFB0;
extern u32 lbl_803DCFB4;
extern u32 lbl_803DCFB8;
extern u32 lbl_803DCFBC;
extern u32 lbl_803DCFC0;
extern u32 lbl_803DCF9C;
extern u32 lbl_803DCFD8;
extern u32 lbl_803DCFDC;
extern u32 lbl_803DCFE0;
void fn_8006C4F8(u32* p) { *p = lbl_803DCFC4; }
void fn_8006C504(u32* p) { *p = lbl_803DCFC8; }
void fn_8006C510(u32* p) { *p = lbl_803DCFB0; }
void fn_8006C51C(u32* p) { *p = lbl_803DCFB4; }
void fn_8006C528(u32* p) { *p = lbl_803DCFB8; }
void fn_8006C534(u32* p) { *p = lbl_803DCFBC; }
void fn_8006C540(u32* p) { *p = lbl_803DCFC0; }
void fn_8006C5B8(u32* p) { *p = lbl_803DCF9C; }
void fn_8006C5CC(u32* p) { *p = lbl_803DCFD8; }
void getReflectionTexture2(u32* p) { *p = lbl_803DCFDC; }
void getTextureFn_8006c5e4(u32* p) { *p = lbl_803DCFE0; }

/* *p1 = lbl1; *p2 = lbl2; (f32) */
extern f32 lbl_803DCFAC;
extern f32 lbl_803DCFA8;

void newshadows_getReflectionScrollOffsets(f32* p1, f32* p2)
{
    *p1 = lbl_803DCFAC;
    *p2 = lbl_803DCFA8;
}

/* misc 8b leaves */
extern f32 lbl_803DCFA4;
f32 fn_8006C670(void) { return lbl_803DCFA4; }

/* fn_X(lbl); lbl = 0; */
extern void mm_free(u32);

void fn_8006CB24(void)
{
    mm_free(lbl_803DCFBC);
    lbl_803DCFBC = 0;
}

/* Three-out info getter:  *p1 = &lbl; *p2 = 4; *p3 = 8; */
extern u8 lbl_8038E1E8[0x80];
#pragma scheduling off
#pragma peephole off
void fn_8006C4C0(int* p1, int* p2, int* p3)
{
    *p1 = (int)lbl_8038E1E8;
    *p2 = 4;
    *p3 = 8;
}

/* Two-out info getter:  *p1 = &lbl; *p2 = 0x10; */
extern u8 lbl_8038E268[0x40];

void textureFn_8006c4e0(int* p1, int* p2)
{
    *p1 = (int)lbl_8038E268;
    *p2 = 0x10;
}

/* Trivial GXLoadTexObj wrapper at offset 0x20 of sda21 pointer. */
extern u32 lbl_803DCFD0;
extern void GXLoadTexObj(void* obj, int id);
extern void GXLoadTexObjPreLoaded(void* obj, void* region, int id);

void fn_8006C678(int id)
{
    GXLoadTexObj((char*)lbl_803DCFD0 + 0x20, id);
}

/* PreLoaded-or-direct wrapper based on byte 0x48 of sda21 pointer.  Variant A. */
extern u32 lbl_803DCFCC;

void fn_8006C6A4(int id)
{
    register int idCopy = id;
    char* p = (char*)lbl_803DCFCC;
    if (*(u8*)(p + 0x48) != 0)
    {
        GXLoadTexObjPreLoaded(p + 0x20, *(void**)(p + 0x40), idCopy);
    }
    else
    {
        GXLoadTexObj(p + 0x20, idCopy);
    }
}

/* PreLoaded-or-direct wrapper using lbl_803DCF7C as base. */
void selectReflectionTexture(int id)
{
    register int idCopy = id;
    char* p = (char*)lbl_803DCF7C;
    if (*(u8*)(p + 0x48) != 0)
    {
        GXLoadTexObjPreLoaded(p + 0x20, *(void**)(p + 0x40), idCopy);
    }
    else
    {
        GXLoadTexObj(p + 0x20, idCopy);
    }
}

/* PreLoaded-or-direct wrapper using lbl_803DCFE4 as base. */
extern u32 lbl_803DCFE4;

void textureFn_8006c75c(int id)
{
    register int idCopy = id;
    char* p = (char*)lbl_803DCFE4;
    if (*(u8*)(p + 0x48) != 0)
    {
        GXLoadTexObjPreLoaded(p + 0x20, *(void**)(p + 0x40), idCopy);
    }
    else
    {
        GXLoadTexObj(p + 0x20, idCopy);
    }
}

typedef struct NewShadowEntry
{
    u8 pad00[0x10];
    u8 isActive;
    u8 pad11[0x3];
} NewShadowEntry;

/* Linear search by pointer identity through the shadow entry table.
 * Clears the active flag when the entry matches the needle. */
extern NewShadowEntry lbl_8038DF48[0x25];

void findSomething(void* needle)
{
    int i;
    NewShadowEntry* entry;
    for (i = 0, entry = lbl_8038DF48; i < 0x25; entry++, ++i)
    {
        if (entry->isActive != 0 && (void*)entry == needle)
        {
            lbl_8038DF48[i].isActive = 0;
            return;
        }
    }
}

/* Cycles a 3-element table, then samples 3 fields from obj->0x64 ptr block. */
extern u8 lbl_803DCF8C;
extern u32 lbl_8038E1DC[3];

void objShadowFn_8006c5f0(int obj, u32* outTable, f32* outF, int* outX, int* outY)
{
    int idx = (lbl_803DCF8C + 1) % 3;
    ObjModelState* modelState;
    *outTable = lbl_8038E1DC[idx];
    modelState = ((GameObject*)obj)->anim.modelState;
    *outF = modelState->shadowScale;
    *outX = (int)modelState->shadowOffsetX;
    *outY = (int)modelState->shadowOffsetY;
}

/* Allocate a 512x512 texture (1bpp?), set field, flush. */
extern void* textureAlloc(int w, int h, int p3, int p4, int p5, int p6, int p7, int p8, int p9);

void* textureAlloc512(void)
{
    void* tex = textureAlloc(0x200, 0x200, 1, 0, 0, 0, 0, 0, 0);
    *(s16*)((char*)tex + 0xe) = 1;
    DCFlushRange((char*)tex + 0x60, *(u32*)((char*)tex + 0x44));
    return tex;
}

/* Draw the reflection texture and copy to the reflection2 region. */
extern f32 lbl_803DED28;
extern void drawTexture(void* p, f32 f1, f32 f2, int a, int b);
extern void GXSetTexCopySrc(u16 left, u16 top, u16 wd, u16 ht);
extern void GXSetTexCopyDst(u16 wd, u16 ht, int fmt, u8 mipmap);
extern void GXCopyTex(void* dest, u8 clear);
extern void GXPreLoadEntireTexture(void* obj, void* region);

void drawReflectionTexture(void)
{
    void* texture;
    f32 scale = lbl_803DED28;
    texture = lbl_803DCF7C;
    drawTexture(texture, scale, scale, 0xff, 0x40);
    GXSetTexCopySrc(0, 0, 0x50, 0x3c);
    GXSetTexCopyDst(0x50, 0x3c, 4, 0);
    GXCopyTex((char*)lbl_803DCFE4 + 0x60, 1);
    if (*(u8*)(lbl_803DCFE4 + 0x48) != 0)
    {
        GXPreLoadEntireTexture((char*)lbl_803DCFE4 + 0x20, *(void**)(lbl_803DCFE4 + 0x40));
    }
}

/* Copy the frame buffer into both reflection textures, optionally preload. */
extern void GXInvalidateTexAll(void);
extern void GXPixModeSync(void);

void updateReflectionTextures(void)
{
    GXSetTexCopySrc(0, 0, 0x280, 0x1e0);
    GXSetTexCopyDst(0x140, 0xf0, 4, 1);
    GXCopyTex((char*)lbl_803DCF7C + 0x60, 0);
    GXSetTexCopySrc(0, 0, 0x280, 0x1e0);
    GXSetTexCopyDst(0x140, 0xf0, 0x11, 1);
    GXCopyTex((char*)lbl_803DCFDC + 0x60, 0);
    if (*(u8*)(lbl_803DCF7C + 0x48) != 0)
    {
        GXPreLoadEntireTexture((char*)lbl_803DCF7C + 0x20, *(void**)(lbl_803DCF7C + 0x40));
    }
    if (*(u8*)(lbl_803DCFDC + 0x48) != 0)
    {
        GXPreLoadEntireTexture((char*)lbl_803DCFDC + 0x20, *(void**)(lbl_803DCFDC + 0x40));
    }
    if (*(u8*)(lbl_803DCF7C + 0x48) == 0 || *(u8*)(lbl_803DCFDC + 0x48) == 0)
    {
        GXInvalidateTexAll();
    }
    GXPixModeSync();
}

typedef struct
{
    int id;
    f32 dist;
    int flags;
} ShadowSortEntry;

#pragma dont_inline on
void fn_8006B830(ShadowSortEntry* arr, int count)
{
    int gap = 1;
    int i, j;
    ShadowSortEntry tmp;
    int limit = (count - 1) / 9;
    while (gap <= limit)
        gap = gap * 3 + 1;
    while (gap > 0)
    {
        for (i = gap + 1; i <= count; i++)
        {
            tmp = arr[i - 1];
            j = i;
            while (j > gap && arr[j - gap - 1].dist < tmp.dist)
            {
                arr[j - 1] = arr[j - gap - 1];
                j -= gap;
            }
            arr[j - 1] = tmp;
        }
        gap /= 3;
    }
}
#pragma dont_inline reset

extern u8 lbl_8030E8B0[];

u16 audioPickSoundEffect_8006ed24(s8 a, u8 b)
{
    u8* base = lbl_8030E8B0;
    int idx = (u8)a;
    u8 v;
    if (idx < 0 || idx >= 0x23) v = 0;
    else v = base[idx + 0xb4];
    switch ((u8)b)
    {
    case 1: break;
    case 3: base += 0x14;
        break;
    case 4: base += 0x3c;
        break;
    case 5: base += 0x64;
        break;
    case 6: base += 0x50;
        break;
    case 8: base += 0x78;
        break;
    case 0xa: base += 0x8c;
        break;
    case 9: base += 0xa0;
        break;
    default: base += 0x28;
        break;
    }
    return *(u16*)(base + v * 2);
}

extern u8 lbl_803DCF78;
extern int* lbl_803DCFE8;
extern char lbl_8038E2A8[];
extern f32 Ydchuff_803DED80[];

extern inline float sqrtf(float x)
{
    static const double _half = .5;
    static const double _three = 3.0;
    volatile float y;
    if (x > 0.0f)
    {
        double guess = __frsqrte((double)x);
        guess = _half * guess * (_three - guess * guess * x);
        guess = _half * guess * (_three - guess * guess * x);
        guess = _half * guess * (_three - guess * guess * x);
        y = (float)(x * guess);
        return y;
    }
    return x;
}

extern f32 CPUFifo_803DED38, GPFifo_803DED3C, __GXCurrentThread_803DED40, lbl_803DED2C;
extern f32 Vdchuff_803DEDC0[2];

void fn_8006CD20(f32* arr, int n, f32* out1, f32* out2, f32 a, f32 b, f32 c)
{
    f32* p;
    int i;
    f32 acc5 = lbl_803DED28;
    f32 acc6 = lbl_803DED28;

    p = arr;
    for (i = 0; i < n; i++, p += 5)
    {
        f32 over = lbl_803DED28;
        if (c < p[0])
        {
            f32 mx, mz, t, s0, tmp, p2lo, d2, sq, ratio, frac, depth;
            t = GPFifo_803DED3C + (p[0] - c) / p[0];
            if (t > lbl_803DED2C) t = lbl_803DED2C;
            s0 = sqrtf(t);

            mx = (f32)__fabs(p[1] - a);
            tmp = (f32)__fabs((lbl_803DED2C + p[1]) - a);
            if (tmp < mx) mx = tmp;
            tmp = (f32)__fabs((p[1] - lbl_803DED2C) - a);
            if (tmp < mx) mx = tmp;

            mz = (f32)__fabs(p[2] - b);
            if (b > p[2]) over = b - p[2];
            tmp = (f32)__fabs((lbl_803DED2C + p[2]) - b);
            if (tmp < mz)
            {
                mz = tmp;
                over = lbl_803DED28;
            }
            p2lo = p[2] - lbl_803DED2C;
            tmp = (f32)__fabs(p2lo - b);
            if (tmp < mz)
            {
                mz = tmp;
                if (b > p2lo) over = b - p2lo;
            }

            d2 = mx * mx + mz * mz;
            sq = sqrtf(d2);

            ratio = c / p[0];
            frac = sqrtf(ratio);
            depth = p[3] - frac * (p[3] - p[4]);
            if (sq <= depth)
            {
                f32 g = lbl_803DED2C - sq / depth;
                g = sqrtf(g);
                acc5 = s0 * g + acc5;
                acc6 = acc6 + over / depth;
                acc6 = CPUFifo_803DED38 * (lbl_803DED2C - c * Vdchuff_803DEDC0[4]) + acc6;
            }
        }
    }
    if (acc5 > lbl_803DED2C) acc5 = lbl_803DED2C;
    if (acc6 > lbl_803DED2C) acc6 = lbl_803DED2C;
    *out1 = __GXCurrentThread_803DED40 * acc6 + Vdchuff_803DEDC0[5];
    *out2 = acc5;
}

extern int testAndSet_onlyUseHeap3(int);
extern f32 fn_802943F4(f32);
extern double floor(double);
extern f32 Yachuff_803DEDE0[2];
extern f32 __PADFixBits;
extern f32 lbl_80391978[];
extern f32 lbl_803DCFA8, lbl_803DCFAC;

void initFn_8006d020(void)
{
    u8 saved;
    int placed, attempts, tex, row, col, collide, j;
    f32* e;
    int* th;

    saved = testAndSet_onlyUseHeap3(1);
    placed = 0;
    attempts = 0;
    e = lbl_80391978;
    while (placed < 0x32 && attempts < 10000)
    {
        e[0] = (f32)(int)
        randomGetRange(8, 0x10);
        e[3] = 0.01f * (f32)(int)
        randomGetRange(5, 10);
        e[4] = e[3] * (0.01f * (f32)(int)
        randomGetRange(0x14, 0x32)
        )
        ;
        attempts = 0;
        do
        {
            f32* o;
            e[1] = 0.001f * (f32)(int)
            randomGetRange(0, 999);
            e[2] = 0.001f * (f32)(int)
            randomGetRange(0, 999);
            collide = 0;
            j = 0;
            o = lbl_80391978;
            while (j < placed && !collide)
            {
                f32 mx, mz, tmp, d;
                mx = (f32)__fabs(e[1] - o[1]);
                tmp = (f32)__fabs((1.0f + e[1]) - o[1]);
                if (tmp < mx) mx = tmp;
                tmp = (f32)__fabs((e[1] - 1.0f) - o[1]);
                if (tmp < mx) mx = tmp;
                mz = (f32)__fabs(e[2] - o[2]);
                tmp = (f32)__fabs((1.0f + e[2]) - o[2]);
                if (tmp < mz) mz = tmp;
                tmp = (f32)__fabs((e[2] - 1.0f) - o[2]);
                if (tmp < mz) mz = tmp;
                d = mx * mx + mz * mz;
                if (d > 0.0f) d = sqrtf(d);
                if (d < e[4] + o[3]) collide = 1;
                o += 5;
                j++;
            }
            attempts++;
        }
        while (collide && attempts < 10000);
        e += 5;
        placed++;
    }

    th = (int*)lbl_8038E268;
    for (tex = 0; tex < 0x10; tex++, th++)
    {
        *th = (int)textureAlloc(0x40, 0x40, 3, 0, 0, 1, 1, 1, 1);
        for (row = 0; row < 0x40; row++)
        {
            for (col = 0; col < 0x40; col++)
            {
                f32 o2, o1;
                int hi, lo;
                u16* dst = (u16*)(*th + (row & 3) * 2 + (row >> 2) * 0x20
                    + (col & 3) * 8 + (col >> 2) * 0x200 + 0x60);
                fn_8006CD20(lbl_80391978, placed, &o1, &o2,
                            (f32)row * 0.015625f,
                            (f32)col * 0.015625f,
                            (f32)tex);
                hi = (int)(__PADFixBits * o2);
                lo = (int)(__PADFixBits * o1);
                *dst = (u16)(((hi & 0xffff) << 8) | lo);
            }
        }
        DCFlushRange((void*)(*th + 0x60), *(u32*)(*th + 0x44));
    }

    lbl_803DCFE0 = (u32)textureAlloc(0x40, 0x40, 3, 0, 0, 1, 1, 1, 1);
    for (row = 0; row < 0x40; row++)
    {
        f32 rv = 0.0981875f * (f32)row;
        for (col = 0; col < 0x40; col++)
        {
            f32 cv, n1, n2, prod, fa, fb;
            int hi, lo;
            u16* dst = (u16*)(lbl_803DCFE0 + (row & 3) * 2 + (row >> 2) * 0x20
                + (col & 3) * 8 + (col >> 2) * 0x200 + 0x60);
            cv = 0.39275f * (f32)col;
            n1 = fn_802943F4(CPUFifo_803DED38 * floor(cv) + rv);
            n2 = fn_802943F4(cv);
            prod = n1 * n2;
            fb = 127.0f * prod + 127.0f;
            fa = 127.0f * n1 + 127.0f;
            lo = (int)fa;
            hi = (int)fb;
            *dst = (u16)(lo | ((hi & 0xffff) << 8));
        }
    }
    DCFlushRange((void*)(lbl_803DCFE0 + 0x60), *(u32*)(lbl_803DCFE0 + 0x44));

    lbl_803DCFAC = 0.0f;
    lbl_803DCFA8 = 0.0f;
    testAndSet_onlyUseHeap3(saved);
}

extern int textureLoadAsset(int);
extern void DCInvalidateRange(void*, int);
extern void fn_80069EB8();
extern void GXTexModeSync(void);
extern f32 lbl_803DED10, lbl_803DED34, Dev_803DED1C;
extern f32 Udchuff_803DEDA0[2], Uachuff_803DEE00[2];
#pragma ppc_unroll_speculative off
void allocLotsOfTextures(void)
{
    char* g = (char*)(int)lbl_8038DF48;
    u8 saved;
    int i, j, h;

    saved = testAndSet_onlyUseHeap3(1);

    *(int*)(g + 0x3a10) = (int)textureAlloc(0x100, 0x100, 0, 0, 0, 0, 0, 1, 1);
    *(int*)(g + 0x3a14) = (int)textureAlloc(0x100, 0x100, 1, 0, 0, 0, 0, 0, 0);
    *(int*)(g + 0x3a18) = *(int*)(g + 0x3a14);
    *(int*)(g + 0x3a1c) = *(int*)(g + 0x3a14);
    *(int*)(g + 0x3a20) = *(int*)(g + 0x3a14);
    *(int*)(g + 0x3a24) = *(int*)(g + 0x3a14);
    *(int*)(g + 0x3a28) = *(int*)(g + 0x3a14);
    *(int*)(g + 0x3a2c) = *(int*)(g + 0x3a14);
    memset((void*)(*(int*)(g + 0x3a10) + 0x60), 0, *(u32*)(*(int*)(g + 0x3a10) + 0x44));
    DCFlushRange((void*)(*(int*)(g + 0x3a10) + 0x60), *(int*)(*(int*)(g + 0x3a10) + 0x44));

    lbl_803DCF7C = (char*)textureAlloc(0x140, 0xf0, 4, 0, 0, 0, 0, 1, 1);
    lbl_803DCFE4 = (int)textureAlloc(0x50, 0x3c, 4, 0, 0, 0, 0, 1, 1);
    lbl_803DCFDC = (int)textureAlloc(0x140, 0xf0, 1, 0, 0, 0, 0, 1, 1);

    lbl_803DCFD8 = (int)textureAlloc(0x20, 0x20, 1, 0, 0, 0, 0, 1, 1);
    for (i = 0; i < 0x20; i++)
    {
        int rowoff, lowoff, isum;
        f32 cy;
        j = 0;
        rowoff = (i >> 3) * 0x20;
        lowoff = i & 7;
        cy = (f32)i - 16.0f;
        isum = lowoff + rowoff;
        for (; j < 0x20; j++)
        {
            int base = lbl_803DCFD8;
            int off = isum + (j & 3) * 8 + (j >> 2) * 0x80 + 0x60;
            f32 dx = cy * 0.0625f;
            f32 dz = ((f32)j - 16.0f) * 0.0625f;
            f32 d2;
            f32 v;
            dx = dx * 1.1f;
            dz = dz * 1.1f;
            d2 = dx * dx + dz * dz;
            if (d2 > 1.0f)
            {
                v = 0.0f;
            }
            else
            {
                v = 1.0f - d2;
            }
            *(u8*)(base + off) = 255.0f * v;
        }
    }
    DCFlushRange((void*)(lbl_803DCFD8 + 0x60), *(int*)(lbl_803DCFD8 + 0x44));

    lbl_803DCFD4 = (int)textureAlloc(0x10, 0x10, 1, 0, 0, 0, 0, 1, 1);
    for (i = 0; i < 0x10; i++)
    {
        int rowoff, lowoff, isum;
        f32 cy;
        j = 0;
        rowoff = (i >> 3) * 0x20;
        lowoff = i & 7;
        cy = (f32)i - 8.0f;
        isum = lowoff + rowoff;
        for (; j < 0x10; j++)
        {
            int base = lbl_803DCFD4;
            int off = isum + (j & 3) * 8 + (j >> 2) * 0x40 + 0x60;
            f32 dx = cy * 0.125f;
            f32 dz = ((f32)j - 8.0f) * 0.125f;
            f32 d2;
            f32 v;
            dx = dx * 1.2f;
            dz = dz * 1.2f;
            d2 = dx * dx + dz * dz;
            if (d2 > 1.0f)
            {
                v = 0.0f;
            }
            else
            {
                v = sqrtf(1.0f - d2);
            }
            *(u8*)(base + off) = 255.0f * v;
        }
    }
    DCFlushRange((void*)(lbl_803DCFD4 + 0x60), *(int*)(lbl_803DCFD4 + 0x44));

    lbl_803DCFD0 = (int)textureAlloc(0x40, 0x40, 5, 0, 0, 0, 0, 1, 1);
    {
        f32 mx = 0.0f;
        for (i = 0; i < 0x40; i++)
        {
            f32 fi, fi2, rc, rc2;
            j = 0;
            fi = (f32)i - 32.0f;
            fi2 = (f32)(i + 1) - 32.0f;
            rc = fi * 0.03125f;
            rc2 = fi2 * 0.03125f;
            for (; j < 0x40; j++)
            {
                f32 cc = ((f32)j - 32.0f) * 0.03125f;
                f32 d1 = sqrtf(cc * cc + rc * rc);
                f32 d2 = sqrtf(cc * cc + rc2 * rc2);
                f32 cc2 = ((f32)(j + 1) - 32.0f) * 0.03125f;
                f32 d3 = sqrtf(cc2 * cc2 + rc * rc);
                f32 n1 = -fn_802943F4(18.852f * d1);
                f64 n2 = __fabs(fn_802943F4(18.852f * d2));
                f64 n3 = __fabs(fn_802943F4(18.852f * d3));
                f32 a = n1 - (f32)n2;
                f32 b = n1 - (f32)n3;
                if (a > mx) mx = a;
                if (b > mx) mx = b;
            }
        }
        {
            f32 inv = 1.0f / mx;
            for (j = 0; j < 0x40; j++)
            {
                int rowoff, lowoff;
                f32 fj, fj2, rc, rc2;
                i = 0;
                rowoff = (j >> 2) * 0x20;
                lowoff = (j & 3) * 2;
                fj = (f32)j - 32.0f;
                fj2 = (f32)(j + 1) - 32.0f;
                rc = fj * 0.03125f;
                rc2 = fj2 * 0.03125f;
                for (; i < 0x40; i++)
                {
                    int dst = lbl_803DCFD0 + lowoff + rowoff + (i & 3) * 8 + (i >> 2) * 0x200;
                    f32 cc = ((f32)i - 32.0f) * 0.03125f;
                    f32 d1 = sqrtf(cc * cc + rc * rc);
                    f32 d2 = sqrtf(cc * cc + rc2 * rc2);
                    f32 cc2 = ((f32)(i + 1) - 32.0f) * 0.03125f;
                    f32 d3 = sqrtf(cc2 * cc2 + rc * rc);
                    f32 n1 = -fn_802943F4(18.852f * d1);
                    f32 n2 = -fn_802943F4(18.852f * d2);
                    f32 n3 = -fn_802943F4(18.852f * d3);
                    f32 a = inv * (127.0f * (n1 - n2)) + 127.0f;
                    f32 b = inv * (127.0f * (n1 - n3)) + 127.0f;
                    f32 dd;
                    f32 c;
                    int bi, ci, ai;
                    if (d1 < 1.0f)
                    {
                        dd = sqrtf(1.0f - d1);
                    }
                    else
                    {
                        dd = 0.0f;
                    }
                    c = 32.0f * dd;
                    if (c > 15.0f) c = 15.0f;
                    a = a * 0.03125f;
                    b = b * 0.0625f;
                    bi = (int)b & 0xf;
                    ci = ((u16)(int)
                    c & 0xf
                    )
                    <<
                    4;
                    ai = ((u16)(int)
                    a & 7
                    )
                    <<
                    12;
                    *(u16*)(dst + 0x60) = (u16)(ci | ai | bi);
                }
            }
        }
    }
    DCFlushRange((void*)(lbl_803DCFD0 + 0x60), *(int*)(lbl_803DCFD0 + 0x44));

    lbl_803DCFCC = textureLoadAsset(0x5b0);
    lbl_803DCFC8 = textureLoadAsset(0x600);
    lbl_803DCFC4 = textureLoadAsset(0xc18);

    lbl_803DCF9C = (int)textureAlloc(0x100, 4, 1, 0, 0, 0, 0, 0, 0);
    for (i = 0; i < 0x100; i++)
    {
        *((u8*)(lbl_803DCF9C + (i & 7) + (i >> 3) * 0x20) + 0x60) = (u8)i;
        *((u8*)(lbl_803DCF9C + (i & 7) + (i >> 3) * 0x20) + 0x68) = (u8)i;
        *((u8*)(lbl_803DCF9C + (i & 7) + (i >> 3) * 0x20) + 0x70) = (u8)i;
        *((u8*)(lbl_803DCF9C + (i & 7) + (i >> 3) * 0x20) + 0x78) = (u8)i;
    }
    DCFlushRange((void*)(lbl_803DCF9C + 0x60), *(int*)(lbl_803DCF9C + 0x44));

    lbl_803DCF98 = (int)textureAlloc(0x100, 4, 1, 0, 0, 0, 0, 1, 1);
    for (i = 0; i < 0x100; i++)
    {
        *((u8*)(lbl_803DCF98 + (i & 7) + (i >> 3) * 0x20) + 0x60) = (u8)(255 - i);
        *((u8*)(lbl_803DCF98 + (i & 7) + (i >> 3) * 0x20) + 0x68) = (u8)(255 - i);
        *((u8*)(lbl_803DCF98 + (i & 7) + (i >> 3) * 0x20) + 0x70) = (u8)(255 - i);
        *((u8*)(lbl_803DCF98 + (i & 7) + (i >> 3) * 0x20) + 0x78) = (u8)(255 - i);
    }
    DCFlushRange((void*)(lbl_803DCF98 + 0x60), *(int*)(lbl_803DCF98 + 0x44));

    lbl_803DCF90 = (int)textureAlloc(0x80, 0x80, 1, 0, 0, 0, 0, 1, 1);
    for (i = 0; i < 0x80; i++)
    {
        int rowoff, lowoff, isum;
        f32 cy;
        j = 0;
        rowoff = (i >> 3) * 0x20;
        lowoff = i & 7;
        cy = (f32)i - 64.0f;
        isum = lowoff + rowoff;
        cy = cy * 0.015625f;
        for (; j < 0x80; j++)
        {
            int base = lbl_803DCF90;
            int off = isum + (j & 3) * 8 + (j >> 2) * 0x200 + 0x60;
            f32 cx = ((f32)j - 64.0f) * 0.015625f;
            f32 d2 = sqrtf(cx * cx + cy * cy);
            *(u8*)(base + off) = (d2 < 0.5f)
                                     ? 0xa0
                                     : ((d2 > 1.0f) ? 0 : (int)(160.0f * (1.0f - (d2 - 0.5f) / 0.5f)));
        }
    }
    DCFlushRange((void*)(lbl_803DCF90 + 0x60), *(int*)(lbl_803DCF90 + 0x44));

    lbl_803DCFC0 = (int)textureAlloc(0x80, 0x80, 1, 0, 0, 0, 0, 1, 1);
    for (i = 0; i < 0x80; i++)
    {
        int rowoff, lowoff, isum;
        f32 cy;
        j = 0;
        rowoff = (i >> 3) * 0x20;
        lowoff = i & 7;
        cy = (f32)i - 64.0f;
        isum = lowoff + rowoff;
        cy = cy * 0.015625f;
        cy = (f32)__fabs(cy);
        for (; j < 0x80; j++)
        {
            int base = lbl_803DCFC0;
            int off = isum + (j & 3) * 8 + (j >> 2) * 0x200 + 0x60;
            f32 cx = (f32)__fabs(((f32)j - 64.0f) * 0.015625f);
            f32 d2 = sqrtf(cx * cx + cy * cy);
            f32 v = 1.0f - d2;
            if (v < 0.0f) v = 0.0f;
            *(u8*)(base + off) = 255.0f * v;
        }
    }
    DCFlushRange((void*)(lbl_803DCFC0 + 0x60), *(int*)(lbl_803DCFC0 + 0x44));

    lbl_803DCFB8 = (int)textureAlloc(0x40, 0x40, 1, 0, 0, 0, 0, 1, 1);
    DCInvalidateRange((void*)(lbl_803DCFB8 + 0x60), *(int*)(lbl_803DCFB8 + 0x44));
    fn_80069EB8(0);

    lbl_803DCFB4 = (int)textureAlloc(0x20, 4, 1, 0, 0, 0, 0, 1, 1);
    for (i = 0; i < 0x20; i++)
    {
        int rowoff, lowoff, isum;
        f32 c0;
        j = 0;
        rowoff = (i >> 3) * 0x20;
        lowoff = i & 7;
        c0 = (f32)i - 16.0f;
        isum = lowoff + rowoff;
        c0 = c0 * 0.0625f;
        c0 = (f32)__fabs(c0);
        for (; j < 4; j++)
        {
            int base = lbl_803DCFB4;
            int off = isum + (j & 3) * 8 + (j >> 2) * 0x80 + 0x60;
            f32 v = sqrtf(c0);
            v = sqrtf(v);
            *(u8*)(base + off) = 255.0f * (1.0f - v);
        }
    }
    DCFlushRange((void*)(lbl_803DCFB4 + 0x60), *(int*)(lbl_803DCFB4 + 0x44));

    lbl_803DCFB0 = (int)textureAlloc(0x80, 0x80, 1, 0, 0, 1, 1, 1, 1);
    for (i = 0; i < 0x80; i++)
    {
        int rowoff, lowoff, isum;
        f32 cy;
        j = 0;
        rowoff = (i >> 3) * 0x20;
        lowoff = i & 7;
        cy = (f32)i - 64.0f;
        isum = lowoff + rowoff;
        cy = cy * 0.015625f;
        for (; j < 0x80; j++)
        {
            int base = lbl_803DCFB0;
            int off = isum + (j & 3) * 8 + (j >> 2) * 0x200 + 0x60;
            f32 cx = ((f32)j - 64.0f) * 0.015625f;
            f32 d2 = sqrtf(cx * cx + cy * cy);
            f32 v;
            if (d2 < 0.25f || d2 > 0.75f)
            {
                v = 0.0f;
            }
            else
            {
                f32 t = 2.0f * (d2 - 0.25f);
                if (t > 0.5f)
                {
                    v = -(2.0f * (t - 0.5f) - 1.0f);
                }
                else
                {
                    v = -(2.0f * (0.5f - t) - 1.0f);
                }
                v = sqrtf(v);
            }
            *(u8*)(base + off) = 16.0f * v;
        }
    }
    DCFlushRange((void*)(lbl_803DCFB0 + 0x60), *(int*)(lbl_803DCFB0 + 0x44));

    lbl_803DCF94 = (int)textureAlloc(4, 4, 3, 0, 0, 0, 0, 1, 1);
    for (i = 0; i < 4; i++)
    {
        f32 x = (f32)i / 3.0f - CPUFifo_803DED38;
        *(u16*)((u8*)(lbl_803DCF94 + (i & 3) * 2 + (i >> 2) * 0x20) + 0x60) =
            (u16)((((int)(255.0f * x + 128.0f) & 0xff) << 8) | ((int)CPUFifo_803DED38 & 0xff));
        *(u16*)((u8*)(lbl_803DCF94 + (i & 3) * 2 + (i >> 2) * 0x20) + 0x68) =
            (u16)((((int)(255.0f * x + 128.0f) & 0xff) << 8) | ((int)Uachuff_803DEE00[5] & 0xff));
        *(u16*)((u8*)(lbl_803DCF94 + (i & 3) * 2 + (i >> 2) * 0x20) + 0x70) =
            (u16)((((int)(255.0f * x + 128.0f) & 0xff) << 8) | ((int)Uachuff_803DEE00[6] & 0xff));
        *(u16*)((u8*)(lbl_803DCF94 + (i & 3) * 2 + (i >> 2) * 0x20) + 0x78) =
            (u16)((((int)(255.0f * x + 128.0f) & 0xff) << 8) | ((int)Uachuff_803DEE00[7] & 0xff));
    }
    DCFlushRange((void*)(lbl_803DCF94 + 0x60), *(int*)(lbl_803DCF94 + 0x44));

    h = (int)textureAlloc(0x80, 0x80, 1, 0, 0, 0, 0, 1, 1);
    memset((void*)(h + 0x60), 0, *(u32*)(h + 0x44));
    *(u16*)(h + 0xe) = 1;
    DCFlushRange((void*)(h + 0x60), *(int*)(h + 0x44));
    *(int*)(g + 0x294) = h;
    h = (int)textureAlloc(0x80, 0x80, 1, 0, 0, 0, 0, 1, 1);
    memset((void*)(h + 0x60), 0, *(u32*)(h + 0x44));
    *(u16*)(h + 0xe) = 1;
    DCFlushRange((void*)(h + 0x60), *(int*)(h + 0x44));
    *(int*)(g + 0x298) = h;
    h = (int)textureAlloc(0x80, 0x80, 1, 0, 0, 0, 0, 1, 1);
    memset((void*)(h + 0x60), 0, *(u32*)(h + 0x44));
    *(u16*)(h + 0xe) = 1;
    DCFlushRange((void*)(h + 0x60), *(int*)(h + 0x44));
    *(int*)(g + 0x29c) = h;
    GXTexModeSync();

    {
        u8* p;
        for (i = 0, p = (u8*)(int)lbl_8038DF48; i < 0x20; i += 0x10)
        {
            for (j = 0; j < 0x10; j++)
            {
                p[j * 0x14 + 0x10] = 0;
                p[j * 0x14 + 0x11] = 1;
            }
            p += 0x140;
        }
        p = (u8*)(int)lbl_8038DF48 + i * 0x14;
        for (; i < 0x21; i++)
        {
            p[0x10] = 0;
            p[0x11] = 1;
            p += 0x14;
        }
    }
    GXInvalidateTexAll();
    testAndSet_onlyUseHeap3(saved);
}
#pragma ppc_unroll_speculative on
void shadowCreate(int* obj)
{
    ObjAnimComponent* objAnim;
    ObjModelInstance* modelDef;
    int* cam;
    f32 dx, dy, dz, dist;
    if (lbl_803DCF78 < 0x12c)
    {
        objAnim = (ObjAnimComponent*)obj;
        modelDef = objAnim->modelInstance;
        *(int**)(lbl_8038E2A8 + lbl_803DCF78 * 0xc) = obj;
        cam = lbl_803DCFE8;
        dx = ((GameObject*)obj)->anim.worldPosX - *(f32*)((char*)cam + 0xc);
        dy = ((GameObject*)obj)->anim.worldPosY - *(f32*)((char*)cam + 0x10);
        dz = ((GameObject*)obj)->anim.worldPosZ - *(f32*)((char*)cam + 0x14);
        dist = sqrtf(dx * dx + dy * dy + dz * dz);
        *(f32*)(lbl_8038E2A8 + lbl_803DCF78 * 0xc + 4) =
            ((GameObject*)obj)->anim.modelState->shadowScale / dist;
        if (modelDef->shadowType == 2)
        {
            *(u8*)(lbl_8038E2A8 + lbl_803DCF78 * 0xc + 8) = 1;
            if (modelDef->renderFlags & 4)
            {
                *(u8*)(lbl_8038E2A8 + lbl_803DCF78 * 0xc + 8) = 2;
                *(f32*)(lbl_8038E2A8 + lbl_803DCF78 * 0xc + 4) = Ydchuff_803DED80[4];
            }
        }
        else
        {
            *(u8*)(lbl_8038E2A8 + lbl_803DCF78 * 0xc + 8) = 0;
        }
        lbl_803DCF78 = lbl_803DCF78 + 1;
    }
}

void objAudioFn_8006edcc(int p1, int mask, int p5, int p6, int p7, f32 f1, f32 f2)
{
    s8 buf[0x1c];
    int bit;
    memset(buf, 0, 0x1c);
    for (bit = 0; bit < 32; bit++)
    {
        if ((mask >> bit) & 1)
        {
            buf[buf[0x1b] + 0x13] = (s8)bit;
            buf[0x1b]++;
        }
    }
    objAudioFn_8006ef38(p1, buf, p5, p6, p7, f1, f2);
}

extern int getHudHiddenFrameCount(void);
extern f32 timeDelta;
extern int* Camera_GetCurrentViewSlot(void);
extern u8 framesThisStep;
extern f32 Udchuff_803DEDA0[2];
extern void fn_80060BB0(void);
extern u8 lbl_803DCF80;
extern int isHeavyFogEnabled(void);
extern f32* Camera_GetInverseViewMatrix(void);
extern void fn_8004C234(f32 * a, f32 * b);
extern f32 Dev_803DED1C;
extern u16 lbl_803DCFA0;
#pragma peephole on
void maybeHudFn_8006c91c(void)
{
    f32 lo, hi;
    if (getHudHiddenFrameCount() == 0)
    {
        f32 d = timeDelta;
        lbl_803DCFAC = 0.0084f * d + lbl_803DCFAC;
        lbl_803DCFA8 = 0.003f * d + lbl_803DCFA8;
        if (lbl_803DCFAC > 256.0f) lbl_803DCFAC = lbl_803DCFAC - 256.0f;
        if (lbl_803DCFA8 > 256.0f) lbl_803DCFA8 = lbl_803DCFA8 - 256.0f;
    }
    lbl_803DCF78 = 0;
    lbl_803DCFE8 = Camera_GetCurrentViewSlot();
    lbl_803DCFA0 = (u16)(lbl_803DCFA0 + framesThisStep * 0x28a);
    lbl_803DCFA4 = 0.2f *
        floor(6.284f * (f32)(u32)lbl_803DCFA0 / 65536.0f);
    fn_80060BB0();
    lbl_803DCF8C = (lbl_803DCF8C + 1) % 3;
    if (isHeavyFogEnabled())
    {
        f32 z = Camera_GetInverseViewMatrix()[7];
        int v;
        fn_8004C234(&hi, &lo);
        if (z >= hi) v = 0;
        else if (z <= lo) v = 0x40;
        else v = (int)(Dev_803DED1C * (hi - z) / (hi - lo));
        if ((u8)v != lbl_803DCF80) fn_80069EB8();
    }
}

extern void Obj_BuildWorldTransformMatrix(int* obj, f32* mtx, int x);
extern f32 playerMapOffsetX, playerMapOffsetZ;
extern f32 lbl_803DED0C, lbl_803DED10, lbl_803DED14, Chan_803DED18;
extern f32 Enabled_803DED20, BarnacleEnabled_803DED24, lbl_803DED2C;
extern void Camera_ProjectWorldSphere(f32* a, f32* b, f32* c, f32* d, f32* e, f32* f,
                                      f32 x, f32 y, f32 z, f32 r);
extern void GXSetViewport(f32 a, f32 b, f32 c, f32 d, f32 e, f32 f);
extern void set_shadowFlag_803dcc29(int x);
extern void objRender(int a, int b, int c, int d, int* obj, int e);
extern int* Obj_GetActiveModel(int* obj);
extern void Camera_ApplyFullViewport(void);
#pragma peephole off
void shadowRenderFn_8006b558(int* obj)
{
    f32 mtx[12];
    f32 vF, vE, vD, vC, vB, vA;
    f32 sc, objScale, nx, ny, m;
    f32* o64;
    Obj_BuildWorldTransformMatrix(obj, mtx, 0);
    Camera_ProjectWorldSphere(&vA, &vB, &vC, &vD, &vE, &vF,
                              ((GameObject*)obj)->anim.localPosX - playerMapOffsetX,
                              ((GameObject*)obj)->anim.localPosY,
                              ((GameObject*)obj)->anim.localPosZ - playerMapOffsetZ,
                              1.3f * (((GameObject*)obj)->anim.hitboxScale * ((GameObject*)obj)->anim.rootMotionScale));
    vD = 320.0f * vD + 8.0f;
    vE = Chan_803DED18 * vE + 8.0f;
    if (vD > vE) m = vD;
    else m = vE;
    sc = Dev_803DED1C / m;
    objScale = ((GameObject*)obj)->anim.rootMotionScale * sc;
    nx = -vA;
    ny = vB;
    GXSetViewport(320.0f * nx, Chan_803DED18 * ny, Enabled_803DED20,
                  BarnacleEnabled_803DED24, 0.0f, 1.0f);
    if (vC < 0.0f)
    {
        f32 saved = ((GameObject*)obj)->anim.rootMotionScale;
        int* model;
        ((GameObject*)obj)->anim.rootMotionScale = objScale;
        set_shadowFlag_803dcc29(1);
        objRender(0, 0, 0, 0, obj, 1);
        set_shadowFlag_803dcc29(0);
        ((GameObject*)obj)->anim.rootMotionScale = saved;
        model = Obj_GetActiveModel(obj);
        *(u16*)((char*)model + 0x18) &= ~0x8;
        gxSetZMode_(1, 3, 1);
        GXSetTexCopySrc(0x100, 0xb0, 0x80, 0x80);
        GXSetTexCopyDst(0x80, 0x80, 0x2a, 0);
        GXCopyTex((void*)(lbl_8038E1DC[lbl_803DCF8C] + 0x60), 1);
        fn_8006A028((u8*)lbl_8038E1DC[(lbl_803DCF8C + 1) % 3], 0x80, 0x10, 0);
        *(f32*)obj[0x64 / 4] = 1.0f / sc;
    }
    else
    {
        *(f32*)obj[0x64 / 4] = vE;
    }
    Camera_ApplyFullViewport();
    o64 = (f32*)obj[0x64 / 4];
    o64[5] = 320.0f * vA;
    o64[6] = Chan_803DED18 * -vB;
    o64[5] = o64[5] + 320.0f;
    o64[6] = o64[6] + Chan_803DED18;
    o64[5] = o64[5] - Dev_803DED1C * o64[0];
    o64[6] = o64[6] - Dev_803DED1C * o64[0];
}

extern f32 lbl_803DED34, GXOverflowSuspendInProgress_803DED48;

void fn_8006CB50(void)
{
    int y, x;
    lbl_803DCFBC = (u32)textureAlloc(0x100, 0x100, 3, 0, 0, 0, 0, 1, 1);
    for (y = 0; y < 0x100; y++)
    {
        f32 fy = (f32)y - 127.5f;
        for (x = 0; x < 0x100; x++)
        {
            char* addr = (char*)lbl_803DCFBC + (y & 3) * 2 + (y >> 2) * 0x20 + (x & 3) * 8 + (x >> 2) * 0x800;
            f32 fx = (f32)x - 127.5f;
            f32 dist = sqrtf(fy * fy + fx * fx);
            f32 ny = fy / dist;
            f32 nx = fx / dist;
            f32 s;
            if (dist <= 112.0f)
            {
                s = lbl_803DED34 * (100.8f - GXOverflowSuspendInProgress_803DED48 * dist) * 0.00390625f;
            }
            else
            {
                s = lbl_803DED28;
            }
            {
                f32 py = 127.0f * (ny * s) + 128.0f;
                f32 px = 127.0f * (nx * s) + 128.0f;
                *(u16*)(addr + 0x60) = (u16)((int)px | (((int)py & 0xffff) << 8));
            }
        }
    }
    DCFlushRange((char*)lbl_803DCFBC + 0x60, *(u32*)((char*)lbl_803DCFBC + 0x44));
}

extern void Camera_DisableViewYOffset(void);
extern void Camera_EnableViewYOffset(void);
extern f32 Camera_GetFovY(void);
extern void Camera_SetFovY(f32 x);
extern void Camera_SetAspectRatio(f32 x);
extern void Camera_SetCurrentViewIndex(int i);
extern void Camera_UpdateViewMatrices(void);
extern void Camera_RebuildProjectionMatrix(void);
extern void Camera_UpdateProjection(int a, int b);
extern f32* Camera_GetViewMatrix(void);
extern void fn_80061094(f32* v, f32* out, f32 x);
extern void mapGetBlocks(int* a, int* b);
extern int fn_800626C8(int* obj, int frames);
extern void fn_8008923C(int* obj, f32* a, f32* b, f32* c);
extern f32 PSVECDotProduct(f32 * a, f32 * b);
extern f32 PSVECMag(f32 * v);
extern void PSVECScale(f32* v, f32* out, f32 s);
extern void PSVECNormalize(f32 * v, f32 * out);
extern int getAngle(f32 a, f32 b);
extern void setScreenWidth(int w);
extern void clearScreenWidth(void);
extern f32* ObjModel_GetJointMatrix(int* model, int joint);
extern void C_MTXOrtho(f32* m, f32 t, f32 b, f32 l, f32 r, f32 n, f32 f);
extern void C_MTXLightOrtho(f32* m, f32 t, f32 b, f32 l, f32 r, f32 sx, f32 sy, f32 tx, f32 ty);
extern void GXSetProjection(f32* m, int type);
extern void PSMTXCopy(f32 * s, f32 * d);
extern void PSMTXConcat(f32 * a, f32 * b, f32 * o);
extern void PSMTXScale(f32* m, f32 x, f32 y, f32 z);
extern void PSMTXTrans(f32* m, f32 x, f32 y, f32 z);
extern void objRenderShadowIfVisible(int* obj, int a, int b, int c, int d, int e);
extern void GXSetCopyFilter(int a, void* b, int c, void* d);
extern void GXSetScissor(int a, int b, int c, int d);
extern void setDisplayCopyFilter(void);
extern int getDrawDistanceFlag_8005cd48(void);
extern int isWidescreen(void);
extern void* memcpy(void* d, const void* s, int n);
extern f32 lbl_803DED28, lbl_803DED2C, lbl_803DED30, lbl_803DED34;
extern f32 lbl_803DED70, lbl_803DED74, lbl_803DED78, lbl_803DED7C;
extern f32 CPUFifo_803DED38, GPFifo_803DED3C, __GXCurrentThread_803DED40;
extern f32 CPGPLinked_803DED44, BreakPointCB_803DED4C, __GXOverflowCount_803DED50;
extern f32 FinishQueue_803DED64;
extern u8 lbl_803DB668[8];
extern f32 lbl_803DB670;
extern int lbl_803DCCF0;
extern f32 lbl_803DCED0, lbl_803DCECC;
extern int lbl_803DCF84, lbl_803DCF88;
extern char lbl_8038DF48b[];

void renderShadows(void)
{
    char* B = (char*)lbl_8038DF48;
    int* slot;
    f32 savedFovY, sCamX, sCamY, sCamZ;
    s16 s170, s14, s19;
    f32 om100[24];
    f32 mTrans[12], mScale[12], mOrtho[16];
    f32 mc54[3], mc48[3];
    f32 vA[3], v30[3];
    f32 dot24[3], proj[3];
    int blkArr, blkCount;
    int r22, r23, r24;
    char* casterPtr;
    f32 dirX, dirY, dirZ, f22, f21, f23, vAy;
    f32 *vAp1, *vAp2, *mc54p;

    if (lbl_803DCF78 == 0) return;
    Camera_DisableViewYOffset();
    fn_8006B830((ShadowSortEntry*)(B + 0x360), lbl_803DCF78);
    Camera_SetCurrentViewIndex(1);
    slot = Camera_GetCurrentViewSlot();
    savedFovY = Camera_GetFovY();
    Camera_SetFovY(lbl_803DED30);
    Camera_SetAspectRatio(lbl_803DED2C);
    sCamX = ((GameObject*)slot)->anim.localPosX;
    sCamY = ((GameObject*)slot)->anim.localPosY;
    sCamZ = ((GameObject*)slot)->anim.localPosZ;
    s170 = ((GameObject*)slot)->anim.rotY;
    s14 = ((GameObject*)slot)->anim.rotX;
    s19 = ((GameObject*)slot)->anim.rotZ;
    ((GameObject*)slot)->anim.rotY = 0;
    v30[0] = lbl_803DED28;
    v30[1] = lbl_803DED2C;
    v30[2] = lbl_803DED28;
    fn_80061094(v30, om100, lbl_803DED34);
    mapGetBlocks(&blkArr, &blkCount);
    r23 = 0;
    r24 = 0;
    casterPtr = B + 0x360;
    vAp1 = &vA[1];
    vAp2 = &vA[2];
    mc54p = &mc54[0];
    for (r22 = 0; (s8)r22 < (int)lbl_803DCF78 && (s8)r22 < 0x64; r22++, casterPtr += 0xc)
    {
        int* obj = *(int**)casterPtr;
        int* of64 = (int*)obj[0x64 / 4];
        int lod, screenW = 0, w = 0;
        char* castSlot;
        Camera_SetCurrentViewIndex(0);
        lod = fn_800626C8(obj, framesThisStep);
        Camera_SetCurrentViewIndex(1);
        if ((u8)lod <= 4) continue;
        if ((*(int*)&((ObjModelState*)of64)->flags & 0x20) != 0)
        {
            memcpy(mc48, (char*)obj + 0xc, 0xc);
            memcpy(mc54p, (char*)obj + 0x18, 0xc);
            memcpy((char*)obj + 0xc, (char*)of64 + 0x20, 0xc);
            memcpy((char*)obj + 0x18, (char*)of64 + 0x20, 0xc);
        }
        castSlot = B + (u8)r24 * 0x68 + 0x1170;
        *(u8*)(castSlot + 0x64) = (u8)lod;
        if ((u8)r23 < 8 && *(u8*)(casterPtr + 8) != 0)
        {
            if ((u8)r23 < 3)
            {
                w = 0x100;
                f23 = CPUFifo_803DED38;
            }
            else if ((u8)r23 < 5)
            {
                w = 0x80;
                f23 = GPFifo_803DED3C;
            }
            else
            {
                w = 0x40;
                f23 = __GXCurrentThread_803DED40;
            }
            if ((u8)r23 == 0) screenW = w << 1;
            else screenW = w;
            if (*(u8*)(casterPtr + 8) == 2)
            {
                screenW = *(u16*)((char*)((int*)obj[0x64 / 4])[1] + 0xa);
            }
            fn_8008923C(obj, vA, vAp1, vAp2);
            dot24[0] = -((ObjModelState*)of64)->shadowOffsetX;
            dot24[1] = -((ObjModelState*)of64)->shadowOffsetY;
            dot24[2] = -((ObjModelState*)of64)->shadowOffsetZ;
            {
                f32 dot = PSVECDotProduct(dot24, vA);
                if (dot < lbl_803DED2C && dot > CPGPLinked_803DED44)
                {
                    f32 mag;
                    proj[0] = GXOverflowSuspendInProgress_803DED48 * dot24[0] + BreakPointCB_803DED4C * vA[0];
                    proj[1] = GXOverflowSuspendInProgress_803DED48 * dot24[1] + BreakPointCB_803DED4C * vA[1];
                    proj[2] = GXOverflowSuspendInProgress_803DED48 * dot24[2] + BreakPointCB_803DED4C * vA[2];
                    mag = PSVECMag(proj);
                    if (mag > lbl_803DED28)
                    {
                        PSVECScale(proj, vA, lbl_803DED2C / mag);
                    }
                }
            }
            if (vA[1] > __GXOverflowCount_803DED50)
            {
                vA[1] = __GXOverflowCount_803DED50;
                PSVECNormalize(vA, vA);
            }
            f22 = vA[0];
            dirX = -f22;
            vAy = vA[1];
            dirY = -vAy;
            f21 = vA[2];
            dirZ = -f21;
            lbl_803DCF84 = (u16)getAngle(dirX, f21);
            lbl_803DCF88 = getAngle(sqrtf(f22 * f22 + f21 * f21), vAy) - 0x3fc8;
            ((GameObject*)slot)->anim.rotY = (s16)lbl_803DCF88;
            ((GameObject*)slot)->anim.rotX = (s16)lbl_803DCF84;
            {
                f32 mag = sqrtf(dirX * dirX + dirY * dirY + dirZ * dirZ);
                if (mag > lbl_803DED28)
                {
                    f32 inv = (&FinishQueue_803DED64)[1] / mag;
                    dirX *= inv;
                    dirY *= inv;
                    dirZ *= inv;
                }
            }
            *(int*)((char*)slot + 0x40) = 0;
            ((ObjModelState*)of64)->shadowOffsetX = -vA[0];
            ((ObjModelState*)of64)->shadowOffsetY = -vA[1];
            ((ObjModelState*)of64)->shadowOffsetZ = -vA[2];
            setScreenWidth(screenW);
            {
                f32* m = ObjModel_GetJointMatrix(Obj_GetActiveModel(obj), 0);
                ((GameObject*)slot)->anim.localPosX = dirX + m[3];
                ((GameObject*)slot)->anim.localPosY = dirY + m[7];
                ((GameObject*)slot)->anim.localPosZ = dirZ + m[11];
            }
            if (*(u32*)&((GameObject*)obj)->anim.parent == 0)
            {
                ((GameObject*)slot)->anim.localPosX += lbl_803DCED0;
                ((GameObject*)slot)->anim.localPosZ += lbl_803DCECC;
            }
            f21 = *(f32*)of64;
            f22 = -f21;
            if (*(u32*)&((GameObject*)obj)->anim.parent != 0)
            {
                ((GameObject*)slot)->anim.localPosX += playerMapOffsetX;
                ((GameObject*)slot)->anim.localPosZ += playerMapOffsetZ;
            }
            GXSetScissor(2, 2, screenW - 4, screenW - 4);
            GXSetViewport(lbl_803DED28, lbl_803DED28, (f32)(u32)screenW, (f32)(u32)screenW, lbl_803DED28, lbl_803DED2C);
            C_MTXOrtho(mOrtho, f22, f21, f22, f21, lbl_803DED2C, (&FinishQueue_803DED64)[2]);
            GXSetProjection(mOrtho, 1);
            Camera_UpdateViewMatrices();
            C_MTXLightOrtho((f32*)castSlot, f21, f22, f22, f21, f23, f23, f23, f23);
            {
                f32* vm = Camera_GetViewMatrix();
                PSMTXCopy(vm, (f32*)(castSlot + 0x30));
                PSMTXConcat((f32*)castSlot, vm, (f32*)castSlot);
                ((ObjModelState*)of64)->shadowCastSlot = castSlot;
                {
                    char* texSlot = B + (u8)r23 * 4 + 0x3a10;
                    *(int*)(castSlot + 0x60) = *(int*)texSlot;
                    *(u8*)(castSlot + 0x65) = lbl_803DB668[(u8)r23];
                    objRenderShadowIfVisible(obj, 0, 0, 0, 0, 0);
                    if (*(u8*)(casterPtr + 8) == 2)
                    {
                        gxSetZMode_(1, 3, 1);
                        PSMTXScale((f32*)(castSlot + 0x30), lbl_803DED28, lbl_803DED28, lbl_803DED28);
                        *(f32*)(castSlot + 0x38) = lbl_803DED70;
                        *(f32*)(castSlot + 0x3c) = lbl_803DED74;
                        *(f32*)(castSlot + 0x5c) = lbl_803DED2C;
                        PSMTXConcat((f32*)(castSlot + 0x30), vm, (f32*)(castSlot + 0x30));
                        GXSetTexCopySrc(0, 0, screenW, screenW);
                        GXSetTexCopyDst(screenW, screenW, 0x11, 0);
                        GXSetCopyFilter(0, (void*)(lbl_803DCCF0 + 0x1a), 0, (void*)(lbl_803DCCF0 + 0x32));
                        GXCopyTex((void*)(*(int*)((char*)obj[0x64 / 4] + 4) + 0x60), 1);
                        setDisplayCopyFilter();
                        *(int*)(castSlot + 0x60) = *(int*)((char*)obj[0x64 / 4] + 4);
                    }
                    else
                    {
                        if ((u8)r23 == 0)
                        {
                            gxSetZMode_(1, 3, 1);
                            GXSetTexCopySrc(0, 0, screenW, screenW);
                            GXSetTexCopyDst(w, w, 0x20, 1);
                            GXCopyTex((void*)(*(int*)texSlot + 0x60), 1);
                            *(int*)(castSlot + 0x60) = *(int*)texSlot;
                        }
                        r23++;
                    }
                }
            }
        }
        else
        {
            f32 fx, fz;
            *(int*)(castSlot + 0x60) = *(int*)((char*)obj[0x64 / 4] + 4);
            fx = ((GameObject*)obj)->anim.localPosX;
            fz = ((GameObject*)obj)->anim.localPosZ;
            if (*(u32*)&((GameObject*)obj)->anim.parent == 0)
            {
                fx -= playerMapOffsetX;
                fz -= playerMapOffsetZ;
            }
            PSMTXTrans(mTrans, -fx, -((GameObject*)obj)->anim.localPosY, -fz);
            {
                f32 s = CPUFifo_803DED38 / *(f32*)of64;
                mScale[0] = s;
                mScale[1] = 0.0f;
                mScale[2] = 0.0f;
                mScale[3] = CPUFifo_803DED38;
                mScale[4] = 0.0f;
                mScale[5] = 0.0f;
                mScale[6] = s;
                mScale[7] = CPUFifo_803DED38;
                mScale[8] = 0.0f;
                mScale[9] = 0.0f;
                mScale[10] = 0.0f;
                mScale[11] = 1.0f;
            }
            PSMTXConcat(mScale, mTrans, (f32*)castSlot);
            ((ObjModelState*)of64)->shadowOffsetX = v30[0];
            ((ObjModelState*)of64)->shadowOffsetY = v30[1];
            ((ObjModelState*)of64)->shadowOffsetZ = v30[2];
            ((ObjModelState*)of64)->shadowCastSlot = castSlot;
        }
        r24++;
        if ((*(int*)&((ObjModelState*)of64)->flags & 0x20) != 0)
        {
            memcpy((char*)obj + 0xc, mc48, 0xc);
            memcpy((char*)obj + 0x18, mc54p, 0xc);
        }
    }
    if ((u8)r23 > 1)
    {
        gxSetZMode_(1, 3, 1);
        GXSetCopyFilter(0, (void*)(lbl_803DCCF0 + 0x1a), 0, (void*)(lbl_803DCCF0 + 0x32));
        GXSetTexCopySrc(0, 0, 0x100, 0x100);
        GXSetTexCopyDst(0x100, 0x100, 0x28, 0);
        GXCopyTex((void*)(*(int*)(B + 0x3a14) + 0x60), 1);
        GXPixModeSync();
        setDisplayCopyFilter();
    }
    clearScreenWidth();
    ((GameObject*)slot)->anim.localPosX = sCamX;
    ((GameObject*)slot)->anim.localPosY = sCamY;
    ((GameObject*)slot)->anim.localPosZ = sCamZ;
    ((GameObject*)slot)->anim.rotY = s170;
    ((GameObject*)slot)->anim.rotX = s14;
    ((GameObject*)slot)->anim.rotZ = s19;
    if (getDrawDistanceFlag_8005cd48() != 0)
    {
        Camera_SetCurrentViewIndex(0);
        Camera_SetFovY(savedFovY);
        if (isWidescreen() != 0) Camera_SetAspectRatio(lbl_803DED78);
        else Camera_SetAspectRatio(lbl_803DED7C);
        Camera_UpdateProjection(0, 0);
    }
    else if (isWidescreen() != 0)
    {
        Camera_SetCurrentViewIndex(0);
        Camera_SetFovY(savedFovY);
        Camera_SetAspectRatio(Ydchuff_803DED80[0]);
        Camera_UpdateProjection(0, 0);
    }
    else
    {
        Camera_SetCurrentViewIndex(0);
        Camera_SetFovY(savedFovY);
        Camera_SetAspectRatio(lbl_803DB670);
        Camera_UpdateProjection(0, 0);
    }
    Camera_UpdateViewMatrices();
    Camera_RebuildProjectionMatrix();
    Camera_ApplyFullViewport();
    Camera_EnableViewYOffset();
}
