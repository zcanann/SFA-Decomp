#include "main/game_object.h"
#include "main/texture.h"
#include "dolphin/os/OSCache.h"
#include "dolphin/gx/GXManage.h"
#include "main/camera.h"
#include "main/sfa_extern_decls.h"
#include "main/dll/DR/dll_80209FE0_shared.h"
#define NEW_SHADOW_MAX_CASTERS 100
extern u32 FUN_800033a8();
extern u32 FUN_80003494();
extern u32 FUN_8000693c();
extern u32 FUN_8000694c();
extern u32 FUN_80006954();
extern u32 FUN_80006974();
extern void* FUN_8000697c();
extern u32 FUN_80006984();
extern u32 FUN_80006988();
extern void* FUN_800069a8();
extern u32 FUN_800069b8();
extern u32 FUN_800069bc();
extern u32 FUN_800069d4();
extern u32 FUN_800069f4();
extern double FUN_800069f8();
extern u32 FUN_80006a00();
extern int FUN_800176d0();
extern u32 FUN_80017730();

extern u32 FUN_80017814();
extern int FUN_80017970();
extern u32 FUN_80017a50();
extern int FUN_80017a54();
extern u32 FUN_8003b7dc();
extern u32 FUN_8003b878();
extern u32 FUN_80040cd0();
extern u32 FUN_80045be8();
extern u32 FUN_80048048();
extern char FUN_80048094();
extern int FUN_800537a0();
extern u32 FUN_8005d00c();
extern u32 FUN_8005d06c();
extern u32 FUN_800606a4();
extern u32 FUN_800606a8();
extern u32 FUN_80060710();
extern u16 FUN_80061198();
extern u32 FUN_80064384();
extern u32 objAudioFn_8006ef38();
extern u32 FUN_8006f788();
extern u32 FUN_8006f790();
extern void gxSetZMode_(u32 compareEnable, int compareFunc, u32 updateEnable);
extern u32 FUN_800709e8();
extern u32 FUN_80080f6c();
extern u32 FUN_802420e0();
extern u32 FUN_802475e4();
extern u32 FUN_80247618();
extern u32 FUN_80247a48();
extern u32 FUN_80247a7c();
extern u32 FUN_80247b70();
extern u32 FUN_80247dfc();
extern u32 FUN_80247edc();
extern u32 FUN_80247ef8();

extern double FUN_80247f90();
extern u32 FUN_80258c24();
extern u32 FUN_80259400();
extern u32 FUN_80259504();
extern u32 FUN_80259858();
extern u32 FUN_80259c0c();
extern u32 FUN_8025aeac();
extern u32 FUN_8025b054();
extern u32 FUN_8025b210();
extern u32 FUN_8025b280();
extern u32 FUN_8025d6ac();
extern u32 FUN_8025da64();
extern u32 FUN_8025da88();
extern u32 FUN_8028680c();
extern u64 FUN_80286840();
extern u32 FUN_80286858();
extern u32 FUN_8028688c();
extern u32 FUN_802947f8();
extern u32 SQRT();
extern u32 DAT_8038ee3c;
extern u32 DAT_8038ee48;
extern int DAT_8038eec8;
extern int DAT_8038ef08;
extern u32 DAT_8038ef0c;
extern u32 DAT_8038ef10;
extern u32 DAT_8038fd18;
extern u32 DAT_8038fd48;
extern u32 DAT_8038fd50;
extern u32 DAT_8038fd54;
extern u32 DAT_8038fd74;
extern u32 DAT_8038fd78;
extern u32 DAT_8038fd7c;
extern u32 DAT_8038fd7d;
extern int DAT_803925b8;
extern u32 DAT_803925bc;
extern u32 DAT_803dc070;
extern u32 DAT_803dc2c8;
extern u32 DAT_803dd970;
extern u32 DAT_803ddbf8;
extern u32 DAT_803ddbfc;
extern u32 DAT_803ddc00;
extern u32 DAT_803ddc04;
extern u32 DAT_803ddc08;
extern u32 DAT_803ddc0c;
extern u32 DAT_803ddc10;
extern u32 DAT_803ddc18;
extern u32 DAT_803ddc1c;
extern u32 DAT_803ddc20;
extern u32 DAT_803ddc30;
extern u32 DAT_803ddc38;
extern u32 DAT_803ddc3c;
extern u32 DAT_803ddc40;
extern u32 DAT_803ddc54;
extern u32 DAT_803ddc58;
extern u32 DAT_803ddc5c;
extern u32 DAT_803ddc60;
extern u32 DAT_803ddc64;
extern u32 DAT_803ddc68;
extern f64 DOUBLE_803df9d8;
extern f64 DOUBLE_803df9e0;
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
                sum -= row[k];
                sum += (row + window)[k];
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
                    sum -= row[k];
                    sum += (row + window)[k];
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
                sum -= row[k];
                sum += (row + window)[k];
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
                    sum -= row[k];
                    sum += (row + window)[k];
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

#pragma scheduling on
#pragma peephole on
void newshadows_captureProjectedShadow(u16* object)
{
    float maxScale;
    int renderState;
    float* shadowSlot;
    double tmpY;
    double savedScale;
    double tmpX;
    double invScale;
    double dirY;
    float projW;
    float scaleY;
    float scaleX;
    float projZ;
    float projY;
    float projX;
    float mtx[15];

    FUN_80017a50(object, mtx, '\0');
    FUN_8000693c((double)(((GameObject*)object)->anim.localPosX - lbl_803DDA58),
                 (double)((GameObject*)object)->anim.localPosY,
                 (double)(((GameObject*)object)->anim.localPosZ - lbl_803DDA5C),
                 (double)(lbl_803DF98C * ((GameObject*)object)->anim.hitboxScale *
                     ((GameObject*)object)->anim.rootMotionScale),
                 &projX, &projY, &projZ, &scaleX, &scaleY, &projW);
    scaleX = lbl_803DF994 * scaleX + lbl_803DF990;
    scaleY = lbl_803DF998 * scaleY + lbl_803DF990;
    maxScale = scaleY;
    if (scaleY < scaleX)
    {
        maxScale = scaleX;
    }
    invScale = (double)(lbl_803DF99C / maxScale);
    tmpX = (double)(float)((double)((GameObject*)object)->anim.rootMotionScale * invScale);
    tmpY = -(double)projX;
    dirY = (double)projY;
    FUN_8025da64((double)(float)((double)lbl_803DF994 * tmpY),
                 (double)(float)((double)lbl_803DF998 * dirY), (double)lbl_803DF9A0,
                 (double)lbl_803DF9A4, (double)lbl_803DF9A8, (double)lbl_803DF9AC);
    if (lbl_803DF9A8 <= projZ)
    {
        **(float**)(object + 0x32) = lbl_803DF9A8;
    }
    else
    {
        savedScale = (double)((GameObject*)object)->anim.rootMotionScale;
        ((GameObject*)object)->anim.rootMotionScale = (float)tmpX;
        FUN_80040cd0(1);
        FUN_8003b878(0, 0, 0, 0, object, 1);
        FUN_80040cd0(0);
        ((GameObject*)object)->anim.rootMotionScale = (float)savedScale;
        renderState = FUN_80017a54((int)object);
        *(u16*)(renderState + 0x18) = *(u16*)(renderState + 0x18) & ~0x8;
        gxSetZMode_(1, GX_LEQUAL, 1);
        FUN_80259400(0x100, 0xb0, 0x80, 0x80);
        FUN_80259504(0x80, 0x80, 0x2a, 0);
        FUN_80259c0c((&DAT_8038ee3c)[DAT_803ddc0c] + 0x60, 1);
        fn_8006A028((u8*)(&DAT_8038ee3c)[(DAT_803ddc0c + 1) % 3], 0x80, 0x10, 0);
        **(float**)(object + 0x32) = (float)((double)lbl_803DF9AC / invScale);
    }
    FUN_80006988();
    tmpX = (double)lbl_803DF994;
    *(float*)(*(int*)&((GameObject*)object)->anim.modelState + 0x14) = (float)(tmpX * -tmpY);
    tmpY = (double)lbl_803DF998;
    *(float*)(*(int*)&((GameObject*)object)->anim.modelState + 0x18) = (float)(tmpY * -dirY);
    *(float*)(*(int*)&((GameObject*)object)->anim.modelState + 0x14) =
        (float)((double)*(float*)(*(int*)&((GameObject*)object)->anim.modelState + 0x14) + tmpX);
    *(float*)(*(int*)&((GameObject*)object)->anim.modelState + 0x18) =
        (float)((double)*(float*)(*(int*)&((GameObject*)object)->anim.modelState + 0x18) + tmpY);
    maxScale = lbl_803DF99C;
    shadowSlot = *(float**)(object + 0x32);
    shadowSlot[5] = -(lbl_803DF99C * *shadowSlot - shadowSlot[5]);
    shadowSlot = *(float**)(object + 0x32);
    shadowSlot[6] = -(maxScale * *shadowSlot - shadowSlot[6]);
    return;
}

void newshadows_sortQueuedShadowCasters(int queueBase, int casterCount)
{
    int remaining;
    float tmpKey;
    u32 tmpWord2;
    u32 cmpKey;
    int gap;
    u32 tmpWord0;
    int destPtr;
    u32* slot;
    int iOff;
    int curPtr;
    int cmpPtr;
    int j;
    int i;

    remaining = (casterCount + -1) / 9 + (casterCount + -1 >> 0x1f);
    for (gap = 1; gap <= remaining - (remaining >> 0x1f); gap = gap * 3 + 1)
    {
    }
    for (; 0 < gap; gap = gap / 3)
    {
        i = gap + 1;
        iOff = i * 0xc;
        curPtr = queueBase + iOff;
        remaining = (casterCount + 1) - i;
        if (i <= casterCount)
        {
            do
            {
                tmpWord0 = *(u32*)(curPtr + -0xc);
                tmpKey = *(float*)(curPtr + -8);
                tmpWord2 = *(u32*)(curPtr + -4);
                destPtr = queueBase + iOff;
                j = i;
                while ((gap < j &&
                    (cmpPtr = queueBase + (j - gap) * 0xc, *(float*)(cmpPtr + -8) < tmpKey)))
                {
                    cmpKey = *(u32*)(cmpPtr + -8);
                    *(u32*)(destPtr + -0xc) = *(u32*)(cmpPtr + -0xc);
                    *(u32*)(destPtr + -8) = cmpKey;
                    *(u32*)(destPtr + -4) = *(u32*)(cmpPtr + -4);
                    destPtr = destPtr + gap * -0xc;
                    j = j - gap;
                }
                slot = (u32*)(queueBase + j * 0xc + -0xc);
                *slot = tmpWord0;
                slot[1] = tmpKey;
                slot[2] = tmpWord2;
                curPtr = curPtr + 0xc;
                i = i + 1;
                iOff = iOff + 0xc;
                remaining = remaining + -1;
            }
            while (remaining != 0);
        }
    }
    return;
}

void newshadows_renderQueuedShadowCasters(void)
{
    u16 savedWord0;
    u16 savedWord2;
    u32 slotByte;
    int slotOff;
    u16* light;
    u16 visibility;
    u32 randVal;
    int* entryPtr;
    int pivot;
    float* viewMtx;
    float* shadowMtx;
    float* model;
    int obj;
    u32 baseTexSize;
    u32 texSize;
    char casterIdx;
    u8 dirShadowCount;
    u32 shadowSlot;
    int* queueEntry;
    double invSqrt;
    double savedZParam;
    double dVar22;
    double savedF21;
    double savedF22;
    double savedF23;
    double dVar23;
    double savedF24;
    double savedF25;
    double savedLightZ;
    double savedF26;
    double savedLightY;
    double savedF27;
    double savedLightX;
    double savedF28;
    double dVar27;
    double savedF29;
    double savedF30;
    double dVar28;
    double savedF31;
    double dVar29;
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
    u32 uStack_260;
    u32 uStack_25c;
    float blendX;
    float blendY;
    float blendZ;
    float objDirX;
    float objDirY;
    float objDirZ;
    float defaultDirX;
    float defaultDirY;
    float defaultDirZ;
    float dirX;
    float dirY;
    float dirZ;
    u8 savedRow0[12];
    u8 savedRow1[12];
    float projMtx[16];
    float scaleMtx0;
    float scaleMtx1;
    float scaleMtx2;
    float scaleMtx3;
    float scaleMtx4;
    float scaleMtx5;
    float scaleMtx6;
    float scaleMtx7;
    float scaleMtx8;
    float scaleMtx9;
    float scaleMtx10;
    float scaleMtx11;
    float transMtx[12];
    float lightMtx[24];
    u32 local_110;
    u32 uStack_10c;
    u32 local_108;
    u32 uStack_104;
    int savedFlag;
    float local_a8;
    float fStack_a4;
    float local_98;
    float fStack_94;
    float spillF23;
    float fStack_84;
    float spillF24;
    float fStack_74;
    float spillF25;
    float fStack_64;
    float spillF26;
    float fStack_54;
    float spillF27;
    float fStack_44;
    float spillF28;
    float fStack_34;
    float spillF29;
    float fStack_24;
    float spillF30;
    float fStack_14;
    float spillF31;
    float fStack_4;

    spillF31 = (float)savedF31;
    fStack_4 = (float)savedPs31;
    spillF30 = (float)savedF30;
    fStack_14 = (float)savedPs30;
    spillF29 = (float)savedF29;
    fStack_24 = (float)savedPs29;
    spillF28 = (float)savedF28;
    fStack_34 = (float)savedPs28;
    spillF27 = (float)savedF27;
    fStack_44 = (float)savedPs27;
    spillF26 = (float)savedF26;
    fStack_54 = (float)savedPs26;
    spillF25 = (float)savedF25;
    fStack_64 = (float)savedPs25;
    spillF24 = (float)savedF24;
    fStack_74 = (float)savedPs24;
    spillF23 = (float)savedF23;
    fStack_84 = (float)savedPs23;
    local_98 = (float)savedF22;
    fStack_94 = (float)savedPs22;
    local_a8 = (float)savedF21;
    fStack_a4 = (float)savedPs21;
    FUN_8028680c();
    if (DAT_803ddbf8 != 0)
    {
        FUN_800069b8();
        newshadows_sortQueuedShadowCasters(-0x7fc710f8, DAT_803ddbf8);
        FUN_80006954(1);
        light = FUN_800069a8();
        savedZParam = FUN_800069f8();
        FUN_80006a00((double)lbl_803DF9B0);
        FUN_800069f4((double)lbl_803DF9AC);
        savedLightX = (double)*(float*)(light + 6);
        savedLightY = (double)*(float*)(light + 8);
        savedLightZ = (double)*(float*)(light + 10);
        savedFlag = (int)(short)light[1];
        savedWord0 = *light;
        savedWord2 = light[2];
        light[1] = 0;
        defaultDirX = lbl_803DF9A8;
        defaultDirY = lbl_803DF9AC;
        defaultDirZ = lbl_803DF9A8;
        FUN_80060710((double)lbl_803DF9B4, &defaultDirX, lightMtx);
        FUN_800606a4(&uStack_25c, &uStack_260);
        dirShadowCount = 0;
        shadowSlot = 0;
        queueEntry = &DAT_8038ef08;
        for (casterIdx = '\0'; ((int)casterIdx < (int)(u32)DAT_803ddbf8 && (casterIdx < NEW_SHADOW_MAX_CASTERS));
             casterIdx = casterIdx + '\x01')
        {
            obj = *queueEntry;
            model = (float*)((GameObject*)obj)->anim.modelState;
            FUN_80006954(0);
            visibility = FUN_80061198(obj, DAT_803dc070);
            FUN_80006954(1);
            if (4 < (visibility & 0xff))
            {
                if ((((ObjModelState*)model)->flags & 0x20) != 0)
                {
                    FUN_80003494((u32)savedRow0, obj + 0xc, 0xc);
                    FUN_80003494((u32)savedRow1, obj + 0x18, 0xc);
                    FUN_80003494(obj + 0xc, (u32)(model + 8), 0xc);
                    FUN_80003494(obj + 0x18, (u32)(model + 8), 0xc);
                }
                slotByte = shadowSlot & 0xff;
                slotOff = slotByte * 0x68;
                shadowMtx = (float*)(&DAT_8038fd18 + slotOff);
                (&DAT_8038fd7c)[slotOff] = visibility;
                if ((dirShadowCount < 8) && (*(char*)(queueEntry + 2) != '\0'))
                {
                    if (dirShadowCount < 3)
                    {
                        baseTexSize = 0x100;
                        dVar23 = (double)lbl_803DF9B8;
                    }
                    else if (dirShadowCount < 5)
                    {
                        baseTexSize = 0x80;
                        dVar23 = (double)lbl_803DF9BC;
                    }
                    else
                    {
                        baseTexSize = 0x40;
                        dVar23 = (double)lbl_803DF9C0;
                    }
                    texSize = baseTexSize;
                    if (dirShadowCount == 0)
                    {
                        texSize = baseTexSize << 1;
                    }
                    if (*(char*)(queueEntry + 2) == '\x02')
                    {
                        texSize = (u32) * (u16*)(*(int*)(*(int*)&((GameObject*)obj)->anim.modelState + 4) + 10);
                        baseTexSize = texSize;
                    }
                    FUN_80080f6c(obj, &dirX, &dirY, &dirZ);
                    objDirX = -model[5];
                    objDirY = -model[6];
                    objDirZ = -model[7];
                    dVar22 = FUN_80247f90(&objDirX, &dirX);
                    if ((dVar22 < (double)lbl_803DF9AC) && ((double)lbl_803DF9C4 < dVar22))
                    {
                        blendX = lbl_803DF9C8 * objDirX + lbl_803DF9CC * dirX;
                        blendY = lbl_803DF9C8 * objDirY + lbl_803DF9CC * dirY;
                        blendZ = lbl_803DF9C8 * objDirZ + lbl_803DF9CC * dirZ;
                        dVar22 = SeekTwiceBeforeRead(&blendX);
                        if ((double)lbl_803DF9A8 < dVar22)
                        {
                            FUN_80247edc((double)(float)((double)lbl_803DF9AC / dVar22), &blendX, &dirX);
                        }
                    }
                    if (lbl_803DF9D0 < dirY)
                    {
                        dirY = lbl_803DF9D0;
                        FUN_80247ef8(&dirX, &dirX);
                    }
                    dVar27 = -(double)dirX;
                    dVar29 = -(double)dirY;
                    dVar28 = -(double)dirZ;
                    randVal = FUN_80017730();
                    DAT_803ddc04 = randVal & 0xffff;
                    randVal = FUN_80017730();
                    DAT_803ddc08 = (randVal & 0xffff) - 0x3fc8;
                    light[1] = DAT_803ddc08;
                    *light = DAT_803ddc04;
                    dVar22 = (double)(float)(dVar28 * dVar28 +
                        (double)(float)(dVar27 * dVar27 + (double)(float)(dVar29 * dVar29)
                        ));
                    if ((double)lbl_803DF9A8 < dVar22)
                    {
                        invSqrt = 1.0 / SQRT(dVar22);
                        invSqrt = DOUBLE_803df9d8 * invSqrt * -(dVar22 * invSqrt * invSqrt - DOUBLE_803df9e0);
                        invSqrt = DOUBLE_803df9d8 * invSqrt * -(dVar22 * invSqrt * invSqrt - DOUBLE_803df9e0);
                        dVar22 = (double)(float)(dVar22 * DOUBLE_803df9d8 * invSqrt *
                            -(dVar22 * invSqrt * invSqrt - DOUBLE_803df9e0));
                    }
                    if ((double)lbl_803DF9A8 < dVar22)
                    {
                        dVar22 = (double)(float)((double)lbl_803DF9E8 / dVar22);
                        dVar27 = (double)(float)(dVar27 * dVar22);
                        dVar29 = (double)(float)(dVar29 * dVar22);
                        dVar28 = (double)(float)(dVar28 * dVar22);
                    }
                    *(u32*)(light + 0x20) = 0;
                    model[5] = -dirX;
                    model[6] = -dirY;
                    model[7] = -dirZ;
                    FUN_8006f788(texSize);
                    entryPtr = (int*)FUN_80017a54(obj);
                    pivot = FUN_80017970(entryPtr, 0);
                    *(float*)(light + 6) = (float)(dVar27 + (double)*(float*)(pivot + 0xc));
                    *(float*)(light + 8) = (float)(dVar29 + (double)*(float*)(pivot + 0x1c));
                    *(float*)(light + 10) = (float)(dVar28 + (double)*(float*)(pivot + 0x2c));
                    if (*(int*)&((GameObject*)obj)->anim.parent == 0)
                    {
                        *(float*)(light + 6) = *(float*)(light + 6) + lbl_803DDB50;
                        *(float*)(light + 10) = *(float*)(light + 10) + lbl_803DDB4C;
                    }
                    dVar22 = (double)*model;
                    dVar27 = -dVar22;
                    if (*(int*)&((GameObject*)obj)->anim.parent != 0)
                    {
                        *(float*)(light + 6) = *(float*)(light + 6) + lbl_803DDA58;
                        *(float*)(light + 10) = *(float*)(light + 10) + lbl_803DDA5C;
                    }
                    FUN_8025da88(2, 2, texSize - 4, texSize - 4);
                    dVar28 = (double)lbl_803DF9A8;
                    local_110 = 0x43300000;
                    local_108 = 0x43300000;
                    uStack_10c = texSize;
                    uStack_104 = texSize;
                    FUN_8025da64(dVar28, dVar28,
                                 (double)(float)((double)(u32)texSize),
                                 (double)(float)((double)(u32)texSize), dVar28
                                 , (double)lbl_803DF9AC);
                    FUN_80247dfc(dVar27, dVar22, dVar27, dVar22, (double)lbl_803DF9AC, (double)lbl_803DF9EC,
                                 projMtx);
                    FUN_8025d6ac(projMtx, 1);
                    FUN_80006984();
                    FUN_80247b70(dVar22, dVar27, dVar27, dVar22, dVar23, dVar23, dVar23, dVar23, shadowMtx);
                    viewMtx = (float*)FUN_80006974();
                    FUN_802475e4(viewMtx, (float*)(&DAT_8038fd48 + slotOff));
                    FUN_80247618(shadowMtx, viewMtx, shadowMtx);
                    ((ObjModelState*)model)->shadowCastSlot = shadowMtx;
                    entryPtr = &DAT_803925b8 + dirShadowCount;
                    (&DAT_8038fd78)[slotByte * 0x1a] = *entryPtr;
                    (&DAT_8038fd7d)[slotOff] = (&DAT_803dc2c8)[dirShadowCount];
                    FUN_8003b7dc(obj);
                    if (*(char*)(queueEntry + 2) == '\x02')
                    {
                        gxSetZMode_(1, GX_LEQUAL, 1);
                        dVar23 = (double)lbl_803DF9A8;
                        FUN_80247a7c(dVar23, dVar23, dVar23, (float*)(&DAT_8038fd48 + slotOff));
                        (&DAT_8038fd50)[slotByte * 0x1a] = lbl_803DF9F0;
                        (&DAT_8038fd54)[slotByte * 0x1a] = lbl_803DF9F4;
                        (&DAT_8038fd74)[slotByte * 0x1a] = lbl_803DF9AC;
                        FUN_80247618((float*)(&DAT_8038fd48 + slotOff), viewMtx, (float*)(&DAT_8038fd48 + slotOff));
                        FUN_80259400(0, 0, texSize, texSize);
                        FUN_80259504((u16)texSize, (u16)texSize, 0x11, 0);
                        FUN_80259858('\0', (u8*)(DAT_803dd970 + 0x1a), '\0', (u8*)(DAT_803dd970 + 0x32));
                        FUN_80259c0c(*(int*)(*(int*)&((GameObject*)obj)->anim.modelState + 4) + 0x60, 1);
                        FUN_80045be8();
                        (&DAT_8038fd78)[slotByte * 0x1a] = *(u32*)(*(int*)&((GameObject*)obj)->anim.modelState +
                            4);
                    }
                    else
                    {
                        if (dirShadowCount == 0)
                        {
                            gxSetZMode_(1, GX_LEQUAL, 1);
                            FUN_80259400(0, 0, texSize, texSize);
                            FUN_80259504((u16)baseTexSize, (u16)baseTexSize, 0x20, 1);
                            FUN_80259c0c(*entryPtr + 0x60, 1);
                            (&DAT_8038fd78)[slotByte * 0x1a] = *entryPtr;
                        }
                        dirShadowCount = dirShadowCount + 1;
                    }
                }
                else
                {
                    (&DAT_8038fd78)[slotByte * 0x1a] = *(u32*)(*(int*)&((GameObject*)obj)->anim.modelState + 4);
                    dVar23 = (double)((GameObject*)obj)->anim.localPosX;
                    dVar22 = (double)((GameObject*)obj)->anim.localPosZ;
                    if (*(int*)&((GameObject*)obj)->anim.parent == 0)
                    {
                        dVar23 = (double)(float)(dVar23 - (double)lbl_803DDA58);
                        dVar22 = (double)(float)(dVar22 - (double)lbl_803DDA5C);
                    }
                    FUN_80247a48(-dVar23, -(double)((GameObject*)obj)->anim.localPosY, -dVar22, transMtx);
                    scaleMtx0 = lbl_803DF9B8 / *model;
                    scaleMtx1 = lbl_803DF9A8;
                    scaleMtx2 = lbl_803DF9A8;
                    scaleMtx3 = lbl_803DF9B8;
                    scaleMtx4 = lbl_803DF9A8;
                    scaleMtx5 = lbl_803DF9A8;
                    scaleMtx7 = lbl_803DF9B8;
                    scaleMtx8 = lbl_803DF9A8;
                    scaleMtx9 = lbl_803DF9A8;
                    scaleMtx10 = lbl_803DF9A8;
                    scaleMtx11 = lbl_803DF9AC;
                    scaleMtx6 = scaleMtx0;
                    FUN_80247618(&scaleMtx0, transMtx, shadowMtx);
                    model[5] = defaultDirX;
                    model[6] = defaultDirY;
                    model[7] = defaultDirZ;
                    ((ObjModelState*)model)->shadowCastSlot = shadowMtx;
                }
                shadowSlot = shadowSlot + 1;
                if ((((ObjModelState*)model)->flags & 0x20) != 0)
                {
                    FUN_80003494(obj + 0xc, savedRow0, 0xc);
                    FUN_80003494(obj + 0x18, savedRow1, 0xc);
                }
            }
            queueEntry = queueEntry + 3;
        }
        if (1 < dirShadowCount)
        {
            gxSetZMode_(1, GX_LEQUAL, 1);
            FUN_80259858('\0', (u8*)(DAT_803dd970 + 0x1a), '\0', (u8*)(DAT_803dd970 + 0x32));
            FUN_80259400(0, 0, 0x100, 0x100);
            FUN_80259504(0x100, 0x100, 0x28, 0);
            FUN_80259c0c(DAT_803925bc + 0x60, 1);
            FUN_80258c24();
            FUN_80045be8();
        }
        FUN_8006f790();
        *(float*)(light + 6) = (float)savedLightX;
        *(float*)(light + 8) = (float)savedLightY;
        *(float*)(light + 10) = (float)savedLightZ;
        light[1] = savedFlag;
        *light = savedWord0;
        light[2] = savedWord2;
        shadowSlot = FUN_8005d00c();
        if (shadowSlot == 0)
        {
            shadowSlot = FUN_8005d06c();
            if (shadowSlot == 0)
            {
                FUN_80006954(0);
                FUN_80006a00(savedZParam);
                FUN_800069f4((double)lbl_803DC2D0);
                FUN_8000694c();
            }
            else
            {
                FUN_80006954(0);
                FUN_80006a00(savedZParam);
                FUN_800069f4((double)lbl_803DFA00);
                FUN_8000694c();
            }
        }
        else
        {
            FUN_80006954(0);
            FUN_80006a00(savedZParam);
            shadowSlot = FUN_8005d06c();
            if (shadowSlot == 0)
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

void newshadows_queueShadowCaster(int object)
{
    ObjAnimComponent* objAnim;
    ObjModelInstance* modelDef;
    float dx;
    float dy;
    float dz;
    int slotOff;
    double invSqrt;
    double dist;

    if (DAT_803ddbf8 < 300)
    {
        objAnim = (ObjAnimComponent*)object;
        modelDef = objAnim->modelInstance;
        (&DAT_8038ef08)[DAT_803ddbf8 * 3] = object;
        dx = ((GameObject*)object)->anim.worldPosX - *(float*)(DAT_803ddc68 + 0xc);
        dy = ((GameObject*)object)->anim.worldPosY - *(float*)(DAT_803ddc68 + 0x10);
        dz = ((GameObject*)object)->anim.worldPosZ - *(float*)(DAT_803ddc68 + 0x14);
        dist = (double)(dz * dz + dx * dx + dy * dy);
        if ((double)lbl_803DF9A8 < dist)
        {
            invSqrt = 1.0 / SQRT(dist);
            invSqrt = DOUBLE_803df9d8 * invSqrt * -(dist * invSqrt * invSqrt - DOUBLE_803df9e0);
            invSqrt = DOUBLE_803df9d8 * invSqrt * -(dist * invSqrt * invSqrt - DOUBLE_803df9e0);
            dist = (double)(float)(dist * DOUBLE_803df9d8 * invSqrt *
                -(dist * invSqrt * invSqrt - DOUBLE_803df9e0));
        }
        slotOff = DAT_803ddbf8 * 0xc;
        *(float*)(&DAT_8038ef0c + slotOff) = (float)((double)((GameObject*)object)->anim.modelState->shadowScale / dist);
        if (modelDef->shadowType == 2)
        {
            (&DAT_8038ef10)[slotOff] = 1;
            if ((modelDef->renderFlags & 4) != 0)
            {
                (&DAT_8038ef10)[slotOff] = 2;
                *(float*)(&DAT_8038ef0c + slotOff) = lbl_803DFA10;
            }
        }
        else
        {
            (&DAT_8038ef10)[slotOff] = 0;
        }
        DAT_803ddbf8 = DAT_803ddbf8 + 1;
    }
    return;
}

void newshadows_getShadowTextureTable4x8(int* tableOut, int* columnsOut, int* rowsOut)
{
    *tableOut = (int)&DAT_8038ee48;
    *columnsOut = 4;
    *rowsOut = 8;
    return;
}

void newshadows_getShadowTextureTable16(int* tableOut, int* countOut)
{
    *tableOut = (int)&DAT_8038eec8;
    *countOut = 0x10;
    return;
}

void newshadows_getShadowTexture(int* textureOut)
{
    *textureOut = DAT_803ddc30;
    return;
}

void newshadows_getBlankShadowTexture(int* textureOut)
{
    *textureOut = DAT_803ddc38;
    return;
}

void newshadows_getShadowDirectionTexture(int* textureOut)
{
    *textureOut = DAT_803ddc3c;
    return;
}

void newshadows_getSoftShadowTexture(int* textureOut)
{
    *textureOut = DAT_803ddc40;
    return;
}

void newshadows_getShadowRampTexture(int* textureOut)
{
    *textureOut = DAT_803ddc1c;
    return;
}

int newshadows_getSmallShadowTexture(void)
{
    return DAT_803ddc54;
}

void newshadows_getShadowDiskTexture(int* textureOut)
{
    *textureOut = DAT_803ddc58;
    return;
}

void newshadows_getShadowNoiseTexture(int* textureOut)
{
    *textureOut = DAT_803ddc60;
    return;
}

void FUN_8006b03c(int object, u32* groupOut, u32* scaleOut, int* offsetXOut, int* offsetYOut)
{
    ObjModelState* modelState = ((GameObject*)object)->anim.modelState;
    *groupOut = (&DAT_8038ee3c)[(DAT_803ddc0c + 1) % 3];
    *scaleOut = *(u32*)&modelState->shadowScale;
    *offsetXOut = modelState->shadowOffsetX;
    *offsetYOut = modelState->shadowOffsetY;
    return;
}

double newshadows_getShadowNoiseScale(void)
{
    return (double)lbl_803DDC24;
}

void newshadows_bindShadowRenderTexture(int textureSlot)
{
    if (((Texture*)DAT_803ddbfc)->preloaded == '\0')
    {
        FUN_8025b054((u32*)(DAT_803ddbfc + 0x20), textureSlot);
    }
    else
    {
        FUN_8025aeac((u32*)(DAT_803ddbfc + 0x20), ((Texture*)DAT_803ddbfc)->tmemAddr, textureSlot);
    }
    return;
}

int newshadows_getShadowRenderTexture(void)
{
    return DAT_803ddbfc;
}

int newshadows_getInverseShadowRampTexture(void)
{
    return DAT_803ddc18;
}

int newshadows_getRadialFalloffTexture(void)
{
    return DAT_803ddc10;
}

void newshadows_bindShadowCaptureTexture(int textureSlot)
{
    if (((Texture*)DAT_803ddc64)->preloaded == '\0')
    {
        FUN_8025b054((u32*)(DAT_803ddc64 + 0x20), textureSlot);
    }
    else
    {
        FUN_8025aeac((u32*)(DAT_803ddc64 + 0x20), ((Texture*)DAT_803ddc64)->tmemAddr, textureSlot);
    }
    return;
}

void newshadows_refreshShadowCaptureTexture(void)
{
    FUN_800709e8((double)lbl_803DF9A8, (double)lbl_803DF9A8, DAT_803ddbfc, 0xff, 0x40);
    FUN_80259400(0, 0, 0x50, 0x3c);
    FUN_80259504(0x50, 0x3c, 4, 0);
    FUN_80259c0c(DAT_803ddc64 + 0x60, 1);
    if (((Texture*)DAT_803ddc64)->preloaded != '\0')
    {
        FUN_8025b280(DAT_803ddc64 + 0x20, ((Texture*)DAT_803ddc64)->tmemAddr);
    }
    return;
}

void newshadows_flushShadowRenderTargets(void)
{
    FUN_80259400(0, 0, 0x280, 0x1e0);
    FUN_80259504(0x140, 0xf0, 4, 1);
    FUN_80259c0c(DAT_803ddbfc + 0x60, 0);
    FUN_80259400(0, 0, 0x280, 0x1e0);
    FUN_80259504(0x140, 0xf0, 0x11, 1);
    FUN_80259c0c(DAT_803ddc5c + 0x60, 0);
    if (((Texture*)DAT_803ddbfc)->preloaded != '\0')
    {
        FUN_8025b280(DAT_803ddbfc + 0x20, ((Texture*)DAT_803ddbfc)->tmemAddr);
    }
    if (((Texture*)DAT_803ddc5c)->preloaded != '\0')
    {
        FUN_8025b280(DAT_803ddc5c + 0x20, ((Texture*)DAT_803ddc5c)->tmemAddr);
    }
    if ((((Texture*)DAT_803ddbfc)->preloaded == '\0') || (((Texture*)DAT_803ddc5c)->preloaded == '\0'))
    {
        FUN_8025b210();
    }
    FUN_80258c24();
    return;
}

void newshadows_updateFrameState(void)
{
    u32 texSize;
    int scrollDisabled;
    char shadowMapEnabled;
    u8* view;
    double depth;
    double savedF31;
    double focusDepth;
    double savedPs31;
    float nearDepth;
    float farDepth;
    u64 local_20;
    float local_8;
    float fStack_4;

    local_8 = (float)savedF31;
    fStack_4 = (float)savedPs31;
    scrollDisabled = FUN_800176d0();
    if (scrollDisabled == 0)
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
    DAT_803ddc20 = DAT_803ddc20 + (u16)DAT_803dc070 * 0x28a;
    local_20 = ((u64)(((u64)(u32)(0x43300000) << 32) | (u32)(DAT_803ddc20)));
    depth = (double)FUN_802947f8();
    lbl_803DDC24 = (float)((double)lbl_803DFA20 * depth);
    FUN_800606a8();
    DAT_803ddc0c = (char)(DAT_803ddc0c + 1) + (char)((DAT_803ddc0c + 1) / 3) * -3;
    shadowMapEnabled = FUN_80048094();
    if (shadowMapEnabled != '\0')
    {
        view = FUN_8000697c();
        focusDepth = (double)*(float*)(view + 0x1c);
        FUN_80048048(&farDepth, &nearDepth);
        depth = (double)farDepth;
        if (focusDepth < depth)
        {
            if ((double)nearDepth < focusDepth)
            {
                texSize = (u32)((lbl_803DF99C * (float)(depth - focusDepth)) / (float)(depth - (double)nearDepth));
                local_20 = (s64)(int)
                texSize;
            }
            else
            {
                texSize = 0x40;
            }
        }
        else
        {
            texSize = 0;
        }
        if ((texSize & 0xff) != DAT_803ddc00)
        {
            FUN_80064384(texSize & 0xff);
        }
    }
    return;
}

void newshadows_getShadowNoiseScroll(float* xOffsetOut, float* yOffsetOut)
{
    *xOffsetOut = lbl_803DDC2C;
    *yOffsetOut = lbl_803DDC28;
    return;
}

void newshadows_freeShadowDirectionTexture(void)
{
    FUN_80017814(DAT_803ddc3c);
    DAT_803ddc3c = 0;
    return;
}

void newshadows_buildShadowDirectionTexture(void)
{
    float intensity;
    float centerOffset;
    float encodeBias;
    float encodeScale;
    double convBiasConst;
    u32 y;
    u32 x;
    int xCount;
    double dy;
    double dx;
    double invSqrt;
    double falloffLimit;
    double epsilon;
    double len;
    u64 convBias;

    DAT_803ddc3c = FUN_800537a0(0x100, 0x100, 3, '\0', 0, 0, 0, 1, 1);
    convBiasConst = DOUBLE_803dfa48;
    encodeScale = lbl_803DFA40;
    encodeBias = lbl_803DFA3C;
    centerOffset = lbl_803DFA2C;
    y = 0;
    epsilon = (double)lbl_803DF9A8;
    falloffLimit = (double)lbl_803DFA38;
    do
    {
        x = 0;
        convBias = (double)(int)y;
        dy = (double)((float)(convBias) - centerOffset);
        xCount = 0x100;
        do
        {
            convBias = (double)(int)x;
            dx = (double)((float)(convBias) - centerOffset);
            len = (double)(float)(dy * dy + (double)(float)(dx * dx));
            if (epsilon < len)
            {
                invSqrt = 1.0 / SQRT(len);
                invSqrt = DOUBLE_803df9d8 * invSqrt * -(len * invSqrt * invSqrt - DOUBLE_803df9e0);
                invSqrt = DOUBLE_803df9d8 * invSqrt * -(len * invSqrt * invSqrt - DOUBLE_803df9e0);
                len = (double)(float)(len * DOUBLE_803df9d8 * invSqrt *
                    -(len * invSqrt * invSqrt - DOUBLE_803df9e0));
            }
            intensity = lbl_803DF9A8;
            if (len <= falloffLimit)
            {
                intensity = lbl_803DF9B4 * -(float)((double)lbl_803DF9C8 * len - (double)lbl_803DFA30)
                    * lbl_803DFA34;
            }
            *(u16*)
                (DAT_803ddc3c + (y & 3) * 2 + ((int)y >> 2) * 0x20 + (x & 3) * 8 +
                    ((int)x >> 2) * 0x800 + 0x60) =
                (u16)(int)(encodeScale * (float)(dx / len) * intensity + encodeBias) |
                (u16)(((int)(encodeScale * (float)(dy / len) * intensity + encodeBias) & 0xffffU) << 8);
            x = x + 1;
            xCount = xCount + -1;
        }
        while (xCount != 0);
        y = y + 1;
    }
    while ((int)y < 0x100);
    FUN_802420e0(DAT_803ddc3c + 0x60, *(int*)(DAT_803ddc3c + 0x44));
    return;
}

void FUN_8006dca8(u64 arg1, double fwdArg2, u32 arg3, u32 arg4,
                  u32 fwdArg5, int fwdArg6, int fwdArg7)
{
    int mask;
    u32 bit;
    int loop;
    u64 extraout_f1;
    u64 f1Arg;
    u64 retPair;
    u8 buf[19];
    u8 bitList[8];
    char count;

    retPair = FUN_80286840();
    mask = retPair;
    f1Arg = extraout_f1;
    FUN_800033a8((int)buf, 0, 0x1c);
    bit = 0;
    loop = 8;
    do
    {
        if ((mask >> (bit & 0x3f) & 1U) != 0)
        {
            bitList[count] = bit;
            count = count + '\x01';
        }
        if ((mask >> (bit + 1 & 0x3f) & 1U) != 0)
        {
            bitList[count] = (char)(bit + 1);
            count = count + '\x01';
        }
        if ((mask >> (bit + 2 & 0x3f) & 1U) != 0)
        {
            bitList[count] = (char)(bit + 2);
            count = count + '\x01';
        }
        if ((mask >> (bit + 3 & 0x3f) & 1U) != 0)
        {
            bitList[count] = (char)(bit + 3);
            count = count + '\x01';
        }
        bit = bit + 4;
        loop = loop + -1;
    }
    while (loop != 0);
    objAudioFn_8006ef38(f1Arg, fwdArg2, (int)((u64)retPair >> 0x20), buf, fwdArg5, fwdArg6, fwdArg7);
    FUN_8028688c();
    return;
}

extern u32 gNewShadowSmallDiskTexture;
extern char* gNewShadowReflectionTexture;
extern u32 lbl_803DCF94;
extern u32 gNewShadowInverseRampTexture;
extern u32 gNewShadowFalloffTexture;
u32 textureFn_8006c5c4(void) { return gNewShadowSmallDiskTexture; }
u32 getLastRenderedFrame(void) { return (u32)gNewShadowReflectionTexture; }
u32 getTextureFn_8006c744(void) { return lbl_803DCF94; }
u32 fn_8006C74C(void) { return gNewShadowInverseRampTexture; }
u32 fn_8006C754(void) { return gNewShadowFalloffTexture; }

extern u32 lbl_803DCFC4;
extern u32 lbl_803DCFC8;
extern u32 gNewShadowRingTexture;
extern u32 lbl_803DCFB4;
extern u32 lbl_803DCFB8;
extern u32 lbl_803DCFBC;
extern u32 gNewShadowRadialTexture;
extern u32 gNewShadowRampTexture;
extern u32 gNewShadowDiskTexture;
extern u32 gNewShadowReflectionTexture2;
extern u32 gNewShadowCausticTexture;
void fn_8006C4F8(u32* p) { *p = lbl_803DCFC4; }
void fn_8006C504(u32* p) { *p = lbl_803DCFC8; }
void fn_8006C510(u32* p) { *p = gNewShadowRingTexture; }
void fn_8006C51C(u32* p) { *p = lbl_803DCFB4; }
void fn_8006C528(u32* p) { *p = lbl_803DCFB8; }
void fn_8006C534(u32* p) { *p = lbl_803DCFBC; }
void fn_8006C540(u32* p) { *p = gNewShadowRadialTexture; }
void fn_8006C5B8(u32* p) { *p = gNewShadowRampTexture; }
void fn_8006C5CC(u32* p) { *p = gNewShadowDiskTexture; }
void getReflectionTexture2(u32* p) { *p = gNewShadowReflectionTexture2; }
void getTextureFn_8006c5e4(u32* p) { *p = gNewShadowCausticTexture; }

extern f32 gNewShadowReflectionScrollX;
extern f32 gNewShadowReflectionScrollY;

void newshadows_getReflectionScrollOffsets(f32* p1, f32* p2)
{
    *p1 = gNewShadowReflectionScrollX;
    *p2 = gNewShadowReflectionScrollY;
}

extern f32 lbl_803DCFA4;
f32 fn_8006C670(void) { return lbl_803DCFA4; }

extern void mm_free(u32);

void fn_8006CB24(void)
{
    mm_free(lbl_803DCFBC);
    lbl_803DCFBC = 0;
}

u8 lbl_8038E1E8[0x80];
#pragma scheduling off
#pragma peephole off
void fn_8006C4C0(int* p1, int* p2, int* p3)
{
    *p1 = (int)lbl_8038E1E8;
    *p2 = 4;
    *p3 = 8;
}

int gNewShadowNoiseTexFrames[0x10];

void textureFn_8006c4e0(int* p1, int* p2)
{
    *p1 = (int)gNewShadowNoiseTexFrames;
    *p2 = 0x10;
}

extern u32 gNewShadowBumpTexture;
extern void GXLoadTexObj(void* obj, int id);
extern void GXLoadTexObjPreLoaded(void* obj, void* region, int id);

void fn_8006C678(int id)
{
    GXLoadTexObj((char*)gNewShadowBumpTexture + 0x20, id);
}

extern u32 lbl_803DCFCC;

void fn_8006C6A4(int id)
{
    register int idCopy = id;
    Texture* p = (Texture*)lbl_803DCFCC;
    if (p->preloaded != 0)
    {
        GXLoadTexObjPreLoaded((char*)p + 0x20, p->tmemAddr, idCopy);
    }
    else
    {
        GXLoadTexObj((char*)p + 0x20, idCopy);
    }
}

void selectReflectionTexture(int id)
{
    register int idCopy = id;
    Texture* p = (Texture*)gNewShadowReflectionTexture;
    if (p->preloaded != 0)
    {
        GXLoadTexObjPreLoaded((char*)p + 0x20, p->tmemAddr, idCopy);
    }
    else
    {
        GXLoadTexObj((char*)p + 0x20, idCopy);
    }
}

extern u32 gNewShadowReflectionSmallTexture;

void textureFn_8006c75c(int id)
{
    register int idCopy = id;
    Texture* p = (Texture*)gNewShadowReflectionSmallTexture;
    if (p->preloaded != 0)
    {
        GXLoadTexObjPreLoaded((char*)p + 0x20, p->tmemAddr, idCopy);
    }
    else
    {
        GXLoadTexObj((char*)p + 0x20, idCopy);
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
#define NEW_SHADOW_ENTRY_CAPACITY 0x25
NewShadowEntry gNewShadowEntries[0x294 / sizeof(NewShadowEntry)];

void findSomething(void* needle)
{
    int i;
    for (i = 0; i < NEW_SHADOW_ENTRY_CAPACITY; ++i)
    {
        if (gNewShadowEntries[i].isActive != 0 && &gNewShadowEntries[i] == needle)
        {
            gNewShadowEntries[i].isActive = 0;
            return;
        }
    }
}

extern u8 gNewShadowFrameIndex;
#define NEW_SHADOW_FRAME_COUNT 3
u32 gNewShadowFrameTextures[NEW_SHADOW_FRAME_COUNT];

void objShadowFn_8006c5f0(int obj, u32* outTable, f32* outF, int* outX, int* outY)
{
    int idx = (gNewShadowFrameIndex + 1) % NEW_SHADOW_FRAME_COUNT;
    *outTable = gNewShadowFrameTextures[idx];
    *outF = ((GameObject*)obj)->anim.modelState->shadowScale;
    *outX = (int)((GameObject*)obj)->anim.modelState->shadowOffsetX;
    *outY = (int)((GameObject*)obj)->anim.modelState->shadowOffsetY;
}

extern void* textureAlloc(u16 w, u16 h, int fmt, u8 mip, u8 maxLod, u8 b8, u8 b9, u8 b10, u8 b11);

void* textureAlloc512(void)
{
    Texture* tex = (Texture*)textureAlloc(0x200, 0x200, 1, 0, 0, 0, 0, 0, 0);
    tex->refCount = 1;
    DCFlushRange((char*)tex + 0x60, *(u32*)((char*)tex + 0x44));
    return tex;
}

extern const f32 lbl_803DED28;
extern void drawTexture(void* p, f32 f1, f32 f2, int a, int b);
extern void GXSetTexCopySrc(u16 left, u16 top, u16 wd, u16 ht);
extern void GXSetTexCopyDst(u16 wd, u16 ht, GXTexFmt fmt, GXBool mipmap);
extern void GXCopyTex(void* dest, GXBool clear);
extern void GXPreLoadEntireTexture(void* obj, void* region);

#pragma optimization_level 2
void drawReflectionTexture(void)
{
    char* texture = gNewShadowReflectionTexture;
    drawTexture(texture, lbl_803DED28, lbl_803DED28, 0xff, 0x40);
    GXSetTexCopySrc(0, 0, 0x50, 0x3c);
    GXSetTexCopyDst(0x50, 0x3c, GX_TF_RGB565, GX_FALSE);
    GXCopyTex((char*)gNewShadowReflectionSmallTexture + 0x60, GX_TRUE);
    if (((Texture*)gNewShadowReflectionSmallTexture)->preloaded != 0)
    {
        GXPreLoadEntireTexture((char*)gNewShadowReflectionSmallTexture + 0x20,
                               ((Texture*)gNewShadowReflectionSmallTexture)->tmemAddr);
    }
}
#pragma optimization_level reset

extern void GXInvalidateTexAll(void);

void updateReflectionTextures(void)
{
    GXSetTexCopySrc(0, 0, 0x280, 0x1e0);
    GXSetTexCopyDst(0x140, 0xf0, GX_TF_RGB565, GX_TRUE);
    GXCopyTex((char*)gNewShadowReflectionTexture + 0x60, GX_FALSE);
    GXSetTexCopySrc(0, 0, 0x280, 0x1e0);
    GXSetTexCopyDst(0x140, 0xf0, GX_TF_Z8, GX_TRUE);
    GXCopyTex((char*)gNewShadowReflectionTexture2 + 0x60, GX_FALSE);
    if (((Texture*)gNewShadowReflectionTexture)->preloaded != 0)
    {
        GXPreLoadEntireTexture((char*)gNewShadowReflectionTexture + 0x20,
                               ((Texture*)gNewShadowReflectionTexture)->tmemAddr);
    }
    if (((Texture*)gNewShadowReflectionTexture2)->preloaded != 0)
    {
        GXPreLoadEntireTexture((char*)gNewShadowReflectionTexture2 + 0x20,
                               ((Texture*)gNewShadowReflectionTexture2)->tmemAddr);
    }
    if (((Texture*)gNewShadowReflectionTexture)->preloaded == 0 ||
        ((Texture*)gNewShadowReflectionTexture2)->preloaded == 0)
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
    int t;
    u8 v;
    if (idx < 0 || idx >= 0x23) t = 0;
    else t = base[idx + 0xb4];
    v = t;
    switch (b)
    {
    case 0: v = t;
        break;
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
    case 7: base += 0x28;
        break;
    default: base += 0x28;
        break;
    }
    return *(u16*)(base + v * 2);
}

extern u8 gNewShadowCasterCount;
extern int* gNewShadowCurrentViewSlot;

typedef struct
{
    int* obj;
    f32 scale;
    u8 flags;
} NewShadowCaster;

NewShadowCaster gNewShadowCasterTable[0x36CC / sizeof(NewShadowCaster)];
extern f32 Ydchuff_803DED80;
extern f32 Ydchuff_803DED90;
extern const double TokenCB_803DED58;
extern const double DrawDone_803DED60;
extern inline float sqrtf(float x)
{
    volatile float y;
    if (x > lbl_803DED28)
    {
        double guess = __frsqrte((double)x);
        guess = TokenCB_803DED58 * guess * (DrawDone_803DED60 - guess * guess * x);
        guess = TokenCB_803DED58 * guess * (DrawDone_803DED60 - guess * guess * x);
        guess = TokenCB_803DED58 * guess * (DrawDone_803DED60 - guess * guess * x);
        y = (float)(x * guess);
        return y;
    }
    return x;
}

extern const f32 CPUFifo_803DED38;
extern f32 GPFifo_803DED3C, __GXCurrentThread_803DED40;
extern const f32 lbl_803DED2C;
extern const f32 Vdchuff_803DEDC0;
extern const f32 Vdchuff_803DEDC8;
extern const f32 Vdchuff_803DEDD0;
extern f32 Vdchuff_803DEDD4;
extern const f32 Uachuff_803DEE00;
extern float __fabsf(float);

/* Sample the animated noise field built from gNewShadowPlacements: sums the
   contribution of every active placement at texel (px,pz) for animation frame
   `frame`. out2 = sparkle intensity (0..1), out1 = accumulated shift term. */
void fn_8006CD20(f32* placements, int count, f32* out1, f32* out2, f32 px, f32 pz, f32 frame)
{
    f32* place;
    int i;
    f32 acc5;
    f32 acc6;

    acc5 = acc6 = lbl_803DED28;
    place = placements;
    for (i = 0; i < count; i++, place += 5)
    {
        f32 over = *(f32*)&lbl_803DED28;
        if (frame < place[0])
        {
            f32 mx, mz, t, s0, tmp, p2lo, d2, sq, ratio, frac, depth;
            t = GPFifo_803DED3C + (place[0] - frame) / place[0];
            if (t > lbl_803DED2C) t = lbl_803DED2C;
            s0 = sqrtf(t);

            mx = __fabsf(place[1] - px);
            tmp = __fabsf((lbl_803DED2C + place[1]) - px);
            if (tmp < mx) mx = tmp;
            tmp = __fabsf((place[1] - lbl_803DED2C) - px);
            if (tmp < mx) mx = tmp;

            mz = __fabsf(place[2] - pz);
            if (pz > place[2]) over = pz - place[2];
            tmp = __fabsf((lbl_803DED2C + place[2]) - pz);
            if (tmp < mz)
            {
                mz = tmp;
                over = lbl_803DED28;
            }
            p2lo = place[2] - lbl_803DED2C;
            tmp = __fabsf(p2lo - pz);
            if (tmp < mz)
            {
                mz = tmp;
                if (pz > p2lo) over = pz - p2lo;
            }

            sq = sqrtf(mx * mx + mz * mz);

            ratio = frame / place[0];
            frac = sqrtf(ratio);
            depth = place[3] - frac * (place[3] - place[4]);
            if (sq <= depth)
            {
                f32 sqd = sq / depth;
                f32 g = sqrtf(lbl_803DED2C - sqd);
                acc5 = s0 * g + acc5;
                over = over / depth;
                acc6 = acc6 + over;
                acc6 = CPUFifo_803DED38 * (lbl_803DED2C - frame * Vdchuff_803DEDD0) + acc6;
            }
        }
    }
    if (acc5 > lbl_803DED2C) acc5 = lbl_803DED2C;
    if (acc6 > *(f32*)&lbl_803DED2C) acc6 = *(f32*)&lbl_803DED2C;
    *out1 = __GXCurrentThread_803DED40 * acc6 + Vdchuff_803DEDD4;
    *out2 = acc5;
}

extern int testAndSet_onlyUseHeap3(int v);
extern float fn_802943F4(float x);
extern float floor(float);
extern const f32 __PADFixBits;
extern const f32 Yachuff_803DEDE0;
extern const f32 Yachuff_803DEDE4, Yachuff_803DEDE8;
extern const f32 Vdchuff_803DEDD8, Vdchuff_803DEDDC;
f32 gNewShadowPlacements[0x112];
extern f32 gNewShadowReflectionScrollY, gNewShadowReflectionScrollX;

#pragma opt_common_subs off
/* Builds the animated water-noise assets: scatters up to 50 non-overlapping random
   placements ([0]=lifetime 8..16 frames, [1..2]=pos, [3]=outer size, [4]=inner size),
   renders 16 noise animation frames through fn_8006CD20, then the caustic texture. */
void initFn_8006d020(void)
{
    u8 saved;
    int attempts;
    int col;
    int row;
    int j;
    f32* e;
    int placed;
    int tex;
    int count;
    u8 collide;

    saved = testAndSet_onlyUseHeap3(1);
    attempts = 0;
    placed = 0;
    e = gNewShadowPlacements;
    while (placed < 0x32 && attempts < 10000u)
    {
        f32 *p1, *p2, *p4;
        e[0] = (f32)(int)
        randomGetRange(8, 0x10);
        e[3] = Vdchuff_803DEDD8 * (f32)(int)
        randomGetRange(5, 10);
        e[4] = e[3] * (Vdchuff_803DEDD8 * (f32)(int)
        randomGetRange(0x14, 0x32)
        )
        ;
        attempts = 0;
        p1 = &e[1];
        p2 = &e[2];
        p4 = &e[4];
        do
        {
            f32* o;
            *p1 = Vdchuff_803DEDDC * (f32)(int)
            randomGetRange(0, 999);
            *p2 = Vdchuff_803DEDDC * (f32)(int)
            randomGetRange(0, 999);
            o = gNewShadowPlacements;
            collide = 0;
            j = 0;
            while (j < placed && !collide)
            {
                f32 mx, mz, tmp, d;
                mx = __fabsf(*p1 - o[1]);
                tmp = __fabsf((lbl_803DED2C + *p1) - o[1]);
                if (tmp < mx) mx = tmp;
                tmp = __fabsf((*p1 - lbl_803DED2C) - o[1]);
                if (tmp < mx) mx = tmp;
                mz = __fabsf(*p2 - o[2]);
                tmp = __fabsf((lbl_803DED2C + *p2) - o[2]);
                if (tmp < mz) mz = tmp;
                tmp = __fabsf((*p2 - lbl_803DED2C) - o[2]);
                if (tmp < mz) mz = tmp;
                d = sqrtf(mx * mx + mz * mz);
                if (d < *p4 + o[3]) collide = 1;
                o += 5;
                j++;
            }
            attempts++;
        }
        while (collide && attempts < 10000u);
        e += 5;
        placed++;
    }

    count = placed;
    tex = 0;
    for (; tex < 0x10; tex++)
    {
        gNewShadowNoiseTexFrames[tex] = (int)textureAlloc(0x40, 0x40, 3, 0, 0, 1, 1, 1, 1);
        for (row = 0; row < 0x40; row++)
        {
            int rowoff, lowoff;
            col = 0;
            rowoff = (row >> 2) * 0x20;
            lowoff = (row & 3) * 2;
            for (; col < 0x40; col++)
            {
                f32 o1, o2;
                int hi, lo;
                int dst = gNewShadowNoiseTexFrames[tex] + lowoff;
                dst += rowoff;
                dst += (col & 3) * 8;
                dst += (col >> 2) * 0x200;
                fn_8006CD20(gNewShadowPlacements, count, &o1, &o2,
                            row * Yachuff_803DEDE0,
                            col * Yachuff_803DEDE0,
                            tex);
                hi = (int)(__PADFixBits * o2);
                lo = (int)(__PADFixBits * o1);
                *(u16*)(dst + 0x60) = (u16)(((hi & 0xffff) << 8) | lo);
            }
        }
        DCFlushRange((void*)(gNewShadowNoiseTexFrames[tex] + 0x60), *(u32*)(gNewShadowNoiseTexFrames[tex] + 0x44));
    }

    gNewShadowCausticTexture = (u32)textureAlloc(0x40, 0x40, 3, 0, 0, 1, 1, 1, 1);
    for (row = 0; row < 0x40; row++)
    {
        int rowoff, lowoff;
        f32 rv;
        col = 0;
        rowoff = (row >> 2) * 0x20;
        lowoff = (row & 3) * 2;
        rv = Yachuff_803DEDE4 * row;
        for (; col < 0x40; col++)
        {
            f32 cv, n1, n2, prod, fa;
            int hi, lo;
            int dst = gNewShadowCausticTexture + lowoff;
            dst += rowoff;
            dst += (col & 3) * 8;
            dst += (col >> 2) * 0x200;
            cv = Yachuff_803DEDE8 * col;
            n1 = fn_802943F4(CPUFifo_803DED38 * floor(cv) + rv);
            n2 = fn_802943F4(cv);
            prod = n1 * n2;
            prod = Vdchuff_803DEDC0 * prod + Vdchuff_803DEDC0;
            fa = Vdchuff_803DEDC0 * n1 + Vdchuff_803DEDC0;
            lo = fa;
            hi = prod;
            *(u16*)(dst + 0x60) = (u16)(lo | ((hi & 0xffff) << 8));
        }
    }
    DCFlushRange((void*)(gNewShadowCausticTexture + 0x60), *(u32*)(gNewShadowCausticTexture + 0x44));

    gNewShadowReflectionScrollX = lbl_803DED28;
    gNewShadowReflectionScrollY = lbl_803DED28;
    testAndSet_onlyUseHeap3(saved);
}
#pragma opt_common_subs reset

extern void fn_80069EB8();
extern const f32 lbl_803DED10;
extern f32 lbl_803DED34;
extern const f32 Dev_803DED1C;
extern const f32 Yachuff_803DEDEC, Yachuff_803DEDF0, Yachuff_803DEDF4, Yachuff_803DEDF8, Yachuff_803DEDFC;
extern const f32 Uachuff_803DEE04, Uachuff_803DEE08, Uachuff_803DEE0C, Uachuff_803DEE10;
extern const f32 Uachuff_803DEE14, Uachuff_803DEE18, Uachuff_803DEE1C;
extern const f32 Udchuff_803DEDBC;
#pragma opt_propagation off
#pragma opt_loop_invariants off
#pragma ppc_unroll_speculative off
void allocLotsOfTextures(void)
{
    char* g = (char*)(int)gNewShadowEntries;
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

    gNewShadowReflectionTexture = textureAlloc(0x140, 0xf0, 4, 0, 0, 0, 0, 1, 1);
    gNewShadowReflectionSmallTexture = (int)textureAlloc(0x50, 0x3c, 4, 0, 0, 0, 0, 1, 1);
    gNewShadowReflectionTexture2 = (int)textureAlloc(0x140, 0xf0, 1, 0, 0, 0, 0, 1, 1);

    gNewShadowDiskTexture = (int)textureAlloc(0x20, 0x20, 1, 0, 0, 0, 0, 1, 1);
    for (i = 0; i < 0x20; i++)
    {
        int rowoff, lowoff, isum;
        f32 cy;
        j = 0;
        rowoff = (i >> 3) * 0x20;
        lowoff = i & 7;
        cy = i - Yachuff_803DEDEC;
        isum = lowoff + rowoff;
        for (; j < 0x20; j++)
        {
            int base = gNewShadowDiskTexture;
            int off = isum + (j & 3) * 8;
            f32 dx, dz, d2;
            off += (j >> 2) * 0x80;
            off += 0x60;
            dx = cy * Vdchuff_803DEDD0;
            dz = (f32)j - Yachuff_803DEDEC;
            dz = dz * Vdchuff_803DEDD0;
            dx = dx * Yachuff_803DEDF0;
            dz = dz * Yachuff_803DEDF0;
            d2 = dx * dx + dz * dz;
            *(u8*)(base + off) = __PADFixBits * ((d2 > lbl_803DED2C) ? lbl_803DED28 : (lbl_803DED2C - d2));
        }
    }
    DCFlushRange((void*)(gNewShadowDiskTexture + 0x60), *(int*)(gNewShadowDiskTexture + 0x44));

    gNewShadowSmallDiskTexture = (int)textureAlloc(0x10, 0x10, 1, 0, 0, 0, 0, 1, 1);
    for (i = 0; i < 0x10; i++)
    {
        int rowoff, lowoff, isum;
        f32 cy;
        j = 0;
        rowoff = (i >> 3) * 0x20;
        lowoff = i & 7;
        cy = i - lbl_803DED10;
        isum = lowoff + rowoff;
        for (; j < 0x10; j++)
        {
            int base = gNewShadowSmallDiskTexture;
            int off = isum + (j & 3) * 8;
            f32 dx, dz, d2;
            f32 v;
            off += (j >> 2) * 0x40;
            off += 0x60;
            dx = cy * __GXCurrentThread_803DED40;
            dz = (f32)j - lbl_803DED10;
            dz = dz * __GXCurrentThread_803DED40;
            dx = dx * Yachuff_803DEDF4;
            dz = dz * Yachuff_803DEDF4;
            d2 = dx * dx + dz * dz;
            if (d2 > lbl_803DED2C)
            {
                v = lbl_803DED28;
            }
            else
            {
                v = sqrtf(lbl_803DED2C - d2);
            }
            *(u8*)(base + off) = __PADFixBits * v;
        }
    }
    DCFlushRange((void*)(gNewShadowSmallDiskTexture + 0x60), *(int*)(gNewShadowSmallDiskTexture + 0x44));

    gNewShadowBumpTexture = (int)textureAlloc(0x40, 0x40, 5, 0, 0, 0, 0, 1, 1);
    {
        f32 mx = lbl_803DED28;
        for (i = 0; i < 0x40; i++)
        {
            f32 fi, fi2, rc, rc2;
            j = 0;
            fi = i - Yachuff_803DEDF8;
            fi2 = (f32)(i + 1) - Yachuff_803DEDF8;
            rc = fi * Yachuff_803DEDFC;
            rc2 = fi2 * Yachuff_803DEDFC;
            for (; j < 0x40; j++)
            {
                f32 cc = (f32)j - Yachuff_803DEDF8;
                f32 d1, d2, cc2, d3, n1, a, b;
                f64 n2, n3;
                cc = cc * Yachuff_803DEDFC;
                d1 = sqrtf(cc * cc + rc * rc);
                d2 = sqrtf(cc * cc + rc2 * rc2);
                cc2 = (f32)(j + 1) - Yachuff_803DEDF8;
                cc2 = cc2 * Yachuff_803DEDFC;
                {
                    f32 rcb = rc;
                    d3 = sqrtf(rcb * rcb + cc2 * cc2);
                }
                n1 = -fn_802943F4(Uachuff_803DEE00 * d1);
                n2 = __fabs(fn_802943F4(Uachuff_803DEE00 * d2));
                n3 = __fabs(fn_802943F4(Uachuff_803DEE00 * d3));
                a = n1 - (f32)n2;
                b = n1 - (f32)n3;
                if (a > mx) mx = a;
                if (b > mx) mx = b;
            }
        }
        {
            f32 inv = lbl_803DED2C / mx;
            for (j = 0; j < 0x40; j++)
            {
                int rowoff, lowoff;
                f32 fj, fj2, rc, rc2;
                i = 0;
                rowoff = (j >> 2) * 0x20;
                lowoff = (j & 3) * 2;
                fj = j - Yachuff_803DEDF8;
                fj2 = (f32)(j + 1) - Yachuff_803DEDF8;
                rc = fj * Yachuff_803DEDFC;
                rc2 = fj2 * Yachuff_803DEDFC;
                for (; i < 0x40; i++)
                {
                    int dst = gNewShadowBumpTexture + lowoff;
                    f32 cc, d1, d2, cc2, d3, n1, n2, n3, a, b;
                    f32 dd;
                    f32 c;
                    int bi, ci, ai;
                    dst += rowoff;
                    dst += (i & 3) * 8;
                    dst += (i >> 2) * 0x200;
                    cc = (f32)i - Yachuff_803DEDF8;
                    cc = cc * Yachuff_803DEDFC;
                    d1 = sqrtf(cc * cc + rc * rc);
                    d2 = sqrtf(cc * cc + rc2 * rc2);
                    cc2 = (f32)(i + 1) - Yachuff_803DEDF8;
                    cc2 = cc2 * Yachuff_803DEDFC;
                    {
                        f32 rcb = rc;
                        d3 = sqrtf(rcb * rcb + cc2 * cc2);
                    }
                    n1 = -fn_802943F4(Uachuff_803DEE00 * d1);
                    n2 = -fn_802943F4(Uachuff_803DEE00 * d2);
                    n3 = -fn_802943F4(Uachuff_803DEE00 * d3);
                    a = inv * (Vdchuff_803DEDC0 * (n1 - n2)) + Vdchuff_803DEDC0;
                    b = inv * (Vdchuff_803DEDC0 * (n1 - n3)) + Vdchuff_803DEDC0;
                    if (d1 < lbl_803DED2C)
                    {
                        dd = sqrtf(lbl_803DED2C - d1);
                    }
                    else
                    {
                        dd = lbl_803DED28;
                    }
                    c = Yachuff_803DEDF8 * dd;
                    if (c > Uachuff_803DEE04) c = Uachuff_803DEE04;
                    a = a * Yachuff_803DEDFC;
                    b = b * Vdchuff_803DEDD0;
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
    DCFlushRange((void*)(gNewShadowBumpTexture + 0x60), *(int*)(gNewShadowBumpTexture + 0x44));

    lbl_803DCFCC = (u32)textureLoadAsset(0x5b0);
    lbl_803DCFC8 = (u32)textureLoadAsset(0x600);
    lbl_803DCFC4 = (u32)textureLoadAsset(0xc18);

    gNewShadowRampTexture = (int)textureAlloc(0x100, 4, 1, 0, 0, 0, 0, 0, 0);
    for (i = 0; i < 0x100; i++)
    {
        int t;
        t = gNewShadowRampTexture + (i & 7);
        t += (i >> 3) * 0x20;
        *(u8*)(t + 0x60) = i;
        t = gNewShadowRampTexture + (i & 7);
        t += (i >> 3) * 0x20;
        *(u8*)(t + 0x68) = i;
        t = gNewShadowRampTexture + (i & 7);
        t += (i >> 3) * 0x20;
        *(u8*)(t + 0x70) = i;
        t = gNewShadowRampTexture + (i & 7);
        t += (i >> 3) * 0x20;
        *(u8*)(t + 0x78) = i;
    }
    DCFlushRange((void*)(gNewShadowRampTexture + 0x60), *(int*)(gNewShadowRampTexture + 0x44));

    gNewShadowInverseRampTexture = (int)textureAlloc(0x100, 4, 1, 0, 0, 0, 0, 1, 1);
    for (i = 0; i < 0x100; i++)
    {
        int t;
        t = gNewShadowInverseRampTexture + (i & 7);
        t += (i >> 3) * 0x20;
        *(u8*)(t + 0x60) = (u8)(255 - i);
        t = gNewShadowInverseRampTexture + (i & 7);
        t += (i >> 3) * 0x20;
        *(u8*)(t + 0x68) = (u8)(255 - i);
        t = gNewShadowInverseRampTexture + (i & 7);
        t += (i >> 3) * 0x20;
        *(u8*)(t + 0x70) = (u8)(255 - i);
        t = gNewShadowInverseRampTexture + (i & 7);
        t += (i >> 3) * 0x20;
        *(u8*)(t + 0x78) = (u8)(255 - i);
    }
    DCFlushRange((void*)(gNewShadowInverseRampTexture + 0x60), *(int*)(gNewShadowInverseRampTexture + 0x44));

    gNewShadowFalloffTexture = (int)textureAlloc(0x80, 0x80, 1, 0, 0, 0, 0, 1, 1);
    for (i = 0; i < 0x80; i++)
    {
        int rowoff, lowoff, isum;
        f32 cy;
        j = 0;
        rowoff = (i >> 3) * 0x20;
        lowoff = i & 7;
        cy = i - Dev_803DED1C;
        isum = lowoff + rowoff;
        cy = cy * Yachuff_803DEDE0;
        for (; j < 0x80; j++)
        {
            int base = gNewShadowFalloffTexture;
            int off = isum + (j & 3) * 8 + (j >> 2) * 0x200 + 0x60;
            f32 cx = ((f32)j - Dev_803DED1C) * Yachuff_803DEDE0;
            f32 d2 = sqrtf(cx * cx + cy * cy);
            *(u8*)(base + off) = (d2 < CPUFifo_803DED38)
                                     ? 0xa0
                                     : ((d2 > lbl_803DED2C) ? 0 : (int)(160.0f * (lbl_803DED2C - (d2 - CPUFifo_803DED38) / CPUFifo_803DED38)));
        }
    }
    DCFlushRange((void*)(gNewShadowFalloffTexture + 0x60), *(int*)(gNewShadowFalloffTexture + 0x44));

    gNewShadowRadialTexture = (int)textureAlloc(0x80, 0x80, 1, 0, 0, 0, 0, 1, 1);
    for (i = 0; i < 0x80; i++)
    {
        int rowoff, lowoff, isum;
        f32 cy;
        j = 0;
        rowoff = (i >> 3) * 0x20;
        lowoff = i & 7;
        cy = i - Dev_803DED1C;
        isum = lowoff + rowoff;
        cy = cy * Yachuff_803DEDE0;
        cy = __fabsf(cy);
        for (; j < 0x80; j++)
        {
            int base = gNewShadowRadialTexture;
            int off = isum + (j & 3) * 8 + (j >> 2) * 0x200 + 0x60;
            f32 cx = __fabsf(((f32)j - Dev_803DED1C) * Yachuff_803DEDE0);
            f32 d2 = sqrtf(cx * cx + cy * cy);
            f32 v = lbl_803DED2C - d2;
            if (v < lbl_803DED28) v = lbl_803DED28;
            *(u8*)(base + off) = 255.0f * v;
        }
    }
    DCFlushRange((void*)(gNewShadowRadialTexture + 0x60), *(int*)(gNewShadowRadialTexture + 0x44));

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
        c0 = i - 16.0f;
        isum = lowoff + rowoff;
        c0 = c0 * 0.0625f;
        c0 = __fabsf(c0);
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

    gNewShadowRingTexture = (int)textureAlloc(0x80, 0x80, 1, 0, 0, 1, 1, 1, 1);
    for (i = 0; i < 0x80; i++)
    {
        int rowoff, lowoff, isum;
        f32 cy;
        j = 0;
        rowoff = (i >> 3) * 0x20;
        lowoff = i & 7;
        cy = i - Dev_803DED1C;
        isum = lowoff + rowoff;
        cy = cy * Yachuff_803DEDE0;
        for (; j < 0x80; j++)
        {
            int base = gNewShadowRingTexture;
            int off = isum + (j & 3) * 8 + (j >> 2) * 0x200 + 0x60;
            f32 cx = ((f32)j - Dev_803DED1C) * Yachuff_803DEDE0;
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
    DCFlushRange((void*)(gNewShadowRingTexture + 0x60), *(int*)(gNewShadowRingTexture + 0x44));

    lbl_803DCF94 = (int)textureAlloc(4, 4, 3, 0, 0, 0, 0, 1, 1);
    for (i = 0; i < 4; i++)
    {
        f32 x = i / 3.0f - CPUFifo_803DED38;
        int lowoff = (i & 3) * 2;
        int rowoff = (i >> 2) * 0x20;
        int t;
        t = lbl_803DCF94 + lowoff;
        t += rowoff;
        *(u16*)(t + 0x60) =
            (u16)((((int)(255.0f * x + 128.0f) & 0xff) << 8) | ((int)CPUFifo_803DED38 & 0xff));
        t = lbl_803DCF94 + lowoff;
        t += rowoff;
        *(u16*)(t + 0x68) =
            (u16)((((int)(255.0f * x + 128.0f) & 0xff) << 8) | ((int)Uachuff_803DEE14 & 0xff));
        t = lbl_803DCF94 + lowoff;
        t += rowoff;
        *(u16*)(t + 0x70) =
            (u16)((((int)(255.0f * x + 128.0f) & 0xff) << 8) | ((int)Uachuff_803DEE18 & 0xff));
        t = lbl_803DCF94 + lowoff;
        t += rowoff;
        *(u16*)(t + 0x78) =
            (u16)((((int)(255.0f * x + 128.0f) & 0xff) << 8) | ((int)Uachuff_803DEE1C & 0xff));
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
        for (i = 0, p = (u8*)(int)gNewShadowEntries; i < 0x20; i += 0x10)
        {
            p[0x010] = 0; p[0x011] = 1;
            p[0x024] = 0; p[0x025] = 1;
            p[0x038] = 0; p[0x039] = 1;
            p[0x04c] = 0; p[0x04d] = 1;
            p[0x060] = 0; p[0x061] = 1;
            p[0x074] = 0; p[0x075] = 1;
            p[0x088] = 0; p[0x089] = 1;
            p[0x09c] = 0; p[0x09d] = 1;
            p[0x0b0] = 0; p[0x0b1] = 1;
            p[0x0c4] = 0; p[0x0c5] = 1;
            p[0x0d8] = 0; p[0x0d9] = 1;
            p[0x0ec] = 0; p[0x0ed] = 1;
            p[0x100] = 0; p[0x101] = 1;
            p[0x114] = 0; p[0x115] = 1;
            p[0x128] = 0; p[0x129] = 1;
            p[0x13c] = 0; p[0x13d] = 1;
            p += 0x140;
        }
        p = (u8*)(int)gNewShadowEntries + i * 0x14;
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
#pragma opt_propagation reset
#pragma opt_loop_invariants reset
#pragma ppc_unroll_speculative on
#pragma opt_common_subs on
void shadowCreate(int* obj)
{
    int* cam;
    f32 dx, dy, dz, dist;
    if (gNewShadowCasterCount < 0x12c)
    {
        gNewShadowCasterTable[gNewShadowCasterCount].obj = obj;
        cam = gNewShadowCurrentViewSlot;
        dx = ((GameObject*)obj)->anim.worldPosX - *(f32*)((char*)cam + 0xc);
        dy = ((GameObject*)obj)->anim.worldPosY - *(f32*)((char*)cam + 0x10);
        dz = ((GameObject*)obj)->anim.worldPosZ - *(f32*)((char*)cam + 0x14);
        dist = sqrtf(dx * dx + dy * dy + dz * dz);
        gNewShadowCasterTable[gNewShadowCasterCount].scale =
            ((GameObject*)obj)->anim.modelState->shadowScale / dist;
        if (((ObjAnimComponent*)obj)->modelInstance->shadowType == 2)
        {
            gNewShadowCasterTable[gNewShadowCasterCount].flags = 1;
            if (((ObjAnimComponent*)obj)->modelInstance->renderFlags & 4)
            {
                gNewShadowCasterTable[gNewShadowCasterCount].flags = 2;
                gNewShadowCasterTable[gNewShadowCasterCount].scale = Ydchuff_803DED90;
            }
        }
        else
        {
            gNewShadowCasterTable[gNewShadowCasterCount].flags = 0;
        }
        gNewShadowCasterCount++;
    }
}
#pragma opt_common_subs reset

void objAudioFn_8006edcc(int p1, int mask, int p5, int p6, int p7, f32 f1, f32 f2)
{
    s8 buf[0x1c];
    int bit;
    memset(buf, 0, 0x1c);
    for (bit = 0; bit < 32; bit++)
    {
        if ((mask >> bit) & 1)
        {
            buf[buf[0x1b] + 0x13] = bit;
            buf[0x1b]++;
        }
    }
    objAudioFn_8006ef38(p1, buf, p5, p6, p7, f1, f2);
}

extern int getHudHiddenFrameCount(void);
extern void fn_80060BB0(void);
extern u8 lbl_803DCF80;
extern u8 isHeavyFogEnabled(void);
extern f32* Camera_GetInverseViewMatrix(void);
extern void fn_8004C234(f32 * a, f32 * b);
extern u16 lbl_803DCFA0;
void maybeHudFn_8006c91c(void)
{
    f32 hi, lo;
    if (getHudHiddenFrameCount() == 0)
    {
        f32 d = timeDelta;
        gNewShadowReflectionScrollX = 0.0084f * d + gNewShadowReflectionScrollX;
        gNewShadowReflectionScrollY = 0.003f * d + gNewShadowReflectionScrollY;
        if (gNewShadowReflectionScrollX > 256.0f) gNewShadowReflectionScrollX = gNewShadowReflectionScrollX - 256.0f;
        if (gNewShadowReflectionScrollY > 256.0f) gNewShadowReflectionScrollY = gNewShadowReflectionScrollY - 256.0f;
    }
    gNewShadowCasterCount = 0;
    gNewShadowCurrentViewSlot = Camera_GetCurrentViewSlot();
    lbl_803DCFA0 = (u16)(lbl_803DCFA0 + framesThisStep * 0x28a);
    lbl_803DCFA4 = 0.2f *
        floor(6.284f * (f32)(u32)lbl_803DCFA0 / 65536.0f);
    fn_80060BB0();
    gNewShadowFrameIndex = (gNewShadowFrameIndex + 1) % NEW_SHADOW_FRAME_COUNT;
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
extern f32 lbl_803DED0C;
extern const f32 lbl_803DED14, Chan_803DED18;
extern f32 Enabled_803DED20, BarnacleEnabled_803DED24;
extern void Camera_ProjectWorldSphere( f32 x, f32 y, f32 z, f32 radius, f32* outX, f32* outY, f32* outZ, f32* outRadiusX, f32* outRadiusY, f32* outRadiusZ);
extern void GXSetViewport(f32 left, f32 top, f32 wd, f32 ht, f32 nearz, f32 farz);
extern void set_shadowFlag_803dcc29(int x);
extern void objRender(int a, int b, int c, int d, int* obj, int e);
extern int* Obj_GetActiveModel(int* obj);
extern void Camera_ApplyFullViewport(void);
void shadowRenderFn_8006b558(int* obj)
{
    f32 mtx[12];
    f32 vA, vB, vC, vD, vE, vF;
    f32 sc, objScale, saved, nx, ny, m;
    Obj_BuildWorldTransformMatrix(obj, mtx, 0);
    Camera_ProjectWorldSphere(((GameObject*)obj)->anim.localPosX - playerMapOffsetX,
                              ((GameObject*)obj)->anim.localPosY,
                              ((GameObject*)obj)->anim.localPosZ - playerMapOffsetZ,
                              lbl_803DED0C * (((GameObject*)obj)->anim.hitboxScale * ((GameObject*)obj)->anim.rootMotionScale),
                              &vA, &vB, &vC, &vD, &vE, &vF);
    vD = lbl_803DED14 * vD + lbl_803DED10;
    vE = Chan_803DED18 * vE + lbl_803DED10;
    if (vD > vE) m = vD;
    else m = vE;
    sc = Dev_803DED1C / m;
    objScale = ((GameObject*)obj)->anim.rootMotionScale * sc;
    nx = -vA;
    ny = vB;
    GXSetViewport(*(f32*)&lbl_803DED14 * nx, *(f32*)&Chan_803DED18 * ny, Enabled_803DED20,
                  BarnacleEnabled_803DED24, lbl_803DED28, lbl_803DED2C);
    if (vC < *(f32*)&lbl_803DED28)
    {
        int* model;
        saved = ((GameObject*)obj)->anim.rootMotionScale;
        ((GameObject*)obj)->anim.rootMotionScale = objScale;
        set_shadowFlag_803dcc29(1);
        objRender(0, 0, 0, 0, obj, 1);
        set_shadowFlag_803dcc29(0);
        ((GameObject*)obj)->anim.rootMotionScale = saved;
        model = Obj_GetActiveModel(obj);
        *(u16*)((char*)model + 0x18) &= ~0x8;
        gxSetZMode_(1, GX_LEQUAL, 1);
        GXSetTexCopySrc(0x100, 0xb0, 0x80, 0x80);
        GXSetTexCopyDst(0x80, 0x80, GX_CTF_B8, GX_FALSE);
        GXCopyTex((void*)(gNewShadowFrameTextures[gNewShadowFrameIndex] + 0x60), GX_TRUE);
        fn_8006A028((u8*)gNewShadowFrameTextures[(gNewShadowFrameIndex + 1) % NEW_SHADOW_FRAME_COUNT], 0x80, 0x10, 0);
        *(f32*)obj[0x64 / 4] = lbl_803DED2C / sc;
    }
    else
    {
        *(f32*)obj[0x64 / 4] = lbl_803DED28;
    }
    Camera_ApplyFullViewport();
    ((f32*)obj[0x64 / 4])[5] = lbl_803DED14 * (-nx);
    ((f32*)obj[0x64 / 4])[6] = Chan_803DED18 * (-ny);
    ((f32*)obj[0x64 / 4])[5] = ((f32*)obj[0x64 / 4])[5] + lbl_803DED14;
    ((f32*)obj[0x64 / 4])[6] = ((f32*)obj[0x64 / 4])[6] + Chan_803DED18;
    ((f32*)obj[0x64 / 4])[5] = ((f32*)obj[0x64 / 4])[5] - Dev_803DED1C * ((f32*)obj[0x64 / 4])[0];
    ((f32*)obj[0x64 / 4])[6] = ((f32*)obj[0x64 / 4])[6] - Dev_803DED1C * ((f32*)obj[0x64 / 4])[0];
}

extern f32 lbl_803DED34, GXOverflowSuspendInProgress_803DED48;
extern const f32 Udchuff_803DEDAC, Udchuff_803DEDB0, Udchuff_803DEDB4, Udchuff_803DEDB8, Udchuff_803DEDBC;

#pragma opt_loop_invariants off
#pragma opt_propagation off
void fn_8006CB50(void)
{
    int yhi;
    int ylo;
    int y, x;
    lbl_803DCFBC = (u32)textureAlloc(0x100, 0x100, 3, 0, 0, 0, 0, 1, 1);
    for (y = 0; y < 0x100; y++)
    {
        f32 fy;
        x = 0;
        yhi = (y >> 2) * 0x20;
        ylo = (y & 3) * 2;
        fy = y - Udchuff_803DEDAC;
        for (; x < 0x100; x++)
        {
            char* addr;
            f32 fx;
            f32 dist;
            f32 ny;
            f32 nx;
            f32 s;
            addr = (char*)lbl_803DCFBC + ylo;
            addr += yhi;
            addr += (x & 3) * 8;
            addr += (x >> 2) * 0x800;
            fx = x - Udchuff_803DEDAC;
            dist = sqrtf(fy * fy + fx * fx);
            ny = fy / dist;
            nx = fx / dist;
            if (dist <= Udchuff_803DEDB8)
            {
                f32 t = lbl_803DED34 * (Udchuff_803DEDB0 - GXOverflowSuspendInProgress_803DED48 * dist);
                s = t * Udchuff_803DEDB4;
            }
            else
            {
                s = lbl_803DED28;
            }
            {
                f32 py;
                f32 px;
                ny = ny * s;
                nx = nx * s;
                py = Vdchuff_803DEDC0 * ny + Udchuff_803DEDBC;
                px = Vdchuff_803DEDC0 * nx + Udchuff_803DEDBC;
                *(u16*)(addr + 0x60) = (u16)((int)px | (((int)py & 0xffff) << 8));
            }
        }
    }
    DCFlushRange((char*)lbl_803DCFBC + 0x60, *(u32*)((char*)lbl_803DCFBC + 0x44));
}
#pragma opt_propagation reset
#pragma opt_loop_invariants reset

extern void Camera_DisableViewYOffset(void);
extern void Camera_EnableViewYOffset(void);
extern f32 Camera_GetFovY(void);
extern void Camera_SetFovY(f32 fovY);
extern void Camera_SetAspectRatio(f32 aspectRatio);
extern void Camera_SetCurrentViewIndex(int index);
extern void Camera_UpdateViewMatrices(void);
extern void Camera_RebuildProjectionMatrix(void);
extern void Camera_UpdateProjection(int a, int b);
extern void fn_80061094(f32* v, f32* out, f32 x);
extern void mapGetBlocks(int* a, int* b);
extern u8 fn_800626C8(int* obj, int frames);
extern void fn_8008923C(int* obj, f32* a, f32* b, f32* c);





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
extern void GXSetCopyFilter(GXBool aa, const u8 sample_pattern[12][2], GXBool vf, const u8 vfilter[7]);

extern void GXSetScissor(int a, int b, int c, int d);
extern void setDisplayCopyFilter(void);
extern int getDrawDistanceFlag_8005cd48(void);
extern void* memcpy(void* d, const void* s, int n);
extern f32 gNewShadowFovY, lbl_803DED34;
extern f32 lbl_803DED70, lbl_803DED74, gNewShadowAspectWide, gNewShadowAspectNarrow;
extern f32 GPFifo_803DED3C, __GXCurrentThread_803DED40;
extern f32 CPGPLinked_803DED44, BreakPointCB_803DED4C, __GXOverflowCount_803DED50;
extern f32 FinishQueue_803DED64;
extern f32 FinishQueue_803DED68;
extern f32 FinishQueue_803DED6C;
extern u8 lbl_803DB668[8];
extern f32 lbl_803DB670;
extern int gRenderModeObj;
extern f32 lbl_803DCED0, lbl_803DCECC;
extern int gNewShadowLightAngleX, gNewShadowLightAngleY;

#pragma opt_common_subs off
#pragma opt_loop_invariants off
void renderShadows(void)
{
    char* casterPtr;
    f32 *vAp1, *vAp2, *mc54p;
    f32 savedFovY, sCamX, sCamY, dirX;
    int savedRotY;
    s16 savedRotX, savedRotZ;
    f32 om100[24];
    f32 mTrans[12], mScale[12], mOrtho[16];
    f32 mc54[3], mc48[3];
    f32 vA[3], v30[3];
    f32 dot24[3], proj[3];
    int* slot;
    char* B = (char*)gNewShadowEntries;
    int blkArr, blkCount;
    s8 casterIdx;
    f32 sCamZ, dirY, dirZ, vAx, vAz, vAy, orthoHalf;
    int texIdx, slotIdx;

    if (gNewShadowCasterCount == 0) return;
    Camera_DisableViewYOffset();
    fn_8006B830((ShadowSortEntry*)(B + 0x360), gNewShadowCasterCount);
    Camera_SetCurrentViewIndex(1);
    slot = Camera_GetCurrentViewSlot();
    savedFovY = Camera_GetFovY();
    Camera_SetFovY(gNewShadowFovY);
    Camera_SetAspectRatio(lbl_803DED2C);
    sCamX = ((GameObject*)slot)->anim.localPosX;
    sCamY = ((GameObject*)slot)->anim.localPosY;
    sCamZ = ((GameObject*)slot)->anim.localPosZ;
    savedRotY = ((GameObject*)slot)->anim.rotY;
    savedRotX = ((GameObject*)slot)->anim.rotX;
    savedRotZ = ((GameObject*)slot)->anim.rotZ;
    ((GameObject*)slot)->anim.rotY = 0;
    v30[0] = lbl_803DED28;
    v30[1] = lbl_803DED2C;
    v30[2] = lbl_803DED28;
    fn_80061094(v30, om100, lbl_803DED34);
    mapGetBlocks(&blkArr, &blkCount);
    texIdx = 0;
    slotIdx = 0;
    casterIdx = 0;
    casterPtr = B + 0x360;
    mc54p = &mc54[0];
    vAp2 = &vA[2];
    vAp1 = &vA[1];
    for (; casterIdx < gNewShadowCasterCount && casterIdx < NEW_SHADOW_MAX_CASTERS; casterIdx++, casterPtr += 0xc)
    {
        int* obj = *(int**)casterPtr;
        int* of64 = (int*)obj[0x64 / 4];
        u8 lod;
        u8 kind;
        int screenW = 0, w = 0;
        char* castSlot;
        Camera_SetCurrentViewIndex(0);
        lod = fn_800626C8(obj, framesThisStep);
        Camera_SetCurrentViewIndex(1);
        if (lod <= 4) continue;
        if ((*(u32*)&((ObjModelState*)of64)->flags & 0x20) != 0)
        {
            memcpy(mc48, (char*)obj + 0xc, 0xc);
            memcpy(mc54p, (char*)obj + 0x18, 0xc);
            memcpy((char*)obj + 0xc, (char*)of64 + 0x20, 0xc);
            memcpy((char*)obj + 0x18, (char*)of64 + 0x20, 0xc);
        }
        castSlot = B + (u8)slotIdx * 0x68 + 0x1170;
        *(u8*)(castSlot + 0x64) = lod;
        if ((u8)texIdx < 8 && (kind = *(u8*)(casterPtr + 8)) != 0)
        {
            if ((u8)texIdx < 3)
            {
                w = 0x100;
                orthoHalf = CPUFifo_803DED38;
            }
            else if ((u8)texIdx < 5)
            {
                w = 0x80;
                orthoHalf = GPFifo_803DED3C;
            }
            else
            {
                w = 0x40;
                orthoHalf = __GXCurrentThread_803DED40;
            }
            if ((u8)texIdx == 0) screenW = w << 1;
            else screenW = w;
            if (kind == 2)
            {
                w = *(u16*)((char*)((int*)obj[0x64 / 4])[1] + 0xa);
                screenW = w;
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
            vAx = vA[0];
            dirX = -vAx;
            vAy = vA[1];
            dirY = -vAy;
            vAz = vA[2];
            dirZ = -vAz;
            gNewShadowLightAngleX = (u16)getAngle(dirX, vAz);
            {
                f32 sqA = vAx * vAx;
                f32 sqB = vAz * vAz;
                gNewShadowLightAngleY = (u16)getAngle(sqrtf(sqA + sqB), vAy) - 0x3fc8;
            }
            ((GameObject*)slot)->anim.rotY = gNewShadowLightAngleY;
            ((GameObject*)slot)->anim.rotX = gNewShadowLightAngleX;
            {
                f32 mag = sqrtf(dirX * dirX + dirY * dirY + dirZ * dirZ);
                if (mag > lbl_803DED28)
                {
                    f32 inv = FinishQueue_803DED68 / mag;
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
            vAz = *(f32*)of64;
            vAx = -vAz;
            if (*(u32*)&((GameObject*)obj)->anim.parent != 0)
            {
                ((GameObject*)slot)->anim.localPosX += playerMapOffsetX;
                ((GameObject*)slot)->anim.localPosZ += playerMapOffsetZ;
            }
            GXSetScissor(2, 2, screenW - 4, screenW - 4);
            GXSetViewport(lbl_803DED28, lbl_803DED28, (f32)(u32)screenW, (f32)(u32)screenW, lbl_803DED28, lbl_803DED2C);
            C_MTXOrtho(mOrtho, vAx, vAz, vAx, vAz, lbl_803DED2C, FinishQueue_803DED6C);
            GXSetProjection(mOrtho, GX_ORTHOGRAPHIC);
            Camera_UpdateViewMatrices();
            C_MTXLightOrtho((f32*)castSlot, vAz, vAx, vAx, vAz, orthoHalf, orthoHalf, orthoHalf, orthoHalf);
            {
                f32* vm = Camera_GetViewMatrix();
                PSMTXCopy(vm, (f32*)(castSlot + 0x30));
                PSMTXConcat((f32*)castSlot, vm, (f32*)castSlot);
                ((ObjModelState*)obj[0x64 / 4])->shadowCastSlot = castSlot;
                {
                    char* texPool = B + 0x3a10;
                    char* texSlot = texPool + (u8)texIdx * 4;
                    *(int*)(castSlot + 0x60) = *(int*)texSlot;
                    *(u8*)(castSlot + 0x65) = lbl_803DB668[(u8)texIdx];
                    objRenderShadowIfVisible(obj, 0, 0, 0, 0, 0);
                    if (*(u8*)(casterPtr + 8) == 2)
                    {
                        gxSetZMode_(1, GX_LEQUAL, 1);
                        PSMTXScale((f32*)(castSlot + 0x30), lbl_803DED28, lbl_803DED28, lbl_803DED28);
                        *(f32*)(castSlot + 0x38) = lbl_803DED70;
                        *(f32*)(castSlot + 0x3c) = lbl_803DED74;
                        *(f32*)(castSlot + 0x5c) = lbl_803DED2C;
                        PSMTXConcat((f32*)(castSlot + 0x30), vm, (f32*)(castSlot + 0x30));
                        GXSetTexCopySrc(0, 0, screenW, screenW);
                        GXSetTexCopyDst(screenW, screenW, GX_TF_Z8, GX_FALSE);
                        GXSetCopyFilter(0, (void*)(gRenderModeObj + 0x1a), 0, (void*)(gRenderModeObj + 0x32));
                        GXCopyTex((void*)(*(int*)((char*)obj[0x64 / 4] + 4) + 0x60), GX_TRUE);
                        setDisplayCopyFilter();
                        *(int*)(castSlot + 0x60) = *(int*)((char*)obj[0x64 / 4] + 4);
                    }
                    else
                    {
                        if ((u8)texIdx == 0)
                        {
                            gxSetZMode_(1, GX_LEQUAL, 1);
                            GXSetTexCopySrc(0, 0, screenW, screenW);
                            GXSetTexCopyDst(w, w, GX_CTF_R4, GX_TRUE);
                            GXCopyTex((void*)(*(int*)texSlot + 0x60), GX_TRUE);
                            *(int*)(castSlot + 0x60) = *(int*)texSlot;
                        }
                        texIdx++;
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
        slotIdx++;
        if ((*(u32*)&((ObjModelState*)of64)->flags & 0x20) != 0)
        {
            memcpy((char*)obj + 0xc, mc48, 0xc);
            memcpy((char*)obj + 0x18, mc54p, 0xc);
        }
    }
    if ((u8)texIdx > 1)
    {
        gxSetZMode_(1, GX_LEQUAL, 1);
        GXSetCopyFilter(0, (void*)(gRenderModeObj + 0x1a), 0, (void*)(gRenderModeObj + 0x32));
        GXSetTexCopySrc(0, 0, 0x100, 0x100);
        GXSetTexCopyDst(0x100, 0x100, GX_CTF_R8, GX_FALSE);
        GXCopyTex((void*)(*(int*)(B + 0x3a14) + 0x60), GX_TRUE);
        GXPixModeSync();
        setDisplayCopyFilter();
    }
    clearScreenWidth();
    ((GameObject*)slot)->anim.localPosX = sCamX;
    ((GameObject*)slot)->anim.localPosY = sCamY;
    ((GameObject*)slot)->anim.localPosZ = sCamZ;
    ((GameObject*)slot)->anim.rotY = savedRotY;
    ((GameObject*)slot)->anim.rotX = savedRotX;
    ((GameObject*)slot)->anim.rotZ = savedRotZ;
    if (getDrawDistanceFlag_8005cd48() != 0)
    {
        Camera_SetCurrentViewIndex(0);
        Camera_SetFovY(savedFovY);
        if (isWidescreen() != 0) Camera_SetAspectRatio(gNewShadowAspectWide);
        else Camera_SetAspectRatio(gNewShadowAspectNarrow);
        Camera_UpdateProjection(0, 0);
    }
    else if (isWidescreen() != 0)
    {
        Camera_SetCurrentViewIndex(0);
        Camera_SetFovY(savedFovY);
        Camera_SetAspectRatio(Ydchuff_803DED80);
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
#pragma opt_loop_invariants reset
#pragma opt_common_subs reset
