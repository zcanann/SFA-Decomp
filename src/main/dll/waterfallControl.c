#include "main/audio/sfx_ids.h"
#include "main/game_object.h"
#include "main/dll/waterfallControl.h"


extern int hitDetectFn_80065e50(f32 x, f32 y, f32 z, int obj, int* hitsOut, int pointCount,
                                int mask);
extern u32 randomGetRange(int min, int max);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void ObjHits_EnableObject(int obj);
extern void ObjHits_DisableObject(int obj);
extern int* ObjList_GetObjects(int* startIndex, int* objectCount);
extern void ObjGroup_RemoveObject(int* obj, int group);
extern void objRenderFn_8003b8f4(f32);

extern f32 timeDelta;
extern f32 lbl_803E2F5C;
extern f32 lbl_803E2F60;
extern f32 lbl_803E2F64;
extern f32 lbl_803E2F68;
extern f64 lbl_803E2F70;
extern f32 lbl_803E2F78;
extern f32 lbl_803E2F7C;
extern f32 lbl_803E2F80;
extern f32 lbl_803E2F84;
extern f32 lbl_803E2F88;
extern f64 lbl_803E2F90;
extern f32 lbl_803E2F98;
extern f32 lbl_803E2F9C;


/*
 * --INFO--
 *
 * Function: tumbleweed_updateRollingMotion
 * EN v1.0 Address: 0x80163BBC
 * EN v1.0 Size: 976b
 */
#pragma scheduling off
void tumbleweed_updateRollingMotion(short* obj, int state)
{
    int hitCount;
    uint uval;
    undefined4* hitEntry;
    int i;
    int bestHit;
    f32 dy;
    f32 bestDy;
    undefined4* hitList[2];

    hitList[0] = (undefined4*)0x0;
    bestDy = lbl_803E2F78;
    hitCount = hitDetectFn_80065e50(*(float*)(obj + 6), *(float*)(obj + 8),
                                 *(float*)(obj + 10), (int)obj, (int*)hitList, 0, 0);
    bestHit = 0;
    hitEntry = hitList[0];
    for (i = 0; i < hitCount; i++)
    {
        dy = *(float*)(obj + 8) - *(float*)*hitEntry;
        if (dy < lbl_803E2F68)
        {
            dy = lbl_803E2F7C * dy + lbl_803E2F5C;
        }
        if (dy < bestDy)
        {
            bestHit = i;
            bestDy = dy;
        }
        hitEntry = hitEntry + 1;
    }
    if (*(float*)(obj + 0x12) > lbl_803E2F80)
    {
        *(float*)(obj + 0x12) = lbl_803E2F80;
    }
    else if (*(float*)(obj + 0x12) < lbl_803E2F7C)
    {
        *(float*)(obj + 0x12) = lbl_803E2F7C;
    }
    if (*(float*)(obj + 0x14) > lbl_803E2F80)
    {
        *(float*)(obj + 0x14) = lbl_803E2F80;
    }
    else if (*(float*)(obj + 0x14) < lbl_803E2F7C)
    {
        *(float*)(obj + 0x14) = lbl_803E2F7C;
    }
    if (*(float*)(obj + 0x16) > lbl_803E2F80)
    {
        *(float*)(obj + 0x16) = lbl_803E2F80;
    }
    else if (*(float*)(obj + 0x16) < lbl_803E2F7C)
    {
        *(float*)(obj + 0x16) = lbl_803E2F7C;
    }
    *(float*)(obj + 6) = *(float*)(obj + 0x12) * timeDelta + *(float*)(obj + 6);
    *(float*)(obj + 8) = *(float*)(obj + 0x14) * timeDelta + *(float*)(obj + 8);
    *(float*)(obj + 10) = *(float*)(obj + 0x16) * timeDelta + *(float*)(obj + 10);
    hitCount = (int)((f32)(int) * (s16*)(state + 0x27c) * timeDelta + (f32)(int)
    obj[2]
    )
    ;
    obj[2] = (short)hitCount;
    hitCount = (int)((f32)(int) * (s16*)(state + 0x27e) * timeDelta + (f32)(int)
    obj[1]
    )
    ;
    obj[1] = (short)hitCount;
    hitCount = (int)((f32)(int) * (s16*)(state + 0x280) * timeDelta + (f32)(int) * obj);
    *obj = (short)hitCount;
    if (hitList[0] != (undefined4*)0x0)
    {
        if (lbl_803E2F60 + *(float*)hitList[0][bestHit] < *(float*)(obj + 8))
        {
            *(float*)(obj + 0x14) = *(float*)(obj + 0x14) + lbl_803E2F64;
        }
        else
        {
            *(float*)(obj + 8) = lbl_803E2F60 + *(float*)hitList[0][bestHit];
            if (obj[0x23] == 0x3fb)
            {
                uval = randomGetRange(0x8c, 0xb4);
                *(f32*)(obj + 0x14) =
                    -(lbl_803E2F84 * *(f32*)(obj + 0x14) *
                        ((f32) * (ushort*)(state + 0x268) / (f32)(int)
                uval
                )
                )
                ;
            }
            else
            {
                uval = randomGetRange(0x14, 0x28);
                *(f32*)(obj + 0x14) =
                    -(lbl_803E2F84 * *(f32*)(obj + 0x14) *
                        ((f32) * (ushort*)(state + 0x268) / (f32)(int)
                uval
                )
                )
                ;
            }
            bestHit = (int)(lbl_803E2F88 * *(f32*)(obj + 0x14));
            if (0x7f < bestHit)
            {
                bestHit = 0x7f;
            }
            if (0x10 < bestHit)
            {
                Sfx_PlayFromObject((int)obj, SFXsc_gethit02);
                uval = randomGetRange(0, 5);
                if ((uval == 0) && ((*(byte*)(state + 0x27a) & 8) != 0))
                {
                    Sfx_PlayFromObject((int)obj, SFXsc_gethit03);
                }
            }
        }
    }
    return;
}

/*
 * --INFO--
 *
 * Function: tumbleweed_func0F
 * EN v1.0 Address: 0x80163F8C
 * EN v1.0 Size: 12b
 */
#pragma peephole off
void tumbleweed_func0F(int obj, int value)
{
    *(int*)(*(int*)&((GameObject*)obj)->extra + 0x284) = value;
}

/*
 * --INFO--
 *
 * Function: tumbleweed_func0E
 * EN v1.0 Address: 0x80163F98
 * EN v1.0 Size: 24b
 */
int tumbleweed_func0E(int obj)
{
    return *(byte*)(*(int*)&((GameObject*)obj)->extra + 0x278) == 6;
}

/*
 * --INFO--
 *
 * Function: tumbleweed_render2
 * EN v1.0 Address: 0x80163FB0
 * EN v1.0 Size: 64b
 */
void tumbleweed_render2(int* obj, int p2)
{
    int* state = ((GameObject*)obj)->extra;
    *(u8*)((char*)state + 0x278) = 6;
    *(int*)((char*)state + 0x290) = p2;
    *(f32*)((char*)state + 0x294) = timeDelta * lbl_803E2F98;
    ObjHits_DisableObject((int)obj);
}

/*
 * --INFO--
 *
 * Function: tumbleweed_modelMtxFn
 * EN v1.0 Address: 0x80163FF0
 * EN v1.0 Size: 112b
 */
void tumbleweed_modelMtxFn(int obj)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    if (*(u8*)(state + 0x278) == 1)
    {
        ObjHits_EnableObject(obj);
        *(u8*)(state + 0x278) = 2;
        *(u8*)(state + 0x27a) |= 3;
        if (((GameObject*)obj)->anim.seqId == 0x4c1)
        {
            *(f32*)(state + 0x2a0) = lbl_803E2F9C;
        }
    }
}

/*
 * --INFO--
 *
 * Function: tumbleweed_func0B
 * EN v1.0 Address: 0x80164060
 * EN v1.0 Size: 16b
 */
void tumbleweed_func0B(int obj, float x, float y)
{
    int extra = *(int*)&((GameObject*)obj)->extra;

    *(float*)(extra + 0x288) = x;
    *(float*)(extra + 0x28c) = y;
}

/*
 * --INFO--
 *
 * Function: tumbleweed_setScale
 * EN v1.0 Address: 0x80164070
 * EN v1.0 Size: 12b
 */
int tumbleweed_setScale(int obj)
{
    return *(byte*)(*(int*)&((GameObject*)obj)->extra + 0x278);
}

/*
 * --INFO--
 *
 * Function: tumbleweed_getExtraSize
 * EN v1.0 Address: 0x8016407C
 * EN v1.0 Size: 8b
 */
int tumbleweed_getExtraSize(void)
{
    return 0x2a4;
}

/*
 * --INFO--
 *
 * Function: tumbleweed_free
 * EN v1.0 Address: 0x80164084
 * EN v1.0 Size: 252b
 */
void tumbleweed_free(int* obj)
{
    int* items;
    int counter;
    int limit;
    int target_id;

    switch (((GameObject*)obj)->anim.seqId)
    {
    case 0x39d:
        target_id = 0x28d;
        break;
    case 0x3fb:
        target_id = 0x3fd;
        break;
    case 0x4ba:
        target_id = 0x4b9;
        break;
    case 0x4c1:
        target_id = 0x4be;
        break;
    }

    items = ObjList_GetObjects(&counter, &limit);
    while (counter < limit)
    {
        int* o = (int*)items[counter];
        if (target_id == *(s16*)((int)o + 0x46))
        {
            (*(code*)(**(int**)((int)o + 0x68) + 0x20))(o, obj);
        }
        counter = counter + 1;
    }
    ObjGroup_RemoveObject(obj, 3);
    ObjGroup_RemoveObject(obj, 0x31);
}

/*
 * --INFO--
 *
 * Function: tumbleweed_render
 * EN v1.0 Address: 0x80164180
 * EN v1.0 Size: 48b
 */
void tumbleweed_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    if ((s32)visible >= 1) objRenderFn_8003b8f4(lbl_803E2F80);
}
