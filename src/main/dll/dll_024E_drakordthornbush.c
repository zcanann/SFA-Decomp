#include "main/dll/DR/dll_80209FE0_shared.h"
#include "main/obj_placement.h"
#include "main/game_object.h"

typedef struct DrakordThornbushPlacement
{
    u8 pad0[0x19 - 0x0];
    u8 unk19;
    s16 unk1A;
    s16 unk1C;
    u8 pad1E[0x20 - 0x1E];
} DrakordThornbushPlacement;


typedef struct DrakordThornbushState
{
    s32 unk0;
    u8 pad4[0x8 - 0x4];
    s32 unk8;
    f32 unkC;
    u8 pad10[0x64 - 0x10];
    s32 light;
    f32 unk68;
    s32 unk6C;
    f32 unk70;
    s32 radius;
} DrakordThornbushState;


/*
 * Function: drakord_thornbush_getExtraSize
 * EN v1.0 Address: 0x8020BAB4
 * EN v1.0 Size: 8b
 */
int drakord_thornbush_getExtraSize(void)
{
    return 0x7c;
}

/*
 * Function: drakord_thornbush_getObjectTypeId
 * EN v1.0 Address: 0x8020BABC
 * EN v1.0 Size: 8b
 */
int drakord_thornbush_getObjectTypeId(void)
{
    return 0;
}

/*
 * Function: drakord_thornbush_release
 * EN v1.0 Address: 0x8020C270
 * EN v1.0 Size: 4b
 */
void drakord_thornbush_release(void)
{
}

/*
 * Function: drakord_thornbush_initialise
 * EN v1.0 Address: 0x8020C274
 * EN v1.0 Size: 4b
 */
void drakord_thornbush_initialise(void)
{
}

#pragma opt_common_subs off

void drakord_thornbush_free(int obj)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    if (((GameObject*)obj)->anim.seqId == 0x709)
    {
        ((void (*)(int, int, int, f32, int))fn_80221978)(obj, inner + 0x14, 3, lbl_803E6588, inner + 0x64);
    }
    if (*(void**)&((DrakordThornbushState*)inner)->light != NULL)
    {
        ModelLightStruct_free(((DrakordThornbushState*)inner)->light);
    }
}

void drakord_thornbush_render(int p1, int p2, int p3, int p4, int p5, s8 vis)
{
    int inner = *(int*)&((GameObject*)p1)->extra;
    f32 v;
    if (((GameObject*)p1)->anim.seqId == 0x709)
    {
        v = ((DrakordThornbushState*)inner)->unk68;
        if (v < lbl_803E6590)
        {
            v = lbl_803E658C;
        }
        ((void (*)(int, int, int, f32, int))fn_80221978)(p1, inner + 0x14, 3, v, inner + 0x64);
    }
    objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E6594);
}

void drakord_thornbush_update(int obj)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    int setup = *(int*)&((GameObject*)obj)->anim.placementData;
    int s2;
    if (fn_80080150((int)((char*)inner + 0xc)) != 0)
    {
        if (((DrakordThornbushState*)inner)->unkC < (f32)(s32)((DrakordThornbushPlacement*)setup)->unk1C)
        {
            ObjHits_EnableObject(obj);
            ObjHitbox_SetSphereRadius(
                obj, (int)(lbl_803E65A8 + (f32)(s32)((DrakordThornbushPlacement*)setup)->unk1C - ((DrakordThornbushState
                    *)inner)->unkC));
        }
        if (timerCountDown(&((DrakordThornbushState*)inner)->unkC) != 0)
        {
            ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
            ((DrakorFlags*)((char*)inner + 0x79))->b80 = 1;
            if (*(u32*)&((ObjPlacement*)setup)->mapId == 0xffffffff)
            {
                Obj_FreeObject(obj);
            }
        }
    }
    else
    {
        Sfx_KeepAliveLoopedObjectSound(obj, 0x479);
        if (((DrakorFlags*)((char*)inner + 0x79))->b80)
        {
            ((DrakorFlags*)((char*)inner + 0x79))->b80 = 0;
        }
        switch (((GameObject*)obj)->anim.seqId)
        {
        case 0x727:
            if (fn_802972A8((int)Obj_GetPlayerObject()) != NULL)
            {
                ObjHits_ClearHitVolumes(obj);
                ObjHits_EnableObject(obj);
            }
            else
            {
                ObjHits_SetHitVolumeSlot(obj, 0xe, 1, 0);
            }
            break;
        case 0x709:
            if (Vec_distance((int*)((char*)Obj_GetPlayerObject() + 0x18), (int*)&((GameObject*)obj)->anim.worldPosX) <
                (f32)(s32)(((DrakordThornbushPlacement*)setup)->unk1C << 1))
            {
                ObjHits_RecordObjectHit((int)Obj_GetPlayerObject(), obj, 5, 1, 0);
            }
            break;
        }
        if (((DrakordThornbushState*)inner)->unk0 == 0)
        {
            s2 = *(int*)&((GameObject*)obj)->anim.placementData;
            ObjHits_EnableObject(obj);
            ((DrakordThornbushState*)inner)->unk0 = ((DrakordThornbushPlacement*)s2)->unk19;
            ObjHitbox_SetSphereRadius(obj, (s16)((DrakordThornbushState*)inner)->radius);
        }
        if (((GameObject*)obj)->anim.seqId == 0x709)
        {
            if (((DrakordThornbushState*)inner)->unk68 < lbl_803E658C)
            {
                ((DrakordThornbushState*)inner)->unk68 = lbl_803E65AC * (f32)(u32)
                framesThisStep + ((DrakordThornbushState*)inner)->unk68;
                ((GameObject*)obj)->anim.rootMotionScale =
                    ((DrakordThornbushState*)inner)->unk68 *
                    (((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase *
                     (f32)(s32)((DrakordThornbushPlacement*)setup)->unk1C) /
                    lbl_803E65B0;
            }
        }
    }
}

void drakord_thornbush_hitDetect(int obj)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    f32 v2;
    f32 v1;
    f32 v0;
    int pC;
    int hitObj;
    int flag;
    int hit;
    int setup;
    if (((DrakordThornbushState*)inner)->unk0 != 0)
    {
        flag = timerCountDown((f32*)((char*)inner + 0x10));
        if ((hit = ObjHits_GetPriorityHitWithPosition(obj, &hitObj, 0, &pC, &v0, &v1, &v2)) != 0)
        {
            if (*(s16*)((char*)hitObj + 0x46) != 0x35f &&
                *(void**)&((DrakordThornbushState*)inner)->unk8 != (void*)hitObj &&
                arrayIndexOf(((DrakordThornbushState*)inner)->unk6C, 2) != -1)
            {
                ((DrakordThornbushState*)inner)->unk8 = hitObj;
                Obj_SpawnHitLightAndFade(obj, &v0, lbl_803E6598);
                ((DrakordThornbushState*)inner)->unk0 -= pC;
                if (((DrakordThornbushState*)inner)->unk0 <= 0)
                {
                    flag = 1;
                }
                else
                {
                    Sfx_PlayFromObject(obj, 0x496);
                }
            }
        }
        else
        {
            ((DrakordThornbushState*)inner)->unk8 = 0;
        }
        if (flag != 0)
        {
            setup = *(int*)&((GameObject*)obj)->anim.placementData;
            ((DrakordThornbushState*)inner)->unk0 = 0;
            switch (((GameObject*)obj)->anim.seqId)
            {
            case 0x727:
                spawnExplosion((int*)obj, (f32)(s32)((DrakordThornbushPlacement*)setup)->unk1C, 1, 0, 0, 0, 0, 1, 1);
                break;
            case 0x709:
                Sfx_PlayFromObject(obj, 0x2f9);
                spawnExplosion((int*)obj, (f32)(s32)(((DrakordThornbushState*)inner)->radius << 1), 1, 1, 1, 1, 0, 1,
                               0);
                ((void (*)(int, int, int, f32, int))fn_80221978)(obj, inner + 0x14, 3, lbl_803E6588, inner + 0x64);
                break;
            }
            if (((DrakordThornbushPlacement*)setup)->unk1A != 0)
            {
                s16toFloat((void*)&((DrakordThornbushState*)inner)->unkC, ((DrakordThornbushPlacement*)setup)->unk1A);
                ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                ObjHits_DisableObject(obj);
            }
            else if (*(u32*)&((ObjPlacement*)setup)->mapId == 0xffffffff)
            {
                Obj_FreeObject(obj);
            }
            else
            {
                Obj_RemoveFromUpdateList((int*)obj);
                ObjHits_DisableObject(obj);
                ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            }
        }
    }
}

void drakord_thornbush_init(int obj, u8* init)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    ((DrakordThornbushState*)inner)->unk0 = 0;
    ObjHits_SetTargetMask(obj, 4);
    ((GameObject*)obj)->anim.rotY = (s16)((s8)init[0x18] << 8);
    if (*(u32*)((char*)init + 0x14) == 0xffffffff)
    {
        ((DrakorFlags*)((char*)inner + 0x79))->b80 = 1;
    }
    storeZeroToFloatParam(&((DrakordThornbushState*)inner)->unkC);
    storeZeroToFloatParam((f32*)((char*)inner + 0x10));
    ((DrakordThornbushState*)inner)->unk8 = 0;
    switch (((GameObject*)obj)->anim.seqId)
    {
    case 0x727:
        *(void**)&((DrakordThornbushState*)inner)->unk6C = &lbl_803DC1A8;
        ObjHitbox_SetSphereRadius(obj, *(s16*)((char*)init + 0x1c));
        ((DrakordThornbushState*)inner)->radius = *(s16*)((char*)init + 0x1c);
        ((DrakordThornbushState*)inner)->unk70 = lbl_803E65C0;
        ((GameObject*)obj)->anim.rootMotionScale =
            ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase * (f32)(s32) * (s16*)((char*)init + 0x1c) /
            lbl_803E6590;
        break;
    case 0x709:
        *(void**)&((DrakordThornbushState*)inner)->unk6C = &lbl_803DC1A0;
        ((GameObject*)obj)->anim.rootMotionScale =
            ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase * (f32)(s32) * (s16*)((char*)init + 0x1c) /
            lbl_803E65C4;
        ObjHitbox_SetSphereRadius(obj, (s16)(*(s16*)((char*)init + 0x1c) / 7));
        s16toFloat((f32*)((char*)inner + 0x10), (int)lbl_803DC1B0);
        ((DrakordThornbushState*)inner)->unk70 = lbl_803E65C8;
        ((DrakordThornbushState*)inner)->radius = *(s16*)((char*)init + 0x1c) / 5;
        ((DrakordThornbushState*)inner)->unk68 = lbl_803E6594;
        break;
    }
}

#pragma opt_common_subs reset
